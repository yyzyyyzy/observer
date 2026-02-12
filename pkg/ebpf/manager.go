// pkg/ebpf/manager.go
package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"
)

// ---------------------------------------------------------------------------
// Handler interfaces
// ---------------------------------------------------------------------------

type TCPEventHandler interface {
	HandleTCPEvent(event *TCPEvent)
}

type UDPEventHandler interface {
	HandleUDPEvent(event *UDPEvent)
}

type TCPacketHandler interface {
	HandleTCPacket(packet *TCPacket)
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

// ManagerOptions Manager 配置选项
type ManagerOptions struct {
	// Ring buffer 大小（字节），必须是 PAGE_SIZE（4096）的 2^n 倍，最小 4096
	// 对应 BPF map 中的 max_entries；Go 侧 ringbuf.NewReader 不需要再指定大小
	RingBufSize int

	// flow_tracker_map 最大条目数
	MaxFlows int

	// eBPF .o 文件目录
	BPFObjDir string

	// TC 监听的网络接口列表（为空则不启用 TC）
	TCInterfaces []string
}

var DefaultManagerOptions = ManagerOptions{
	RingBufSize: 256 * 1024,
	MaxFlows:    10240,
	BPFObjDir:   "./bpf",
}

// ---------------------------------------------------------------------------
// Internal BPF object holders
// ---------------------------------------------------------------------------

type tcpObjects struct {
	FlowTrackerMap *ebpf.Map // BPF_MAP_TYPE_HASH
	TcpEvents      *ebpf.Map // BPF_MAP_TYPE_RINGBUF
	StatsMap       *ebpf.Map // BPF_MAP_TYPE_ARRAY
}

type udpObjects struct {
	UdpFlowMap *ebpf.Map // BPF_MAP_TYPE_LRU_HASH
	UdpEvents  *ebpf.Map // BPF_MAP_TYPE_RINGBUF
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

type Manager struct {
	opts ManagerOptions

	tcpObjs *tcpObjects
	udpObjs *udpObjects

	// ring buffer readers
	// 关键：reader.Close() 是线程安全的，调用后阻塞中的 Read() 会立即
	// 返回 ringbuf.ErrClosed，事件循环 goroutine 因此可以正常退出。
	tcpRing *ringbuf.Reader
	udpRing *ringbuf.Reader

	links []link.Link

	tcpHandlers   []TCPEventHandler
	udpHandlers   []UDPEventHandler
	tcpktHandlers []TCPacketHandler

	mu      sync.Mutex
	running bool
	wg      sync.WaitGroup
}

func NewManager(opts ManagerOptions) *Manager {
	if opts.RingBufSize == 0 {
		opts.RingBufSize = DefaultManagerOptions.RingBufSize
	}
	if opts.MaxFlows == 0 {
		opts.MaxFlows = DefaultManagerOptions.MaxFlows
	}
	if opts.BPFObjDir == "" {
		opts.BPFObjDir = DefaultManagerOptions.BPFObjDir
	}
	return &Manager{opts: opts}
}

func (m *Manager) RegisterTCPHandler(h TCPEventHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tcpHandlers = append(m.tcpHandlers, h)
}

func (m *Manager) RegisterUDPHandler(h UDPEventHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.udpHandlers = append(m.udpHandlers, h)
}

func (m *Manager) RegisterTCPacketHandler(h TCPacketHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tcpktHandlers = append(m.tcpktHandlers, h)
}

// Start 加载 eBPF 程序，挂载 kprobes，启动事件循环
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return errors.New("manager already running")
	}

	// 内核 < 5.11 需要解除 RLIMIT_MEMLOCK
	if err := rlimit.RemoveMemlock(); err != nil {
		log.WithError(err).Warn("Failed to remove memlock limit")
	}

	if err := m.loadTCPPrograms(); err != nil {
		return fmt.Errorf("load TCP programs: %w", err)
	}

	if err := m.loadUDPPrograms(); err != nil {
		m.cleanup()
		return fmt.Errorf("load UDP programs: %w", err)
	}

	m.running = true
	m.wg.Add(1)
	go m.tcpEventLoop()
	m.wg.Add(1)
	go m.udpEventLoop()

	log.Info("eBPF manager started")
	return nil
}

// Stop 优雅关闭。
//
// 正确的关闭顺序：
//  1. 先 close ring buffer reader ——这会让阻塞在 Read() 里的 goroutine
//     立即收到 ErrClosed 并自行退出。
//  2. 再 wg.Wait() 等待 goroutine 真正结束。
//  3. 最后 cleanup() 关闭 kprobe links 和 BPF maps。
//
// 原来代码用 stopCh + select/default 是非阻塞轮询，无法打断已经进入
// Read() 的 goroutine，导致 wg.Wait() 永远卡死、Ctrl+C 无响应。
func (m *Manager) Stop() {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}
	m.running = false

	// Step 1: 关闭 reader，打断阻塞的 Read()
	if m.tcpRing != nil {
		m.tcpRing.Close()
	}
	if m.udpRing != nil {
		m.udpRing.Close()
	}
	m.mu.Unlock()

	// Step 2: 等待事件循环 goroutine 退出
	m.wg.Wait()

	// Step 3: 清理 kprobe links 和 BPF maps
	m.cleanup()
	log.Info("eBPF manager stopped")
}

// ---------------------------------------------------------------------------
// Load helpers
// ---------------------------------------------------------------------------

func (m *Manager) loadTCPPrograms() error {
	objPath := fmt.Sprintf("%s/tcp_tracer.o", m.opts.BPFObjDir)
	if _, err := os.Stat(objPath); err != nil {
		return fmt.Errorf("TCP BPF object not found at %s: %w", objPath, err)
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("load collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("new collection: %w", err)
	}

	m.tcpObjs = &tcpObjects{
		FlowTrackerMap: coll.Maps["flow_tracker_map"],
		TcpEvents:      coll.Maps["tcp_events"],
		StatsMap:       coll.Maps["stats_map"],
	}

	hooks := []struct{ prog, fn string }{
		{"kprobe__tcp_connect", "tcp_connect"},
		{"kprobe__tcp_rcv_state_process", "tcp_rcv_state_process"},
		{"kprobe__tcp_sendmsg", "tcp_sendmsg"},
		{"kprobe__tcp_ack", "tcp_ack"},
		{"kprobe__tcp_retransmit_skb", "tcp_retransmit_skb"},
		{"kprobe__tcp_select_window", "tcp_select_window"},
		{"kprobe__tcp_send_active_reset", "tcp_send_active_reset"},
		{"kprobe__tcp_set_state", "tcp_set_state"},
	}
	for _, h := range hooks {
		prog := coll.Programs[h.prog]
		if prog == nil {
			log.WithField("prog", h.prog).Warn("Program not found in collection")
			continue
		}
		kp, err := link.Kprobe(h.fn, prog, nil)
		if err != nil {
			log.WithFields(log.Fields{"prog": h.prog, "fn": h.fn}).
				WithError(err).Warn("Failed to attach kprobe")
			continue
		}
		m.links = append(m.links, kp)
		log.WithFields(log.Fields{"prog": h.prog, "fn": h.fn}).Debug("kprobe attached")
	}

	// ringbuf.NewReader 直接接受 RINGBUF 类型的 *ebpf.Map，不需要指定 buffer 大小
	// （大小已在 BPF 程序的 max_entries 里固定）
	rd, err := ringbuf.NewReader(m.tcpObjs.TcpEvents)
	if err != nil {
		coll.Close()
		return fmt.Errorf("new ringbuf reader for tcp_events: %w", err)
	}
	m.tcpRing = rd
	coll.Close()
	return nil
}

func (m *Manager) loadUDPPrograms() error {
	objPath := fmt.Sprintf("%s/udp_tracer.o", m.opts.BPFObjDir)
	if _, err := os.Stat(objPath); err != nil {
		log.WithField("path", objPath).Warn("UDP BPF object not found, UDP monitoring disabled")
		return nil
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("load UDP collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("new UDP collection: %w", err)
	}

	m.udpObjs = &udpObjects{
		UdpFlowMap: coll.Maps["udp_flow_map"],
		UdpEvents:  coll.Maps["udp_events"],
	}

	for _, h := range []struct {
		prog    string
		fn      string
		retprobe bool
	}{
		{"kprobe__udp_sendmsg", "udp_sendmsg", false},
		{"kprobe__udp_recvmsg", "udp_recvmsg", false},
		{"kretprobe__udp_recvmsg", "udp_recvmsg", true},
	} {
		prog := coll.Programs[h.prog]
		if prog == nil {
			continue
		}
		var kp link.Link
		var err error
		if h.retprobe {
			kp, err = link.Kretprobe(h.fn, prog, nil)
		} else {
			kp, err = link.Kprobe(h.fn, prog, nil)
		}
		if err != nil {
			log.WithField("fn", h.fn).WithError(err).Warn("Failed to attach UDP kprobe")
			continue
		}
		m.links = append(m.links, kp)
		log.WithFields(log.Fields{"prog": h.prog, "retprobe": h.retprobe}).Debug("UDP probe attached")
	}

	rd, err := ringbuf.NewReader(m.udpObjs.UdpEvents)
	if err != nil {
		coll.Close()
		return fmt.Errorf("new ringbuf reader for udp_events: %w", err)
	}
	m.udpRing = rd
	coll.Close()
	return nil
}

// ---------------------------------------------------------------------------
// Event loops
//
// 正确模式：直接阻塞在 Read()。
// 不要在 Read() 前加 select/default 轮询 stopCh——那样在 goroutine 阻塞
// 于 Read() 时永远无法响应 stopCh，导致 Stop() 中的 wg.Wait() 卡死。
//
// Stop() 调用 reader.Close() 后，Read() 会立即返回 ringbuf.ErrClosed，
// 循环检测到后 return，wg.Done() 通知 Stop() 可以继续。
// ---------------------------------------------------------------------------

func (m *Manager) tcpEventLoop() {
	defer m.wg.Done()
	log.Info("TCP ring buffer event loop started")

	for {
		record, err := m.tcpRing.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Debug("TCP ring buffer closed, event loop exiting")
				return
			}
			log.WithError(err).Warn("Error reading from TCP ring buffer")
			continue
		}

		event, err := parseTCPEvent(record.RawSample)
		if err != nil {
			log.WithError(err).Debug("Failed to parse TCP event")
			continue
		}

		m.mu.Lock()
		handlers := m.tcpHandlers
		m.mu.Unlock()

		for _, h := range handlers {
			h.HandleTCPEvent(event)
		}
	}
}

func (m *Manager) udpEventLoop() {
	defer m.wg.Done()

	if m.udpRing == nil {
		log.Info("UDP monitoring disabled, event loop not started")
		return
	}
	log.Info("UDP ring buffer event loop started")

	for {
		record, err := m.udpRing.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Debug("UDP ring buffer closed, event loop exiting")
				return
			}
			log.WithError(err).Warn("Error reading from UDP ring buffer")
			continue
		}

		event, err := parseUDPEvent(record.RawSample)
		if err != nil {
			log.WithError(err).Debug("Failed to parse UDP event")
			continue
		}

		m.mu.Lock()
		handlers := m.udpHandlers
		m.mu.Unlock()

		for _, h := range handlers {
			h.HandleUDPEvent(event)
		}
	}
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

func (m *Manager) cleanup() {
	for _, l := range m.links {
		l.Close()
	}
	m.links = nil

	// reader 已在 Stop() 中提前关闭，这里幂等关闭
	if m.tcpRing != nil {
		m.tcpRing.Close()
		m.tcpRing = nil
	}
	if m.udpRing != nil {
		m.udpRing.Close()
		m.udpRing = nil
	}
	if m.tcpObjs != nil {
		if m.tcpObjs.FlowTrackerMap != nil {
			m.tcpObjs.FlowTrackerMap.Close()
		}
		if m.tcpObjs.TcpEvents != nil {
			m.tcpObjs.TcpEvents.Close()
		}
		if m.tcpObjs.StatsMap != nil {
			m.tcpObjs.StatsMap.Close()
		}
		m.tcpObjs = nil
	}
	if m.udpObjs != nil {
		if m.udpObjs.UdpFlowMap != nil {
			m.udpObjs.UdpFlowMap.Close()
		}
		if m.udpObjs.UdpEvents != nil {
			m.udpObjs.UdpEvents.Close()
		}
		m.udpObjs = nil
	}
}

// ---------------------------------------------------------------------------
// Deserializers — 按 C struct 内存布局逐字段解析（小端）
// ---------------------------------------------------------------------------

func parseTCPEvent(raw []byte) (*TCPEvent, error) {
	const minSize = 152
	if len(raw) < minSize {
		return nil, fmt.Errorf("TCP raw data too short: got %d, want >= %d", len(raw), minSize)
	}
	ev := &TCPEvent{}
	ev.TimestampNs    = binary.LittleEndian.Uint64(raw[0:8])
	ev.PID            = binary.LittleEndian.Uint32(raw[8:12])
	ev.TID            = binary.LittleEndian.Uint32(raw[12:16])
	copy(ev.Comm[:], raw[16:32])
	ev.SAddr          = binary.LittleEndian.Uint32(raw[32:36])
	ev.DAddr          = binary.LittleEndian.Uint32(raw[36:40])
	ev.SPort          = binary.LittleEndian.Uint16(raw[40:42])
	ev.DPort          = binary.LittleEndian.Uint16(raw[42:44])
	ev.Protocol       = raw[44]
	ev.EventType      = raw[45]
	ev.Direction      = raw[46]
	// raw[47] = alignment padding
	ev.SynRTT         = binary.LittleEndian.Uint32(raw[48:52])
	ev.SynRTTClient   = binary.LittleEndian.Uint32(raw[52:56])
	ev.SynRTTServer   = binary.LittleEndian.Uint32(raw[56:60])
	ev.RTTMean        = binary.LittleEndian.Uint32(raw[60:64])
	ev.RTTMax         = binary.LittleEndian.Uint32(raw[64:68])
	ev.RTTMin         = binary.LittleEndian.Uint32(raw[68:72])
	ev.SRTMean        = binary.LittleEndian.Uint32(raw[72:76])
	ev.SRTMax         = binary.LittleEndian.Uint32(raw[76:80])
	ev.RetransCount   = binary.LittleEndian.Uint32(raw[80:84])
	// raw[84:88] = padding (align RetransBytes to 8)
	ev.RetransBytes    = binary.LittleEndian.Uint64(raw[88:96])
	ev.ZeroWndCount    = binary.LittleEndian.Uint32(raw[96:100])
	// raw[100:104] = padding
	ev.ZeroWndDuration = binary.LittleEndian.Uint64(raw[104:112])
	ev.BytesSent       = binary.LittleEndian.Uint64(raw[112:120])
	ev.BytesReceived   = binary.LittleEndian.Uint64(raw[120:128])
	ev.PacketsSent     = binary.LittleEndian.Uint64(raw[128:136])
	ev.PacketsReceived = binary.LittleEndian.Uint64(raw[136:144])
	ev.SynRetrans      = raw[144]
	ev.RSTCount        = raw[145]
	ev.TimeoutFlag     = raw[146]
	ev.TCPState        = raw[147]
	ev.DurationNs      = binary.LittleEndian.Uint32(raw[148:152])
	return ev, nil
}

func parseUDPEvent(raw []byte) (*UDPEvent, error) {
	const minSize = 64
	if len(raw) < minSize {
		return nil, fmt.Errorf("UDP raw data too short: got %d, want >= %d", len(raw), minSize)
	}
	ev := &UDPEvent{}
	ev.TimestampNs = binary.LittleEndian.Uint64(raw[0:8])
	ev.PID         = binary.LittleEndian.Uint32(raw[8:12])
	ev.TID         = binary.LittleEndian.Uint32(raw[12:16])
	copy(ev.Comm[:], raw[16:32])
	ev.SAddr       = binary.LittleEndian.Uint32(raw[32:36])
	ev.DAddr       = binary.LittleEndian.Uint32(raw[36:40])
	ev.SPort       = binary.LittleEndian.Uint16(raw[40:42])
	ev.DPort       = binary.LittleEndian.Uint16(raw[42:44])
	ev.Direction   = raw[44]
	// raw[45:48] = _pad[3]
	ev.PacketSize  = binary.LittleEndian.Uint32(raw[48:52])
	// raw[52:56] = _pad2 (align TotalBytes to 8)
	ev.TotalBytes  = binary.LittleEndian.Uint64(raw[56:64])
	return ev, nil
}
