// pkg/ebpf/manager.go — eBPF 程序加载、kprobe 挂载、TC 分类器、Ring Buffer 事件循环

package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"
)

// ── Handler 接口 ──────────────────────────────────────────

type TCPEventHandler interface {
	HandleTCPEvent(event *TCPEvent)
}

type UDPEventHandler interface {
	HandleUDPEvent(event *UDPFlowEvent)
}

type TCPacketHandler interface {
	HandleTCPacket(packet *TCPacket)
}

type L7EventHandler interface {
	HandleL7Event(event *L7Event)
}

// ── ManagerOptions ────────────────────────────────────────

type ManagerOptions struct {
	RingBufSize  int
	MaxFlows     int
	BPFObjDir    string
	TCInterfaces []string
}

var DefaultManagerOptions = ManagerOptions{
	RingBufSize: 256 * 1024,
	MaxFlows:    10240,
	BPFObjDir:   "./bpf",
}

// ── 内部对象持有 ──────────────────────────────────────────

type tcpObjects struct {
	FlowTrackerMap *ebpf.Map
	TcpEvents      *ebpf.Map
	StatsMap       *ebpf.Map
}

type udpObjects struct {
	UdpFlowMap  *ebpf.Map
	UdpEvents   *ebpf.Map
	RecvmsgArgs *ebpf.Map
}

// ── Manager ───────────────────────────────────────────────

type Manager struct {
	opts ManagerOptions

	tcpObjs *tcpObjects
	udpObjs *udpObjects

	tcpRing *ringbuf.Reader
	udpRing *ringbuf.Reader
	l7Ring  *ringbuf.Reader
	tcRing  *ringbuf.Reader

	links []link.Link

	tcpHandlers   []TCPEventHandler
	udpHandlers   []UDPEventHandler
	tcpktHandlers []TCPacketHandler
	l7Handlers    []L7EventHandler

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

func (m *Manager) RegisterL7Handler(h L7EventHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.l7Handlers = append(m.l7Handlers, h)
}

// Start 加载 eBPF 程序并启动事件循环
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return errors.New("manager already running")
	}

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

	if err := m.loadL7Programs(); err != nil {
		log.WithError(err).Warn("L7 BPF load failed, L7 capture disabled")
	}

	if err := m.loadTCPrograms(); err != nil {
		log.WithError(err).Warn("TC BPF load failed, TC capture disabled")
	}

	m.running = true
	m.wg.Add(1)
	go m.tcpEventLoop()
	m.wg.Add(1)
	go m.udpEventLoop()
	if m.l7Ring != nil {
		m.wg.Add(1)
		go m.l7EventLoop()
	}
	if m.tcRing != nil {
		m.wg.Add(1)
		go m.tcEventLoop()
	}

	log.Info("eBPF manager started")
	return nil
}

func (m *Manager) Stop() {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}
	m.running = false
	for _, r := range []*ringbuf.Reader{m.tcpRing, m.udpRing, m.l7Ring, m.tcRing} {
		if r != nil {
			r.Close()
		}
	}
	m.mu.Unlock()
	m.wg.Wait()
	m.cleanup()
	log.Info("eBPF manager stopped")
}

// ── Loaders ───────────────────────────────────────────────

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

	kprobes := []struct{ prog, fn string }{
		{"kprobe__tcp_connect", "tcp_connect"},
		{"kprobe__inet_csk_accept", "inet_csk_accept"},
		{"kprobe__tcp_rcv_state_process", "tcp_rcv_state_process"},
		{"kprobe__tcp_sendmsg", "tcp_sendmsg"},
		{"kprobe__tcp_recvmsg", "tcp_recvmsg"},
		{"kprobe__tcp_ack", "tcp_ack"},
		{"kprobe__tcp_retransmit_skb", "tcp_retransmit_skb"},
		{"kprobe__tcp_send_active_reset", "tcp_send_active_reset"},
		{"kprobe__tcp_set_state", "tcp_set_state"},
	}
	for _, h := range kprobes {
		prog := coll.Programs[h.prog]
		if prog == nil {
			log.WithField("prog", h.prog).Warn("TCP program not found in collection")
			continue
		}
		kp, err := link.Kprobe(h.fn, prog, nil)
		if err != nil {
			log.WithFields(log.Fields{"prog": h.prog, "fn": h.fn}).
				WithError(err).Warn("Failed to attach TCP kprobe")
			continue
		}
		m.links = append(m.links, kp)
		log.WithFields(log.Fields{"prog": h.prog, "fn": h.fn}).Debug("TCP kprobe attached")
	}

	kretprobes := []struct{ prog, fn string }{
		{"kretprobe__inet_csk_accept", "inet_csk_accept"},
		{"kretprobe__tcp_recvmsg", "tcp_recvmsg"},
	}
	for _, h := range kretprobes {
		prog := coll.Programs[h.prog]
		if prog == nil {
			log.WithField("prog", h.prog).Warn("TCP kretprobe program not found")
			continue
		}
		krp, err := link.Kretprobe(h.fn, prog, nil)
		if err != nil {
			log.WithFields(log.Fields{"prog": h.prog, "fn": h.fn}).
				WithError(err).Warn("Failed to attach TCP kretprobe")
			continue
		}
		m.links = append(m.links, krp)
	}

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
		UdpFlowMap:  coll.Maps["udp_flow_map"],
		UdpEvents:   coll.Maps["udp_events"],
		RecvmsgArgs: coll.Maps["recvmsg_args"],
	}

	for _, h := range []struct {
		prog     string
		fn       string
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
		var lerr error
		if h.retprobe {
			kp, lerr = link.Kretprobe(h.fn, prog, nil)
		} else {
			kp, lerr = link.Kprobe(h.fn, prog, nil)
		}
		if lerr != nil {
			log.WithField("fn", h.fn).WithError(lerr).Warn("Failed to attach UDP probe")
			continue
		}
		m.links = append(m.links, kp)
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

func (m *Manager) loadL7Programs() error {
	objPath := fmt.Sprintf("%s/l7_tracer.o", m.opts.BPFObjDir)
	if _, err := os.Stat(objPath); err != nil {
		log.WithField("path", objPath).Debug("L7 BPF object not found, L7 capture disabled")
		return nil
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("load L7 collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("new L7 collection: %w", err)
	}

	l7Events := coll.Maps["l7_events"]
	if l7Events == nil {
		coll.Close()
		return fmt.Errorf("l7_events map not found")
	}

	// l7_tracer.c 中的 Section 名：kprobe/tcp_sendmsg 和 kprobe/tcp_recvmsg
	// 对应程序名（cilium/ebpf 用 SEC 名推断）：kprobe__tcp_sendmsg_l7 等
	hooks := []struct {
		prog     string
		fn       string
		retprobe bool
	}{
		{"kprobe__tcp_sendmsg_l7", "tcp_sendmsg", false},
		{"kprobe__tcp_recvmsg_l7", "tcp_recvmsg", false},
		{"kretprobe__tcp_recvmsg_l7", "tcp_recvmsg", true},
		{"kretprobe__tcp_sendmsg_l7", "tcp_sendmsg", true},
	}
	for _, h := range hooks {
		prog := coll.Programs[h.prog]
		if prog == nil {
			log.WithField("prog", h.prog).Debug("L7 program not found in collection, skipping")
			continue
		}
		var kp link.Link
		var lerr error
		if h.retprobe {
			kp, lerr = link.Kretprobe(h.fn, prog, nil)
		} else {
			kp, lerr = link.Kprobe(h.fn, prog, nil)
		}
		if lerr != nil {
			log.WithField("fn", h.fn).WithError(lerr).Warn("Failed to attach L7 probe")
			continue
		}
		m.links = append(m.links, kp)
		log.WithField("prog", h.prog).Debug("L7 probe attached")
	}

	rd, err := ringbuf.NewReader(l7Events)
	if err != nil {
		coll.Close()
		return fmt.Errorf("new ringbuf reader for l7_events: %w", err)
	}
	m.l7Ring = rd
	coll.Close()
	log.Info("L7 eBPF programs loaded")
	return nil
}

// ── TC Program Loader ─────────────────────────────────────
// 使用 github.com/cilium/ebpf/link 的原生 TC 接口，自动管理 clsact qdisc 及 BPF filter。
// 生命周期随 link.Link.Close() 一并清理，无需手写 netlink 代码。

func (m *Manager) loadTCPrograms() error {
	objPath := fmt.Sprintf("%s/tc_tracer.o", m.opts.BPFObjDir)
	if _, err := os.Stat(objPath); err != nil {
		log.WithField("path", objPath).Debug("TC BPF object not found, TC capture disabled")
		return nil
	}

	if len(m.opts.TCInterfaces) == 0 {
		log.Debug("No TC interfaces configured, TC capture disabled")
		return nil
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("load TC collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("new TC collection: %w", err)
	}
	defer coll.Close()

	tcEvents := coll.Maps["tc_events"]
	if tcEvents == nil {
		return fmt.Errorf("tc_events map not found in tc_tracer.o")
	}

	ingressProg := coll.Programs["tc_ingress"]
	egressProg := coll.Programs["tc_egress"]
	if ingressProg == nil || egressProg == nil {
		return fmt.Errorf("tc_ingress or tc_egress program not found in tc_tracer.o")
	}

	attached := 0
	for _, ifName := range m.opts.TCInterfaces {
		iface, err := net.InterfaceByName(ifName)
		if err != nil {
			log.WithField("iface", ifName).WithError(err).Warn("TC: interface not found, skipping")
			continue
		}

		// 使用 link.AttachTC，由 cilium/ebpf 库内部处理 clsact qdisc 创建及 filter 挂载
		ingLink, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   ingressProg,
			Attach:    ebpf.AttachTCXIngress,
		})
		if err != nil {
			log.WithField("iface", ifName).WithError(err).Warn("TC: attach ingress failed")
			continue
		}
		m.links = append(m.links, ingLink)

		egrLink, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   egressProg,
			Attach:    ebpf.AttachTCXEgress,
		})
		if err != nil {
			log.WithField("iface", ifName).WithError(err).Warn("TC: attach egress failed")
			// ingress 已成功，继续计入
		} else {
			m.links = append(m.links, egrLink)
		}

		log.WithField("iface", ifName).Info("TC classifier attached (ingress+egress)")
		attached++
	}

	if attached == 0 {
		log.Warn("TC: no interfaces attached successfully, TC capture disabled")
		return nil
	}

	rd, err := ringbuf.NewReader(tcEvents)
	if err != nil {
		return fmt.Errorf("new ringbuf reader for tc_events: %w", err)
	}
	m.tcRing = rd
	log.WithField("interfaces", m.opts.TCInterfaces).Info("TC BPF programs loaded")
	return nil
}

// ── Event Loops ───────────────────────────────────────────

func (m *Manager) tcpEventLoop() {
	defer m.wg.Done()
	log.Info("TCP ring buffer event loop started")
	for {
		record, err := m.tcpRing.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
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

func (m *Manager) l7EventLoop() {
	defer m.wg.Done()
	log.Info("L7 ring buffer event loop started")
	for {
		record, err := m.l7Ring.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.WithError(err).Warn("Error reading from L7 ring buffer")
			continue
		}
		event, err := parseL7Event(record.RawSample)
		if err != nil {
			log.WithError(err).Debug("Failed to parse L7 event")
			continue
		}
		m.mu.Lock()
		handlers := m.l7Handlers
		m.mu.Unlock()
		for _, h := range handlers {
			h.HandleL7Event(event)
		}
	}
}

func (m *Manager) tcEventLoop() {
	defer m.wg.Done()
	log.Info("TC ring buffer event loop started")
	for {
		record, err := m.tcRing.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.WithError(err).Warn("Error reading from TC ring buffer")
			continue
		}
		pkt, err := parseTCPacketEvent(record.RawSample)
		if err != nil {
			log.WithError(err).Debug("Failed to parse TC packet")
			continue
		}
		m.mu.Lock()
		handlers := m.tcpktHandlers
		m.mu.Unlock()
		for _, h := range handlers {
			h.HandleTCPacket(pkt)
		}
	}
}

// ── Cleanup ───────────────────────────────────────────────

func (m *Manager) cleanup() {
	for _, l := range m.links {
		l.Close()
	}
	m.links = nil
	if m.tcpObjs != nil {
		m.tcpObjs.FlowTrackerMap.Close()
		m.tcpObjs.TcpEvents.Close()
		m.tcpObjs.StatsMap.Close()
		m.tcpObjs = nil
	}
	if m.udpObjs != nil {
		m.udpObjs.UdpFlowMap.Close()
		m.udpObjs.UdpEvents.Close()
		m.udpObjs.RecvmsgArgs.Close()
		m.udpObjs = nil
	}
}

// ── Deserializers ─────────────────────────────────────────

func parseTCPEvent(raw []byte) (*TCPEvent, error) {
	const size = 152
	if len(raw) < size {
		return nil, fmt.Errorf("TCP raw data too short: got %d, want %d", len(raw), size)
	}
	ev := &TCPEvent{}
	ev.TimestampNs = binary.LittleEndian.Uint64(raw[0:8])
	ev.PID = binary.LittleEndian.Uint32(raw[8:12])
	ev.TID = binary.LittleEndian.Uint32(raw[12:16])
	copy(ev.Comm[:], raw[16:32])
	ev.SAddr = binary.LittleEndian.Uint32(raw[32:36])
	ev.DAddr = binary.LittleEndian.Uint32(raw[36:40])
	ev.SPort = binary.LittleEndian.Uint16(raw[40:42])
	ev.DPort = binary.LittleEndian.Uint16(raw[42:44])
	ev.Protocol = raw[44]
	ev.Lifecycle = raw[45]
	ev.Direction = raw[46]
	ev.Role = raw[47]
	ev.SynRTT = binary.LittleEndian.Uint32(raw[48:52])
	ev.SynRTTClient = binary.LittleEndian.Uint32(raw[52:56])
	ev.SynRTTServer = binary.LittleEndian.Uint32(raw[56:60])
	ev.RTTMean = binary.LittleEndian.Uint32(raw[60:64])
	ev.RTTMax = binary.LittleEndian.Uint32(raw[64:68])
	ev.RTTMin = binary.LittleEndian.Uint32(raw[68:72])
	ev.SRTMean = binary.LittleEndian.Uint32(raw[72:76])
	ev.SRTMax = binary.LittleEndian.Uint32(raw[76:80])
	ev.RetransCount = binary.LittleEndian.Uint32(raw[80:84])
	ev.EventSubtype = raw[84]
	ev.DestroyReason = raw[85]
	ev.SynRetrans = raw[86]
	ev.RSTCount = raw[87]
	ev.RetransBytes = binary.LittleEndian.Uint64(raw[88:96])
	ev.ZeroWndCount = binary.LittleEndian.Uint32(raw[96:100])
	ev.ZeroWndDuration = binary.LittleEndian.Uint64(raw[104:112])
	ev.BytesSent = binary.LittleEndian.Uint64(raw[112:120])
	ev.BytesReceived = binary.LittleEndian.Uint64(raw[120:128])
	ev.PacketsSent = binary.LittleEndian.Uint64(raw[128:136])
	ev.PacketsReceived = binary.LittleEndian.Uint64(raw[136:144])
	ev.TimeoutFlag = raw[144]
	ev.TCPState = raw[145]
	ev.DurationUs = binary.LittleEndian.Uint32(raw[148:152])
	return ev, nil
}

func parseUDPEvent(raw []byte) (*UDPFlowEvent, error) {
	const size = 88
	if len(raw) < size {
		return nil, fmt.Errorf("UDP raw data too short: got %d, want %d", len(raw), size)
	}
	ev := &UDPFlowEvent{}
	ev.TimestampNs = binary.LittleEndian.Uint64(raw[0:8])
	ev.PID = binary.LittleEndian.Uint32(raw[8:12])
	ev.TID = binary.LittleEndian.Uint32(raw[12:16])
	copy(ev.Comm[:], raw[16:32])
	ev.SAddr = binary.LittleEndian.Uint32(raw[32:36])
	ev.DAddr = binary.LittleEndian.Uint32(raw[36:40])
	ev.SPort = binary.LittleEndian.Uint16(raw[40:42])
	ev.DPort = binary.LittleEndian.Uint16(raw[42:44])
	ev.Direction = raw[44]
	ev.Role = raw[45]
	ev.EventType = raw[46]
	ev.PacketSize = binary.LittleEndian.Uint32(raw[48:52])
	ev.TotalBytes = binary.LittleEndian.Uint64(raw[56:64])
	ev.BytesSent = binary.LittleEndian.Uint64(raw[64:72])
	ev.BytesRecv = binary.LittleEndian.Uint64(raw[72:80])
	ev.DurationNs = binary.LittleEndian.Uint64(raw[80:88])
	return ev, nil
}

func parseL7Event(raw []byte) (*L7Event, error) {
	const headerSize = 50
	if len(raw) < headerSize {
		return nil, fmt.Errorf("L7 raw data too short: %d", len(raw))
	}
	ev := &L7Event{}
	ev.TimestampNs = binary.LittleEndian.Uint64(raw[0:8])
	ev.PID = binary.LittleEndian.Uint32(raw[8:12])
	ev.TID = binary.LittleEndian.Uint32(raw[12:16])
	copy(ev.Comm[:], raw[16:32])
	ev.SAddr = binary.LittleEndian.Uint32(raw[32:36])
	ev.DAddr = binary.LittleEndian.Uint32(raw[36:40])
	ev.SPort = binary.LittleEndian.Uint16(raw[40:42])
	ev.DPort = binary.LittleEndian.Uint16(raw[42:44])
	ev.Protocol = raw[44]
	ev.Direction = raw[45]
	ev.PayloadSize = binary.LittleEndian.Uint32(raw[46:50])
	if len(raw) > headerSize && ev.PayloadSize > 0 {
		copyLen := int(ev.PayloadSize)
		if copyLen > len(ev.Payload) {
			copyLen = len(ev.Payload)
		}
		available := len(raw) - headerSize
		if copyLen > available {
			copyLen = available
		}
		copy(ev.Payload[:], raw[headerSize:headerSize+copyLen])
	}
	return ev, nil
}

// parseTCPacketEvent 解析 TC 包事件（包含 IPv6 字段，72 bytes）
func parseTCPacketEvent(raw []byte) (*TCPacket, error) {
	const size = 72
	if len(raw) < size {
		return nil, fmt.Errorf("TC packet raw data too short: %d (need %d)", len(raw), size)
	}
	pkt := &TCPacket{}
	pkt.TimestampNs = binary.LittleEndian.Uint64(raw[0:8])
	pkt.IfIndex = binary.LittleEndian.Uint32(raw[8:12])
	pkt.SAddr = binary.LittleEndian.Uint32(raw[12:16])
	pkt.DAddr = binary.LittleEndian.Uint32(raw[16:20])
	pkt.SPort = binary.LittleEndian.Uint16(raw[20:22])
	pkt.DPort = binary.LittleEndian.Uint16(raw[22:24])
	pkt.Protocol = raw[24]
	pkt.Direction = raw[25]
	pkt.TCPFlags = raw[26]
	pkt.IPVersion = raw[27]
	pkt.PacketLen = binary.LittleEndian.Uint32(raw[28:32])
	pkt.IPHeaderLen = binary.LittleEndian.Uint32(raw[32:36])
	pkt.IPTTL = raw[36]
	pkt.IPTOS = raw[37]
	pkt.IPID = binary.LittleEndian.Uint16(raw[38:40])
	// [40:56] saddr6, [56:72] daddr6
	copy(pkt.SAddr6[:], raw[40:56])
	copy(pkt.DAddr6[:], raw[56:72])
	return pkt, nil
}
