// pkg/ebpf/l7_inference_manager.go — L7 协议推断 BPF 程序管理

package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	log "github.com/sirupsen/logrus"
)

// ── L7 元数据事件（与 BPF struct l7_meta_event 精确对齐，80 bytes）

type L7MetaEvent struct {
	TimestampNs uint64
	PID         uint32
	TID         uint32
	Comm        [16]byte
	SAddr       uint32
	DAddr       uint32
	SPort       uint16
	DPort       uint16
	Proto       uint8
	Direction   uint8
	L7Proto     uint8
	ReqType     uint8 // 1=request 2=response 3=session
	HTTPMethod  uint8
	MySQLCmd    uint8
	HTTPStatus  uint16
	HTTPURLHash uint32
	RedisCmd    [8]byte
	DNSTxID     uint16
	DNSFlags    uint16
	KafkaAPIKey uint16
	_pad        uint16
	KafkaCorrel uint32
	PayloadLen  uint32
}

const l7MetaEventSize = int(unsafe.Sizeof(L7MetaEvent{})) // 80

// L7MetaEventHandler 接收内核推断的协议元数据事件
type L7MetaEventHandler interface {
	HandleL7MetaEvent(event *L7MetaEvent)
}

// ── tail call 跳转表槽位（与 BPF 宏对应）─────────────────

const (
	tailSetup  = 0
	tailHTTP   = 1
	tailHTTP2  = 2
	tailMySQL  = 3
	tailRedis  = 4
	tailDNS    = 5
	tailKafka  = 6
)

// tailProgNames 跳转表槽位 → BPF 程序名
var tailProgNames = map[uint32]string{
	tailSetup: "tail_setup",
	tailHTTP:  "tail_http",
	tailHTTP2: "tail_http2",
	tailMySQL: "tail_mysql",
	tailRedis: "tail_redis",
	tailDNS:   "tail_dns",
	tailKafka: "tail_kafka",
}

type l7InferObjects struct {
	L7MetaEvents *ebpf.Map
}

// loadL7InferencePrograms 加载 l7_inference_tracer.o 并挂载钩子
func (m *Manager) loadL7InferencePrograms() error {
	objPath := fmt.Sprintf("%s/l7_inference_tracer.o", m.opts.BPFObjDir)
	if _, err := os.Stat(objPath); err != nil {
		log.WithField("path", objPath).Debug("l7_inference_tracer.o not found, kernel-side inference disabled")
		return nil
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("load L7 inference collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("new L7 inference collection: %w", err)
	}
	defer coll.Close()

	// 填充 tail call 跳转表
	// 每个协议子程序 + tail_setup 都注册到 l7_tail_progs
	tailMap := coll.Maps["l7_tail_progs"]
	if tailMap == nil {
		return fmt.Errorf("l7_tail_progs map not found")
	}
	for slot, name := range tailProgNames {
		prog := coll.Programs[name]
		if prog == nil {
			log.WithField("prog", name).Debug("tail call program not found, skipping slot")
			continue
		}
		if err := tailMap.Put(uint32(slot), uint32(prog.FD())); err != nil {
			log.WithField("prog", name).WithError(err).Warn("Failed to insert tail call")
		}
	}

	l7MetaMap := coll.Maps["l7_meta_events"]
	if l7MetaMap == nil {
		return fmt.Errorf("l7_meta_events map not found")
	}
	m.l7InferObjs = &l7InferObjects{L7MetaEvents: l7MetaMap}

	// 只挂载 kprobe/kretprobe（tail call 子程序由内核跳转，不需要 link.Kprobe）
	probes := []struct {
		prog     string
		fn       string
		retprobe bool
	}{
		{"kprobe__tcp_sendmsg_infer",  "tcp_sendmsg", false},
		{"kretprobe__tcp_sendmsg_infer", "tcp_sendmsg", true},
		{"kprobe__tcp_recvmsg_infer",  "tcp_recvmsg", false},
		{"kretprobe__tcp_recvmsg_infer", "tcp_recvmsg", true},
	}
	attached := 0
	for _, h := range probes {
		prog := coll.Programs[h.prog]
		if prog == nil {
			log.WithField("prog", h.prog).Debug("L7 inference program not found")
			continue
		}
		var lnk link.Link
		var lerr error
		if h.retprobe {
			lnk, lerr = link.Kretprobe(h.fn, prog, nil)
		} else {
			lnk, lerr = link.Kprobe(h.fn, prog, nil)
		}
		if lerr != nil {
			log.WithField("fn", h.fn).WithError(lerr).Warn("Failed to attach L7 inference probe")
			continue
		}
		m.links = append(m.links, lnk)
		attached++
	}

	rd, err := ringbuf.NewReader(l7MetaMap)
	if err != nil {
		return fmt.Errorf("new ringbuf reader for l7_meta_events: %w", err)
	}
	m.l7InferRing = rd

	log.WithField("probes", attached).Info("L7 inference BPF programs loaded (kernel-side protocol detection enabled)")
	return nil
}

// l7InferEventLoop 从 l7_meta_events ringbuf 读取元数据事件
func (m *Manager) l7InferEventLoop() {
	defer m.wg.Done()
	log.Info("L7 inference ring buffer event loop started")
	for {
		record, err := m.l7InferRing.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.WithError(err).Warn("Error reading from L7 inference ring buffer")
			continue
		}
		event, err := parseL7MetaEvent(record.RawSample)
		if err != nil {
			log.WithError(err).Debug("Failed to parse L7 meta event")
			continue
		}
		m.mu.Lock()
		handlers := m.l7MetaHandlers
		m.mu.Unlock()
		for _, h := range handlers {
			h.HandleL7MetaEvent(event)
		}
	}
}

// RegisterL7MetaHandler 注册 L7 元数据事件处理器
func (m *Manager) RegisterL7MetaHandler(h L7MetaEventHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.l7MetaHandlers = append(m.l7MetaHandlers, h)
}

// parseL7MetaEvent 从原始字节反序列化 L7MetaEvent
func parseL7MetaEvent(raw []byte) (*L7MetaEvent, error) {
	if len(raw) < l7MetaEventSize {
		return nil, fmt.Errorf("L7 meta event too short: %d < %d", len(raw), l7MetaEventSize)
	}
	ev := &L7MetaEvent{}
	off := 0

	ev.TimestampNs = binary.LittleEndian.Uint64(raw[off:]); off += 8
	ev.PID         = binary.LittleEndian.Uint32(raw[off:]); off += 4
	ev.TID         = binary.LittleEndian.Uint32(raw[off:]); off += 4
	copy(ev.Comm[:], raw[off:off+16]);                       off += 16
	ev.SAddr        = binary.LittleEndian.Uint32(raw[off:]); off += 4
	ev.DAddr        = binary.LittleEndian.Uint32(raw[off:]); off += 4
	ev.SPort        = binary.LittleEndian.Uint16(raw[off:]); off += 2
	ev.DPort        = binary.LittleEndian.Uint16(raw[off:]); off += 2
	ev.Proto        = raw[off]; off++
	ev.Direction    = raw[off]; off++
	ev.L7Proto      = raw[off]; off++
	ev.ReqType      = raw[off]; off++
	ev.HTTPMethod   = raw[off]; off++
	ev.MySQLCmd     = raw[off]; off++
	ev.HTTPStatus   = binary.LittleEndian.Uint16(raw[off:]); off += 2
	ev.HTTPURLHash  = binary.LittleEndian.Uint32(raw[off:]); off += 4
	copy(ev.RedisCmd[:], raw[off:off+8]);                    off += 8
	ev.DNSTxID      = binary.LittleEndian.Uint16(raw[off:]); off += 2
	ev.DNSFlags     = binary.LittleEndian.Uint16(raw[off:]); off += 2
	ev.KafkaAPIKey  = binary.LittleEndian.Uint16(raw[off:]); off += 2
	off += 2 // _pad
	ev.KafkaCorrel  = binary.LittleEndian.Uint32(raw[off:]); off += 4
	ev.PayloadLen   = binary.LittleEndian.Uint32(raw[off:])

	return ev, nil
}

// L7MetaProtoString 将 BPF 协议枚举转为字符串
func L7MetaProtoString(proto uint8) string {
	switch proto {
	case 1: return "HTTP"
	case 2: return "HTTP2"
	case 3: return "MySQL"
	case 4: return "Redis"
	case 5: return "DNS"
	case 6: return "Kafka"
	case 7: return "MQTT"
	default: return "Unknown"
	}
}

// ToL7Event 将元数据事件转换为 L7Event（payload 为空）
func (ev *L7MetaEvent) ToL7Event() *L7Event {
	return &L7Event{
		TimestampNs: ev.TimestampNs,
		PID:         ev.PID,
		TID:         ev.TID,
		Comm:        ev.Comm,
		SAddr:       ev.SAddr,
		DAddr:       ev.DAddr,
		SPort:       ev.SPort,
		DPort:       ev.DPort,
		Protocol:    ev.Proto,
		Direction:   ev.Direction,
		PayloadSize: 0,
	}
}

// StartTime 从时间戳生成 time.Time
func (ev *L7MetaEvent) StartTime() time.Time {
	return time.Unix(0, int64(ev.TimestampNs))
}
