// pkg/ebpf/types.go — 核心类型定义

package ebpf

import "time"

// ── Flow 生命周期 ─────────────────────────────────────────

type FlowLifecycle uint8

const (
	FlowCreate  FlowLifecycle = 1
	FlowUpdate  FlowLifecycle = 2
	FlowDestroy FlowLifecycle = 3
)

func (l FlowLifecycle) String() string {
	switch l {
	case FlowCreate:
		return "CREATE"
	case FlowUpdate:
		return "UPDATE"
	case FlowDestroy:
		return "DESTROY"
	default:
		return "UNKNOWN"
	}
}

// ── 事件子类型 ────────────────────────────────────────────

type EventSubtype uint8

const (
	SubtypeNone       EventSubtype = 0
	SubtypeRetrans    EventSubtype = 1
	SubtypeZeroWnd    EventSubtype = 2
	SubtypeBytesFlush EventSubtype = 3
	SubtypeRST        EventSubtype = 4
)

// ── 销毁原因 ──────────────────────────────────────────────

type DestroyReason uint8

const (
	DestroyFIN     DestroyReason = 1
	DestroyRST     DestroyReason = 2
	DestroyTimeout DestroyReason = 3
)

func (r DestroyReason) String() string {
	switch r {
	case DestroyFIN:
		return "FIN"
	case DestroyRST:
		return "RST"
	case DestroyTimeout:
		return "TIMEOUT"
	default:
		return "UNKNOWN"
	}
}

// ── 连接角色 ──────────────────────────────────────────────

type FlowRole uint8

const (
	RoleUnknown FlowRole = 0
	RoleClient  FlowRole = 1
	RoleServer  FlowRole = 2
)

func (r FlowRole) String() string {
	switch r {
	case RoleClient:
		return "CLIENT"
	case RoleServer:
		return "SERVER"
	default:
		return "UNKNOWN"
	}
}

// ── 方向 ─────────────────────────────────────────────────

const (
	FlowDirectionIngress = 0
	FlowDirectionEgress  = 1
)

// ── 协议 ─────────────────────────────────────────────────

const (
	ProtocolTCP = 6
	ProtocolUDP = 17
)

// ── TCP 状态 ──────────────────────────────────────────────

const (
	TCPEstablished = 1
	TCPSynSent     = 2
	TCPSynRecv     = 3
	TCPFinWait1    = 4
	TCPFinWait2    = 5
	TCPTimeWait    = 6
	TCPClose       = 7
	TCPCloseWait   = 8
	TCPLastAck     = 9
	TCPListen      = 10
	TCPClosing     = 11
)

var TCPStateNames = map[uint8]string{
	TCPEstablished: "ESTABLISHED",
	TCPSynSent:     "SYN_SENT",
	TCPSynRecv:     "SYN_RECV",
	TCPFinWait1:    "FIN_WAIT1",
	TCPFinWait2:    "FIN_WAIT2",
	TCPTimeWait:    "TIME_WAIT",
	TCPClose:       "CLOSE",
	TCPCloseWait:   "CLOSE_WAIT",
	TCPLastAck:     "LAST_ACK",
	TCPListen:      "LISTEN",
	TCPClosing:     "CLOSING",
}

func GetTCPStateName(state uint8) string {
	if name, ok := TCPStateNames[state]; ok {
		return name
	}
	return "UNKNOWN"
}

// ── FlowKey：统一五元组，用于所有 Map/Cache ───────────────

type FlowKey struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
	Proto   uint8
	_       [3]byte
}

// NewFlowKey 构造规范化的 FlowKey（始终以 client 侧为 Src）
func NewFlowKey(saddr, daddr uint32, sport, dport uint16, proto uint8, role FlowRole) FlowKey {
	if role == RoleServer {
		return FlowKey{
			SrcIP:   daddr,
			DstIP:   saddr,
			SrcPort: dport,
			DstPort: sport,
			Proto:   proto,
		}
	}
	return FlowKey{
		SrcIP:   saddr,
		DstIP:   daddr,
		SrcPort: sport,
		DstPort: dport,
		Proto:   proto,
	}
}

// ── TCPEvent：与 BPF struct tcp_event 精确对齐（152 bytes）

type TCPEvent struct {
	TimestampNs uint64   // [0:8]
	PID         uint32   // [8:12]
	TID         uint32   // [12:16]
	Comm        [16]byte // [16:32]

	SAddr    uint32 // [32:36]
	DAddr    uint32 // [36:40]
	SPort    uint16 // [40:42]
	DPort    uint16 // [42:44]
	Protocol uint8  // [44]

	Lifecycle    uint8 // [45]
	Direction    uint8 // [46]
	Role         uint8 // [47]

	SynRTT       uint32 // [48:52]
	SynRTTClient uint32 // [52:56]
	SynRTTServer uint32 // [56:60]

	RTTMean uint32 // [60:64]
	RTTMax  uint32 // [64:68]
	RTTMin  uint32 // [68:72]

	SRTMean uint32 // [72:76]
	SRTMax  uint32 // [76:80]

	RetransCount  uint32 // [80:84]
	EventSubtype  uint8  // [84]
	DestroyReason uint8  // [85]
	SynRetrans    uint8  // [86]
	RSTCount      uint8  // [87]
	RetransBytes  uint64 // [88:96]

	ZeroWndCount    uint32 // [96:100]
	_               uint32 // [100:104]
	ZeroWndDuration uint64 // [104:112]

	BytesSent       uint64 // [112:120]
	BytesReceived   uint64 // [120:128]
	PacketsSent     uint64 // [128:136]
	PacketsReceived uint64 // [136:144]

	TimeoutFlag uint8  // [144]
	TCPState    uint8  // [145]
	_           uint16 // [146:148]
	DurationUs  uint32 // [148:152]
}

// ── UDPFlowEvent：与 BPF struct udp_flow_event 对齐（88 bytes）

type UDPEventType uint8

const (
	UDPFlowNew    UDPEventType = 1
	UDPFlowUpdate UDPEventType = 2
)

func (t UDPEventType) String() string {
	switch t {
	case UDPFlowNew:
		return "NEW"
	case UDPFlowUpdate:
		return "UPDATE"
	default:
		return "UNKNOWN"
	}
}

type UDPFlowEvent struct {
	TimestampNs uint64
	PID         uint32
	TID         uint32
	Comm        [16]byte
	SAddr       uint32 // 规范化 client IP
	DAddr       uint32 // 规范化 server IP
	SPort       uint16 // 规范化 client port
	DPort       uint16 // 规范化 server port
	Direction   uint8
	Role        uint8
	EventType   uint8
	_           uint8
	PacketSize  uint32
	_           uint32
	TotalBytes  uint64
	BytesSent   uint64
	BytesRecv   uint64
	DurationNs  uint64
}

// UDPEvent 后向兼容别名
type UDPEvent = UDPFlowEvent

// UDPFlow 用户态 UDP 流聚合对象
type UDPFlow struct {
	Key         FlowKey
	SrcIP       string
	DstIP       string
	SrcPort     uint16
	DstPort     uint16
	Role        FlowRole
	ProcessName string
	PID         uint32
	StartTime   time.Time
	LastSeen    time.Time
	Duration    time.Duration
	BytesSent   uint64
	BytesRecv   uint64
	PktsSent    uint64
	PktsRecv    uint64
	CloudTag    interface{}
}

// ── L7Event：L7 载荷事件（packed 布局）───────────────────

type L7Event struct {
	TimestampNs uint64
	PID         uint32
	TID         uint32
	Comm        [16]byte
	SAddr       uint32
	DAddr       uint32
	SPort       uint16
	DPort       uint16
	Protocol    uint8
	Direction   uint8
	PayloadSize uint32
	Payload     [4096]byte
}

// ── L7 协议枚举 ───────────────────────────────────────────

type L7Protocol uint16

const (
	L7ProtocolUnknown L7Protocol = 0
	L7ProtocolHTTP    L7Protocol = 1
	L7ProtocolHTTP2   L7Protocol = 2
	L7ProtocolMySQL   L7Protocol = 3
	L7ProtocolRedis   L7Protocol = 4
	L7ProtocolDNS     L7Protocol = 5
	L7ProtocolKafka   L7Protocol = 6
	L7ProtocolGRPC    L7Protocol = 7
	L7ProtocolPing    L7Protocol = 8
	L7ProtocolTLS     L7Protocol = 9
	L7ProtocolCustom  L7Protocol = 100
)

func (p L7Protocol) String() string {
	switch p {
	case L7ProtocolHTTP:
		return "HTTP"
	case L7ProtocolHTTP2:
		return "HTTP2"
	case L7ProtocolMySQL:
		return "MySQL"
	case L7ProtocolRedis:
		return "Redis"
	case L7ProtocolDNS:
		return "DNS"
	case L7ProtocolKafka:
		return "Kafka"
	case L7ProtocolGRPC:
		return "gRPC"
	case L7ProtocolPing:
		return "Ping"
	case L7ProtocolTLS:
		return "TLS"
	case L7ProtocolCustom:
		return "Custom"
	default:
		return "Unknown"
	}
}

type L7RequestType uint8

const (
	L7RequestTypeRequest  L7RequestType = 1
	L7RequestTypeResponse L7RequestType = 2
	L7RequestTypeSession  L7RequestType = 3
)

// ── TCPacket：与 BPF struct tc_packet 对齐 ───────────────
// tc_tracer.c 的 tc_packet 增加了 IPv6 地址字段（总大小 72 bytes）

type TCPacket struct {
	TimestampNs uint64
	IfIndex     uint32
	SAddr       uint32
	DAddr       uint32
	SPort       uint16
	DPort       uint16
	Protocol    uint8
	Direction   uint8
	TCPFlags    uint8
	IPVersion   uint8  // 4 或 6
	PacketLen   uint32
	IPHeaderLen uint32
	IPTTL       uint8
	IPTOS       uint8
	IPID        uint16
	SAddr6      [16]byte
	DAddr6      [16]byte
}

// ── Flow：用户态全量流状态对象 ───────────────────────────

type Flow struct {
	Key FlowKey

	SrcIP       string
	DstIP       string
	SrcPort     uint16
	DstPort     uint16
	Protocol    string
	Role        FlowRole
	ProcessName string
	PID         uint32

	Lifecycle     FlowLifecycle
	DestroyReason DestroyReason
	TCPState      string

	StartTime time.Time
	EndTime   time.Time
	Duration  time.Duration
	LastSeen  time.Time

	SynRTT       time.Duration
	SynRTTServer time.Duration
	SynRTTClient time.Duration

	RTTMin  time.Duration
	RTTMean time.Duration
	RTTMax  time.Duration

	SRTMean time.Duration
	SRTMax  time.Duration

	BytesSent       uint64
	BytesReceived   uint64
	PacketsSent     uint64
	PacketsReceived uint64

	RetransCount uint32
	RetransBytes uint64
	RetransRatio float64

	ZeroWndCount    uint32
	ZeroWndDuration time.Duration

	SynRetransCount uint8
	RSTCount        uint8
	TimeoutOccurred bool

	CloudTag interface{}
}
