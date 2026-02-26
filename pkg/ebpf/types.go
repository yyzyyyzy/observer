// pkg/ebpf/types.go
// DeepFlow 对齐类型定义 v3
//
// 核心设计：
//   - FlowKey：统一五元组 + 协议，所有 Map/Cache 使用同一 key
//   - FlowLifecycle：三态 CREATE / UPDATE / DESTROY
//   - FlowRole：CLIENT / SERVER / UNKNOWN
//   - DestroyReason：FIN / RST / TIMEOUT
//   - TCPEvent：与 BPF struct tcp_event 内存布局精确对齐（152 bytes）
//   - Flow：用户态全量状态对象，所有指标都挂在 Flow 上

package ebpf

import "time"

// ── Flow 生命周期三态 ────────────────────────────────────

// FlowLifecycle 对应 BPF 侧 FLOW_CREATE / FLOW_UPDATE / FLOW_DESTROY
type FlowLifecycle uint8

const (
	FlowCreate  FlowLifecycle = 1 // ESTABLISHED → 连接建立
	FlowUpdate  FlowLifecycle = 2 // 中间状态变化（重传、零窗口、字节采样）
	FlowDestroy FlowLifecycle = 3 // TCP_CLOSE → 连接终止
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

// ── 事件子类型（Update 的触发原因） ─────────────────────

type EventSubtype uint8

const (
	SubtypeNone       EventSubtype = 0
	SubtypeRetrans    EventSubtype = 1
	SubtypeZeroWnd    EventSubtype = 2
	SubtypeBytesFlush EventSubtype = 3 // 字节阈值采样触发
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

// ── 连接 role ─────────────────────────────────────────────

type FlowRole uint8

const (
	RoleUnknown FlowRole = 0
	RoleClient  FlowRole = 1 // 主动发起连接（tcp_connect）
	RoleServer  FlowRole = 2 // 被动接受连接（listen/accept）
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

// ── 统一 FlowKey ─────────────────────────────────────────
// 所有 Map、Cache 使用同一 key 类型，避免 string 拼接开销。
// 方向统一为 client→server（SrcIP:SrcPort = 低端口侧）。

type FlowKey struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
	Proto   uint8
	_       [3]byte // padding，保证结构体可比较且对齐
}

// NewFlowKey 从事件字段构造 FlowKey。
// 方向规范化：始终以 client 侧（role=CLIENT 或 SrcPort > DstPort）为 Src。
func NewFlowKey(saddr, daddr uint32, sport, dport uint16, proto uint8, role FlowRole) FlowKey {
	if role == RoleServer {
		// 服务端视角：sport 是服务端口（低），翻转为 client→server
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

// ── TCPEvent：与 BPF struct tcp_event 精确对齐（152 bytes）──
//
// 字段偏移注释与 tcp_tracer.c 中的注释保持一致。

type TCPEvent struct {
	// [0:8]
	TimestampNs uint64
	// [8:12]
	PID uint32
	// [12:16]
	TID uint32
	// [16:32]
	Comm [16]byte

	// 五元组 [32:44]
	SAddr    uint32 // [32:36]
	DAddr    uint32 // [36:40]
	SPort    uint16 // [40:42]
	DPort    uint16 // [42:44]
	Protocol uint8  // [44]

	// 状态 [45:48]
	Lifecycle     uint8 // [45] FlowLifecycle
	Direction     uint8 // [46]
	Role          uint8 // [47] FlowRole

	// SYN RTT [48:60] μs
	SynRTT       uint32 // [48:52]
	SynRTTClient uint32 // [52:56]
	SynRTTServer uint32 // [56:60]

	// Data RTT [60:80] μs
	RTTMean uint32 // [60:64]
	RTTMax  uint32 // [64:68]
	RTTMin  uint32 // [68:72]

	// SRT [72:80]
	SRTMean uint32 // [72:76]
	SRTMax  uint32 // [76:80]

	// 重传 [80:96]
	RetransCount  uint32 // [80:84]
	EventSubtype  uint8  // [84]
	DestroyReason uint8  // [85]
	SynRetrans    uint8  // [86]
	RSTCount      uint8  // [87]
	RetransBytes  uint64 // [88:96]

	// 零窗口 [96:112]
	ZeroWndCount    uint32 // [96:100]
	_               uint32 // [100:104] pad
	ZeroWndDuration uint64 // [104:112]

	// 流量 [112:144]
	BytesSent       uint64 // [112:120]
	BytesReceived   uint64 // [120:128]
	PacketsSent     uint64 // [128:136]
	PacketsReceived uint64 // [136:144]

	// 状态标志 [144:152]
	TimeoutFlag uint8  // [144]
	TCPState    uint8  // [145]
	_           uint16 // [146:148] pad
	DurationUs  uint32 // [148:152]
}

// ── UDPFlowEvent：与 BPF struct udp_flow_event 精确对齐（88 bytes）─
//
// BPF 侧已完成 FlowKey 规范化（client→server 方向）：
//   SAddr/SPort = client 侧（即使是 server 端收包也翻转了）
//   Role 字段告知本端身份（1=client 2=server）
//
// 字段偏移与 bpf/udp_tracer.c struct udp_flow_event 完全一致：
//   [0:8]   TimestampNs
//   [8:12]  PID
//   [12:16] TID
//   [16:32] Comm[16]
//   [32:36] SAddr        规范化 client IP
//   [36:40] DAddr        规范化 server IP
//   [40:42] SPort        规范化 client port
//   [42:44] DPort        规范化 server port
//   [44]    Direction    本端视角 0=ingress 1=egress
//   [45]    Role         1=client 2=server
//   [46]    EventType    1=NEW 2=UPDATE
//   [47]    _pad
//   [48:52] PacketSize   本次包大小（真实值）
//   [52:56] _pad2
//   [56:64] TotalBytes   bytes_sent + bytes_recv
//   [64:72] BytesSent    累积发送字节
//   [72:80] BytesRecv    累积接收字节
//   [80:88] DurationNs   自 first_ts 起的持续时间

// UDPEventType UDP 流事件类型
type UDPEventType uint8

const (
	UDPFlowNew    UDPEventType = 1 // 首次看到该五元组
	UDPFlowUpdate UDPEventType = 2 // 字节采样阈值触发的快照
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

// UDPFlowEvent BPF ring buffer 事件（对应 struct udp_flow_event，88 bytes）
// UDPEvent 为后向兼容别名
type UDPFlowEvent struct {
	TimestampNs uint64
	PID         uint32
	TID         uint32
	Comm        [16]byte
	SAddr       uint32   // 规范化：client IP
	DAddr       uint32   // 规范化：server IP
	SPort       uint16   // 规范化：client port
	DPort       uint16   // 规范化：server port
	Direction   uint8    // 本端视角：0=ingress 1=egress
	Role        uint8    // 1=client 2=server
	EventType   uint8    // 1=NEW 2=UPDATE
	_           uint8    // pad
	PacketSize  uint32   // 本次包大小（真实值）
	_           uint32   // pad2
	TotalBytes  uint64   // 累积 tx+rx
	BytesSent   uint64   // 累积发送字节
	BytesRecv   uint64   // 累积接收字节
	DurationNs  uint64   // 持续时间（ns）
}

// UDPEvent 后向兼容别名
type UDPEvent = UDPFlowEvent

// UDPFlow 用户态 UDP 流聚合对象
type UDPFlow struct {
	Key FlowKey

	// 身份
	SrcIP       string // client IP
	DstIP       string // server IP
	SrcPort     uint16 // client port
	DstPort     uint16 // server port
	Role        FlowRole
	ProcessName string
	PID         uint32

	// 时间
	StartTime time.Time
	LastSeen  time.Time
	Duration  time.Duration

	// 流量（双向累积）
	BytesSent uint64
	BytesRecv uint64
	PktsSent  uint64
	PktsRecv  uint64

	// 云标签（*cloudmeta.CloudTag，interface{} 避免循环依赖）
	CloudTag interface{}
}

// ── L7 载荷事件（uprobe/sk_msg 抓取应用层数据）────────────
// BPF 侧抓到的原始应用层数据，交给 L7 解析器识别协议
type L7Event struct {
	TimestampNs  uint64
	PID          uint32
	TID          uint32
	Comm         [16]byte
	SAddr        uint32
	DAddr        uint32
	SPort        uint16
	DPort        uint16
	Protocol     uint8  // TCP=6 UDP=17
	Direction    uint8  // 0=ingress 1=egress
	PayloadSize  uint32 // 实际载荷字节数（可能被截断）
	Payload      [4096]byte
}

// L7Protocol 应用层协议枚举
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
	L7ProtocolCustom  L7Protocol = 100 // WASM 插件扩展
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
	case L7ProtocolCustom:
		return "Custom"
	default:
		return "Unknown"
	}
}

// L7RequestType 请求类型
type L7RequestType uint8

const (
	L7RequestTypeRequest  L7RequestType = 1
	L7RequestTypeResponse L7RequestType = 2
	L7RequestTypeSession  L7RequestType = 3 // DNS等一问一答聚合
)

// ── TCPacket：与 BPF struct tc_packet 对齐 ───────────────

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
	_           uint8
	PacketLen   uint32
	IPHeaderLen uint32
	IPTTL       uint8
	IPTOS       uint8
	IPID        uint16
}

// ── Flow：用户态全量状态对象 ─────────────────────────────
// 所有指标都挂在 Flow 上，是 DeepFlow 流数据模型的对应。

type Flow struct {
	// 唯一键
	Key FlowKey

	// 身份
	SrcIP       string
	DstIP       string
	SrcPort     uint16
	DstPort     uint16
	Protocol    string
	Role        FlowRole   // CLIENT 或 SERVER
	ProcessName string
	PID         uint32

	// 生命周期
	Lifecycle     FlowLifecycle
	DestroyReason DestroyReason
	TCPState      string

	// 时间
	StartTime   time.Time
	EndTime     time.Time
	Duration    time.Duration
	LastSeen    time.Time

	// ── 建连质量（SYN RTT，三段） ─────────────────
	// SynRTT = 完整建连时延（SYN → 最终ACK）
	// SynRTTServer = 服务端处理时延（SYN → SYN+ACK）
	// SynRTTClient = 客户端回 ACK 时延（SYN+ACK → ACK）
	SynRTT       time.Duration
	SynRTTServer time.Duration
	SynRTTClient time.Duration

	// ── 数据传输时延（RTT min/avg/max） ───────────
	RTTMin  time.Duration
	RTTMean time.Duration
	RTTMax  time.Duration

	// ── 系统响应时延 ──────────────────────────────
	SRTMean time.Duration
	SRTMax  time.Duration

	// ── 吞吐 ──────────────────────────────────────
	BytesSent       uint64
	BytesReceived   uint64
	PacketsSent     uint64
	PacketsReceived uint64

	// ── 重传 ──────────────────────────────────────
	RetransCount uint32
	RetransBytes uint64
	RetransRatio float64

	// ── 零窗口 ────────────────────────────────────
	ZeroWndCount    uint32
	ZeroWndDuration time.Duration

	// ── 异常 ──────────────────────────────────────
	SynRetransCount uint8
	RSTCount        uint8
	TimeoutOccurred bool

	// CloudTag is injected by cloudmeta provider (interface{} avoids import cycle)
	CloudTag interface{} // *cloudmeta.CloudTag
}

// CloudTag on Flow is set by cloudmeta provider (interface{} to avoid import cycle)
// Actual type: *cloudmeta.CloudTag
