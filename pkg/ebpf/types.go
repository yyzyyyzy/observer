// pkg/ebpf/types.go
package ebpf

import "time"

// 事件类型常量（与 tcp_tracer.c 的 EVENT_* 宏一一对应）
const (
	EventTypeConnect   = 1 // EVENT_FLOW_START：连接进入 ESTABLISHED
	EventTypeAccept    = 1 // 服务端也通过 ESTABLISHED 状态识别，复用同一值
	EventTypeClose     = 2 // EVENT_FLOW_END：连接进入 TCP_CLOSE
	EventTypeRetrans   = 3 // EVENT_RETRANS
	EventTypeZeroWnd   = 4 // EVENT_ZERO_WND
	EventTypeRST       = 5 // EVENT_RST

	// 向后兼容别名
	EventTypeFlowStart = 1
	EventTypeFlowEnd   = 2
)

// 流方向常量
const (
	FlowDirectionIngress = 0
	FlowDirectionEgress  = 1
)

// 协议类型常量
const (
	ProtocolTCP = 6
	ProtocolUDP = 17
)

// TCP 状态常量
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

// TCPEvent 增强的 TCP 事件（与 eBPF 结构体对应）
type TCPEvent struct {
	TimestampNs uint64
	PID         uint32
	TID         uint32
	Comm        [16]byte

	// 五元组
	SAddr    uint32
	DAddr    uint32
	SPort    uint16
	DPort    uint16
	Protocol uint8

	// 事件类型和方向
	EventType uint8
	Direction uint8

	// 建连时延（微秒）
	SynRTT       uint32
	SynRTTClient uint32
	SynRTTServer uint32

	// 数据传输时延（微秒）
	RTTMean uint32
	RTTMax  uint32
	RTTMin  uint32

	// 系统时延（微秒）
	SRTMean uint32
	SRTMax  uint32

	// 重传统计
	RetransCount uint32
	RetransBytes uint64

	// 零窗口统计
	ZeroWndCount    uint32
	ZeroWndDuration uint64

	// 流量统计
	BytesSent       uint64
	BytesReceived   uint64
	PacketsSent     uint64
	PacketsReceived uint64

	// 异常标志
	SynRetrans  uint8
	RSTCount    uint8
	TimeoutFlag uint8

	// TCP 状态
	TCPState uint8

	// 连接时长
	DurationNs uint32
}

// UDPEvent UDP 事件
type UDPEvent struct {
	TimestampNs uint64
	PID         uint32
	TID         uint32
	Comm        [16]byte
	SAddr       uint32
	DAddr       uint32
	SPort       uint16
	DPort       uint16
	Direction   uint8
	_           [3]byte // padding
	PacketSize  uint32
	TotalBytes  uint64
}

// TCPacket TC 数据包
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
	_           uint8 // padding
	PacketLen   uint32
}

// FlowInfo 流信息（应用层使用）
type FlowInfo struct {
	// 基本信息
	SrcIP       string
	DstIP       string
	SrcPort     uint16
	DstPort     uint16
	Protocol    string
	Direction   string
	ProcessName string
	PID         uint32

	// 基础流量统计
	BytesSent       uint64
	BytesReceived   uint64
	PacketsSent     uint64
	PacketsReceived uint64

	// 时间信息
	StartTime time.Time
	EndTime   time.Time
	Duration  time.Duration

	// 建连时延
	SynRTT       time.Duration
	SynRTTClient time.Duration
	SynRTTServer time.Duration

	// 数据传输时延
	RTTMean time.Duration
	RTTMax  time.Duration
	RTTMin  time.Duration
	SRTMean time.Duration
	SRTMax  time.Duration

	// 性能指标
	RetransCount    uint32
	RetransBytes    uint64
	RetransRatio    float64
	ZeroWndCount    uint32
	ZeroWndDuration time.Duration

	// 异常标志
	SynRetransCount uint8
	EstablishFail   bool
	QueueOverflow   bool
	RSTCount        uint8
	TimeoutOccurred bool
	HalfCloseLack   bool

	// TCP 状态
	TCPState string
}

// TCPStateNames TCP 状态名称映射
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

// GetTCPStateName 获取 TCP 状态名称
func GetTCPStateName(state uint8) string {
	if name, ok := TCPStateNames[state]; ok {
		return name
	}
	return "UNKNOWN"
}
