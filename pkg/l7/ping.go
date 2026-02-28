// pkg/l7/ping.go
// ICMP Echo（Ping）协议解析器
//
// ── ICMP 报文格式（IPv4，RFC 792）────────────────────────────────────────────
//
//   ┌────────────────────────────────────────────────┐
//   │  Type     (1 B)  8=Echo Request  0=Echo Reply  │
//   │  Code     (1 B)  始终为 0                       │
//   │  Checksum (2 B)  校验和                         │
//   │  ID       (2 B)  标识符（ping 进程 PID）        │
//   │  Sequence (2 B)  序列号（递增）                 │
//   │  Data     (N B)  填充数据（可选）               │
//   └────────────────────────────────────────────────┘
//
// ── ICMPv6 报文格式（RFC 4443）───────────────────────────────────────────────
//
//   Echo Request: Type=128  Echo Reply: Type=129（格式同 ICMPv4 Echo）
//
// ── 采集路径 ─────────────────────────────────────────────────────────────────
//
//   ICMP 不经过 tcp_sendmsg/recvmsg，不会出现在 L7 TCP tracer 中。
//   eBPF TC hook 在网卡 ingress/egress 捕获 IP 层报文，
//   由 tc_tracer.c 识别 protocol=1（ICMP）/58（ICMPv6）并上报。
//   PingParser 对上报的 ICMP payload（不含 IP 头）进行解析。
//
// ── RTT 计算 ─────────────────────────────────────────────────────────────────
//
//   Registry 以 (ID, Sequence) 为 key 配对 Request 和 Reply，
//   计算 ResponseUs = Reply.ts - Request.ts。
//   PingParser 自身不计算 RTT，仅提取 ID/Seq。

package l7

import (
	"encoding/binary"
	"time"

	"observer/pkg/ebpf"
)

// ICMP / ICMPv6 Echo 类型常量
const (
	icmpv4EchoRequest uint8 = 8
	icmpv4EchoReply   uint8 = 0
	icmpv6EchoRequest uint8 = 128
	icmpv6EchoReply   uint8 = 129
)

// PingParser ICMP / ICMPv6 Echo Request/Reply 解析器。
// 通过 Identifier + Sequence Number 配对，由 Registry 计算 RTT。
type PingParser struct{}

func NewPingParser() *PingParser { return &PingParser{} }

func (p *PingParser) Protocol() ebpf.L7Protocol { return ebpf.L7ProtocolPing }

// CanParse 识别 ICMPv4 Echo 和 ICMPv6 Echo。
// ICMP Code 必须为 0（非 0 表示错误消息，不是 Echo）。
func (p *PingParser) CanParse(payload []byte, srcPort, dstPort uint16) bool {
	if len(payload) < 8 {
		return false
	}
	icmpType := payload[0]
	icmpCode := payload[1]
	if icmpCode != 0 {
		return false
	}
	return icmpType == icmpv4EchoRequest || icmpType == icmpv4EchoReply ||
		icmpType == icmpv6EchoRequest || icmpType == icmpv6EchoReply
}

func (p *PingParser) Parse(payload []byte, direction uint8, ts time.Time) *ParseResult {
	if len(payload) < 8 {
		return nil
	}

	icmpType := payload[0]
	icmpCode := payload[1]
	icmpID := binary.BigEndian.Uint16(payload[4:6])
	icmpSeq := binary.BigEndian.Uint16(payload[6:8])

	result := &ParseResult{
		Protocol:  ebpf.L7ProtocolPing,
		StartTime: ts,
		EndTime:   ts,
		ICMPType:  icmpType,
		ICMPCode:  icmpCode,
		ICMPID:    icmpID,
		ICMPSeq:   icmpSeq,
	}

	switch icmpType {
	case icmpv4EchoRequest, icmpv6EchoRequest:
		result.ReqType = ebpf.L7RequestTypeRequest
		result.RequestType = "Echo"
		result.RequestResource = "ping"

	case icmpv4EchoReply, icmpv6EchoReply:
		result.ReqType = ebpf.L7RequestTypeResponse
		result.RequestType = "EchoReply"
		result.RequestResource = "pong"
		result.ResponseStatus = 0

	default:
		return nil
	}

	return result
}
