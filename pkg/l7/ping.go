// pkg/l7/ping.go
// Ping（ICMP Echo）协议解析器。
//
// ICMP 帧格式（IPv4，通过 raw socket 或 TC hook 捕获）：
//   [0]    Type（8=Echo Request 0=Echo Reply）
//   [1]    Code（通常为 0）
//   [2:4]  Checksum
//   [4:6]  Identifier（ping 进程标识）
//   [6:8]  Sequence Number（递增序列号）
//   [8:]   Data（可选，填充数据）
//
// 注意：eBPF 通常在 IP 层以上抓包，payload 可能从 ICMP 头部开始。
// 本解析器仅用于 TC hook 或 raw socket 捕获的 ICMP 报文，
// 对于 TCP/UDP L7 tracer 捕获的数据不会触发（protocol=1 不在追踪范围）。

package l7

import (
	"encoding/binary"
	"time"

	"observer/pkg/ebpf"
)

const (
	icmpTypeEchoReply   = 0
	icmpTypeEchoRequest = 8
)

// PingParser ICMP Echo Request/Reply 解析器，用于追踪 Ping 操作的 RTT。
// 通过 Identifier + Sequence Number 配对请求和响应计算 RTT。
type PingParser struct{}

func NewPingParser() *PingParser { return &PingParser{} }

func (p *PingParser) Protocol() ebpf.L7Protocol { return ebpf.L7ProtocolPing }

func (p *PingParser) CanParse(payload []byte, srcPort, dstPort uint16) bool {
	if len(payload) < 8 {
		return false
	}
	icmpType := payload[0]
	icmpCode := payload[1]
	// ICMP Echo Request 或 Reply，Code=0
	return (icmpType == icmpTypeEchoRequest || icmpType == icmpTypeEchoReply) && icmpCode == 0
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

		ResponseStatus: 0,
		RequestType:    "Echo",
	}

	switch icmpType {
	case icmpTypeEchoRequest:
		result.ReqType = ebpf.L7RequestTypeRequest
		result.RequestResource = "ping"
	case icmpTypeEchoReply:
		result.ReqType = ebpf.L7RequestTypeResponse
		result.RequestResource = "pong"
		// RTT 由请求/响应配对后在 Registry.emitL7Log 计算
	default:
		return nil
	}

	return result
}
