// pkg/l7/dns.go
// DNS 协议解析器（RFC 1035 / RFC 3596 AAAA / RFC 6891 EDNS0）
//
// ── DNS 消息格式 ──────────────────────────────────────────────────────────────
//
//   ┌────────────────────────────────────────────┐
//   │  ID         (16 bit)                       │  偏移 0
//   │  Flags      (16 bit)                       │  偏移 2
//   │    QR(1) OPCODE(4) AA(1) TC(1) RD(1)       │
//   │    RA(1) Z(3) RCODE(4)                     │
//   │  QDCOUNT    (16 bit)                       │  偏移 4
//   │  ANCOUNT    (16 bit)                       │  偏移 6
//   │  NSCOUNT    (16 bit)                       │  偏移 8
//   │  ARCOUNT    (16 bit)                       │  偏移 10
//   ├────────────────────────────────────────────┤
//   │  Questions  (QDCOUNT 条)                   │
//   │  Answers    (ANCOUNT 条)                   │
//   │  Authority  (NSCOUNT 条)                   │
//   │  Additional (ARCOUNT 条)                   │
//   └────────────────────────────────────────────┘
//
//   域名压缩指针：高 2 位为 0b11（0xC0）时为压缩指针，低 14 位为目标偏移。
//
// ── 资源记录（RR）格式 ───────────────────────────────────────────────────────
//
//   NAME (variable) | TYPE (2) | CLASS (2) | TTL (4) | RDLENGTH (2) | RDATA
//
// ── 协议识别策略 ─────────────────────────────────────────────────────────────
//
//   CanParse：端口 53（UDP/TCP），最强特征，直接返回 true。
//   Parse：校验头部 12 字节存在，OPCODE ∈ [0,5]，RCODE ∈ [0,23]。

package l7

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"observer/pkg/ebpf"
)

// ── DNS Flags 位域常量 ────────────────────────────────────────────────────────

const (
	dnsQR       = 0x8000 // Query(0) / Response(1)
	dnsOpMask   = 0x7800 // OPCODE [14:11]
	dnsOpShift  = 11
	dnsTCMask   = 0x0200 // Truncated
	dnsRCodeMask = 0x000F // RCODE [3:0]
)

// DNS 查询类型常量
const (
	dnsTypeA    = 1
	dnsTypeNS   = 2
	dnsTypeCNAME = 5
	dnsTypeSOA  = 6
	dnsTypePTR  = 12
	dnsTypeMX   = 15
	dnsTypeTXT  = 16
	dnsTypeAAAA = 28
	dnsTypeSRV  = 33
	dnsTypeAny  = 255
)

var dnsTypeNames = map[uint16]string{
	dnsTypeA:    "A",
	dnsTypeNS:   "NS",
	dnsTypeCNAME: "CNAME",
	dnsTypeSOA:  "SOA",
	dnsTypePTR:  "PTR",
	dnsTypeMX:   "MX",
	dnsTypeTXT:  "TXT",
	dnsTypeAAAA: "AAAA",
	dnsTypeSRV:  "SRV",
	dnsTypeAny:  "ANY",
}

var dnsRCodeNames = map[uint16]string{
	0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL",
	3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
	6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET",
	9: "NOTAUTH", 10: "NOTZONE",
}

// DNSParser DNS 协议解析器（UDP/TCP port=53）。
type DNSParser struct{}

func NewDNSParser() *DNSParser { return &DNSParser{} }

func (p *DNSParser) Protocol() ebpf.L7Protocol { return ebpf.L7ProtocolDNS }

// CanParse 仅凭端口判断（DNS 端口 53 是强特征，不需要检查 payload）。
// TCP DNS 报文前 2 字节是长度前缀，UDP DNS 无长度前缀，两种情况均可靠通过端口识别。
func (p *DNSParser) CanParse(payload []byte, srcPort, dstPort uint16) bool {
	return srcPort == 53 || dstPort == 53
}

func (p *DNSParser) Parse(payload []byte, direction uint8, ts time.Time) *ParseResult {
	// TCP DNS 报文：前 2 字节为长度前缀，跳过后解析
	data := payload
	if len(data) >= 2 {
		tcpLen := binary.BigEndian.Uint16(data[0:2])
		if int(tcpLen) == len(data)-2 && len(data) > 14 {
			data = data[2:] // TCP DNS
		}
	}

	msg, err := parseDNSMessage(data)
	if err != nil {
		return nil
	}

	result := &ParseResult{
		Protocol:        ebpf.L7ProtocolDNS,
		ReqType:         ebpf.L7RequestTypeSession,
		StartTime:       ts,
		EndTime:         ts,
		DNSQueryName:    msg.queryName,
		DNSQueryType:    msg.queryType,
		DNSRCode:        msg.rcode,
		RequestResource: msg.queryName,
		RequestType:     dnsTypeName(msg.queryType),
	}

	if msg.isResponse {
		result.DNSAnswerIP = msg.answerIP
		if msg.rcode != 0 {
			result.ResponseStatus = 1 // DNS 错误归为 client_error（NXDOMAIN 等）
			result.ResponseCode = int64(msg.rcode)
			result.ResponseErrMsg = dnsRCodeName(msg.rcode)
		} else {
			result.ResponseStatus = 0
		}
	}

	return result
}

// ── DNS 消息解析 ──────────────────────────────────────────────────────────────

type dnsMessage struct {
	isResponse bool
	queryName  string
	queryType  uint16
	rcode      uint16
	answerIP   string
}

func parseDNSMessage(data []byte) (*dnsMessage, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("dns: header too short (%d bytes)", len(data))
	}

	flags := binary.BigEndian.Uint16(data[2:4])
	opcode := (flags & dnsOpMask) >> dnsOpShift
	rcode := flags & dnsRCodeMask
	qdCount := binary.BigEndian.Uint16(data[4:6])
	anCount := binary.BigEndian.Uint16(data[6:8])

	// 基本合法性校验
	if opcode > 5 {
		return nil, fmt.Errorf("dns: invalid opcode %d", opcode)
	}
	if rcode > 23 {
		return nil, fmt.Errorf("dns: invalid rcode %d", rcode)
	}

	msg := &dnsMessage{
		isResponse: flags&dnsQR != 0,
		rcode:      rcode,
	}

	offset := 12
	// 解析 Question section
	for i := 0; i < int(qdCount) && offset < len(data); i++ {
		name, newOff, err := parseDNSName(data, offset)
		if err != nil {
			break
		}
		msg.queryName = name
		offset = newOff
		if offset+4 <= len(data) {
			msg.queryType = binary.BigEndian.Uint16(data[offset : offset+2])
			offset += 4 // QTYPE(2) + QCLASS(2)
		}
	}

	// 解析 Answer section（仅提取第一条 A/AAAA 记录）
	if msg.isResponse && anCount > 0 {
		for i := 0; i < int(anCount) && offset < len(data); i++ {
			_, newOff, err := parseDNSName(data, offset)
			if err != nil {
				break
			}
			offset = newOff
			if offset+10 > len(data) {
				break
			}
			rrType := binary.BigEndian.Uint16(data[offset : offset+2])
			rdLen := binary.BigEndian.Uint16(data[offset+8 : offset+10])
			offset += 10
			if offset+int(rdLen) > len(data) {
				break
			}
			rdata := data[offset : offset+int(rdLen)]
			offset += int(rdLen)

			switch rrType {
			case dnsTypeA:
				if len(rdata) == 4 {
					msg.answerIP = net.IP(rdata).String()
				}
			case dnsTypeAAAA:
				if len(rdata) == 16 {
					msg.answerIP = net.IP(rdata).String()
				}
			}
			if msg.answerIP != "" {
				break
			}
		}
	}

	return msg, nil
}

// parseDNSName 解析 DNS 域名（支持 RFC 1035 §4.1.4 指针压缩）。
// 返回：域名字符串、解析后的偏移量（不包括通过指针跳转的部分）。
func parseDNSName(data []byte, offset int) (string, int, error) {
	var labels []string
	visited := make(map[int]bool)
	origOffset := -1 // 记录第一个指针跳转前的位置

	for {
		if offset >= len(data) {
			return "", offset, fmt.Errorf("dns: name parse out of bounds")
		}
		if visited[offset] {
			return "", offset, fmt.Errorf("dns: name pointer loop")
		}
		visited[offset] = true

		b := data[offset]
		if b == 0 {
			// 域名终止符
			offset++
			break
		}

		if b&0xC0 == 0xC0 {
			// 压缩指针（高 2 位为 0b11）
			if offset+1 >= len(data) {
				return "", offset, fmt.Errorf("dns: truncated pointer")
			}
			if origOffset < 0 {
				origOffset = offset + 2 // 保存指针后的偏移
			}
			ptr := int(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3FFF)
			if ptr >= offset {
				return "", offset, fmt.Errorf("dns: forward pointer not allowed")
			}
			offset = ptr
			continue
		}

		// 普通 label
		labelLen := int(b)
		offset++
		if offset+labelLen > len(data) {
			return "", offset, fmt.Errorf("dns: label out of bounds")
		}
		labels = append(labels, string(data[offset:offset+labelLen]))
		offset += labelLen
	}

	if origOffset >= 0 {
		offset = origOffset // 返回指针之后的位置
	}
	return strings.Join(labels, "."), offset, nil
}

func dnsTypeName(t uint16) string {
	if name, ok := dnsTypeNames[t]; ok {
		return name
	}
	return fmt.Sprintf("TYPE%d", t)
}

func dnsRCodeName(rcode uint16) string {
	if name, ok := dnsRCodeNames[rcode]; ok {
		return name
	}
	return fmt.Sprintf("RCODE%d", rcode)
}
