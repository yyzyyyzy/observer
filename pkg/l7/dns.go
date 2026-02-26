// pkg/l7/dns.go
// DNS 协议解析器（RFC 1035）
package l7

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"observer/pkg/ebpf"
)

// DNS Header flags
const (
	dnsQR     = 0x8000 // Query/Response
	dnsOpMask = 0x7800
	dnsAA     = 0x0400
	dnsTC     = 0x0200
	dnsRD     = 0x0100
	dnsRA     = 0x0080
	dnsRCode  = 0x000F
)

type DNSParser struct{}

func NewDNSParser() *DNSParser { return &DNSParser{} }

func (p *DNSParser) Protocol() ebpf.L7Protocol { return ebpf.L7ProtocolDNS }

func (p *DNSParser) CanParse(payload []byte, srcPort, dstPort uint16) bool {
	return srcPort == 53 || dstPort == 53
}

func (p *DNSParser) Parse(payload []byte, direction uint8, ts time.Time) *ParseResult {
	msg, err := parseDNSMessage(payload)
	if err != nil {
		return nil
	}

	result := &ParseResult{
		Protocol:     ebpf.L7ProtocolDNS,
		ReqType:      ebpf.L7RequestTypeSession,
		StartTime:    ts,
		EndTime:      ts,
		DNSQueryName: msg.queryName,
		DNSQueryType: msg.queryType,
		DNSRCode:     msg.rcode,
	}

	if msg.isResponse {
		result.DNSAnswerIP = msg.answerIP
		if msg.rcode != 0 {
			result.ResponseStatus = 1
			result.ResponseCode = int64(msg.rcode)
			result.ResponseErrMsg = dnsRCodeName(msg.rcode)
		}
	}

	return result
}

type dnsMessage struct {
	isResponse bool
	queryName  string
	queryType  uint16
	rcode      uint16
	answerIP   string
}

func parseDNSMessage(data []byte) (*dnsMessage, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("too short")
	}

	flags := binary.BigEndian.Uint16(data[2:4])
	qdCount := binary.BigEndian.Uint16(data[4:6])
	anCount := binary.BigEndian.Uint16(data[6:8])

	msg := &dnsMessage{
		isResponse: flags&dnsQR != 0,
		rcode:      flags & dnsRCode,
	}

	offset := 12
	// 解析问题节
	for i := 0; i < int(qdCount) && offset < len(data); i++ {
		name, newOffset, err := parseDNSName(data, offset)
		if err != nil {
			break
		}
		msg.queryName = name
		offset = newOffset
		if offset+4 <= len(data) {
			msg.queryType = binary.BigEndian.Uint16(data[offset : offset+2])
			offset += 4
		}
	}

	// 解析回答节（只取第一个 A/AAAA 记录的 IP）
	if msg.isResponse && anCount > 0 {
		for i := 0; i < int(anCount) && offset < len(data); i++ {
			_, newOffset, err := parseDNSName(data, offset)
			if err != nil {
				break
			}
			offset = newOffset
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
			case 1: // A
				if len(rdata) == 4 {
					msg.answerIP = net.IP(rdata).String()
				}
			case 28: // AAAA
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

// parseDNSName 解析 DNS 域名（支持压缩指针）
func parseDNSName(data []byte, offset int) (string, int, error) {
	var labels []string
	visited := make(map[int]bool)

	for {
		if offset >= len(data) {
			return "", offset, fmt.Errorf("out of bounds")
		}
		if visited[offset] {
			return "", offset, fmt.Errorf("loop detected")
		}
		visited[offset] = true

		length := int(data[offset])
		if length == 0 {
			offset++
			break
		}
		// 压缩指针（高2位为11）
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				return "", offset, fmt.Errorf("invalid pointer")
			}
			ptr := int(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3FFF)
			label, _, err := parseDNSName(data, ptr)
			if err != nil {
				return "", offset, err
			}
			labels = append(labels, label)
			offset += 2
			break
		}
		offset++
		if offset+length > len(data) {
			return "", offset, fmt.Errorf("label out of bounds")
		}
		labels = append(labels, string(data[offset:offset+length]))
		offset += length
	}
	return strings.Join(labels, "."), offset, nil
}

func dnsRCodeName(rcode uint16) string {
	switch rcode {
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE_%d", rcode)
	}
}
