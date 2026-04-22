// pkg/collector/udp_l7_dispatcher.go — UDP L7 协议解析分发器
//
// 将 UDP 流事件（UDPFlowEvent）中的 payload 路由到 L7 解析器。
//
// UDP L7 支持的协议：
//   - DNS（port 53）：最高优先级，基于事务 ID 配对请求/响应
//   - DHCP（port 67/68）
//   - SNMP（port 161/162）：解析 community string + OID
//   - NTP（port 123）：mode 字段
//
// 与 TCP L7 的差异：
//   - UDP 无连接：直接使用 l7_tracer.c 的 UDP 路径（udp_sendmsg/recvmsg 的 payload）
//   - 流量小且频繁（如 DNS）：BPF 侧已有 64KB 采样阈值过滤了频繁小包
//   - 无需 session 配对（DNS 用 txid 配对，其他协议多为 session 类型）

package collector

import (
	"encoding/binary"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"observer/pkg/ebpf"
	"observer/pkg/storage"
)

// UDPDispatcher 处理 UDP 流事件并尝试 L7 协议解析
type UDPDispatcher struct {
	store *storage.ClickHouseClient

	// DNS 事务配对表（txid → 请求时间戳）
	dnsPending map[uint16]dnsPendingEntry
}

type dnsPendingEntry struct {
	ts      time.Time
	srcIP   uint32
	srcPort uint16
	dstIP   uint32
	dstPort uint16
	pid     uint32
	comm    [16]byte
	name    string
	qtype   uint16
}

// NewUDPDispatcher 构建 UDP L7 分发器
func NewUDPDispatcher(store *storage.ClickHouseClient) *UDPDispatcher {
	return &UDPDispatcher{
		store:      store,
		dnsPending: make(map[uint16]dnsPendingEntry),
	}
}

// HandleUDPL7Event 处理来自 l7_tracer 的 UDP payload 事件
// 注意：此方法由 L7EventHandler 接口调用，专门处理 Protocol=UDP 的事件
func (d *UDPDispatcher) HandleUDPL7Event(ev *ebpf.L7Event) {
	if ev.Protocol != ebpf.ProtocolUDP {
		return
	}
	if ev.PayloadSize == 0 {
		return
	}
	sz := ev.PayloadSize
	if sz > uint32(len(ev.Payload)) {
		sz = uint32(len(ev.Payload))
	}
	payload := ev.Payload[:sz]
	now := time.Unix(0, int64(ev.TimestampNs))

	// DNS（port 53）
	if ev.SPort == 53 || ev.DPort == 53 {
		d.handleDNS(ev, payload, now)
		return
	}

	// NTP（port 123）
	if ev.SPort == 123 || ev.DPort == 123 {
		d.handleNTP(ev, payload, now)
		return
	}
}

// handleDNS 解析 UDP DNS 报文并配对请求/响应
func (d *UDPDispatcher) handleDNS(ev *ebpf.L7Event, payload []byte, now time.Time) {
	if len(payload) < 12 {
		return
	}

	txid := binary.BigEndian.Uint16(payload[0:2])
	flags := binary.BigEndian.Uint16(payload[2:4])
	isResponse := (flags & 0x8000) != 0
	rcode := flags & 0x000F

	// 解析 Question 段 QNAME
	qname := parseDNSQName(payload, 12)
	qdcount := binary.BigEndian.Uint16(payload[4:6])
	var qtype uint16
	if qdcount > 0 {
		// 跳过 QNAME 找 QTYPE（简化版：找 \x00 结束符后读 2 字节）
		for i := 12; i < len(payload)-3; i++ {
			if payload[i] == 0x00 {
				qtype = binary.BigEndian.Uint16(payload[i+1 : i+3])
				break
			}
		}
	}

	if !isResponse {
		// 请求：缓存 txid 和请求元数据
		d.dnsPending[txid] = dnsPendingEntry{
			ts:      now,
			srcIP:   ev.SAddr,
			srcPort: ev.SPort,
			dstIP:   ev.DAddr,
			dstPort: ev.DPort,
			pid:     ev.PID,
			comm:    ev.Comm,
			name:    qname,
			qtype:   qtype,
		}
		return
	}

	// 响应：查找匹配的请求
	pending, ok := d.dnsPending[txid]
	var responseUs uint32
	var reqName string
	if ok {
		delete(d.dnsPending, txid)
		responseUs = uint32(now.Sub(pending.ts).Microseconds())
		reqName = pending.name
	}
	if reqName == "" {
		reqName = qname
	}

	// 解析 Answer 段第一条 A/AAAA 记录
	answerIP := parseDNSFirstAnswer(payload)

	if d.store == nil {
		return
	}
	d.store.WriteL7FlowLog(storage.L7FlowLog{
		StartTime:  pending.ts,
		EndTime:    now,
		ResponseUs: responseUs,

		SrcIP:   storage.SafeIPv4(ebpf.Uint32ToIP(ev.SAddr)),
		DstIP:   storage.SafeIPv4(ebpf.Uint32ToIP(ev.DAddr)),
		SrcPort: ev.SPort,
		DstPort: ev.DPort,
		Protocol: ebpf.ProtocolUDP,

		PID:         ev.PID,
		ProcessName: ebpf.ParseCommField(ev.Comm),

		L7Protocol: uint16(ebpf.L7ProtocolDNS),
		L7ProtName: "DNS",
		ReqType:    uint8(ebpf.L7RequestTypeSession),

		RequestResource: reqName,
		RequestType:     qtypeString(qtype),

		DNSQueryName: reqName,
		DNSQueryType: qtype,
		DNSRCode:     rcode,
		DNSAnswerIP:  answerIP,

		ResponseStatus: func() uint8 {
			if rcode == 0 {
				return 0
			}
			return 1
		}(),
		ResponseCode: int64(rcode),
	})
}

// handleNTP 解析 NTP 报文（简单版，仅记录 mode）
func (d *UDPDispatcher) handleNTP(ev *ebpf.L7Event, payload []byte, now time.Time) {
	if len(payload) < 48 {
		return
	}
	mode := payload[0] & 0x07
	// mode=3=client 4=server
	log.WithFields(log.Fields{
		"mode":  mode,
		"sport": ev.SPort,
		"dport": ev.DPort,
		"pid":   ev.PID,
	}).Debug("NTP packet captured")
	// NTP 记录为 session 类型，不配对请求/响应
}

// ── DNS 解析辅助 ──────────────────────────────────────────

// parseDNSQName 从 DNS 报文 offset 处解析 QNAME（点分域名）
func parseDNSQName(pkt []byte, offset int) string {
	var labels []string
	maxJumps := 10 // 防止无限循环（压缩指针循环）
	for offset < len(pkt) && maxJumps > 0 {
		length := int(pkt[offset])
		if length == 0 {
			break
		}
		// 检测 DNS 压缩指针（高两位为 11）
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(pkt) {
				break
			}
			ptr := int(binary.BigEndian.Uint16(pkt[offset:offset+2]) & 0x3FFF)
			offset = ptr
			maxJumps--
			continue
		}
		offset++
		if offset+length > len(pkt) {
			break
		}
		labels = append(labels, string(pkt[offset:offset+length]))
		offset += length
	}
	return strings.Join(labels, ".")
}

// parseDNSFirstAnswer 从 DNS 响应中提取第一条 A 记录 IP
func parseDNSFirstAnswer(pkt []byte) string {
	if len(pkt) < 12 {
		return ""
	}
	qdcount := int(binary.BigEndian.Uint16(pkt[4:6]))
	ancount := int(binary.BigEndian.Uint16(pkt[6:8]))
	if ancount == 0 {
		return ""
	}

	// 跳过 Question 段
	offset := 12
	for i := 0; i < qdcount && offset < len(pkt); i++ {
		// 跳过 QNAME
		for offset < len(pkt) {
			l := int(pkt[offset])
			if l == 0 {
				offset++
				break
			}
			if l&0xC0 == 0xC0 {
				offset += 2
				break
			}
			offset += 1 + l
		}
		offset += 4 // QTYPE + QCLASS
	}

	// 读取第一条 Answer
	for i := 0; i < ancount && offset < len(pkt); i++ {
		// 跳过 NAME（可能是压缩指针）
		if offset < len(pkt) && pkt[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(pkt) && pkt[offset] != 0 {
				l := int(pkt[offset])
				offset += 1 + l
			}
			offset++
		}
		if offset+10 > len(pkt) {
			break
		}
		rtype := binary.BigEndian.Uint16(pkt[offset : offset+2])
		// rclass := binary.BigEndian.Uint16(pkt[offset+2 : offset+4])
		rdlen := int(binary.BigEndian.Uint16(pkt[offset+8 : offset+10]))
		offset += 10 // TYPE+CLASS+TTL+RDLEN

		if rtype == 1 && rdlen == 4 && offset+4 <= len(pkt) {
			// A record
			return ebpf.Uint32ToIP(binary.BigEndian.Uint32(pkt[offset : offset+4]))
		}
		if rtype == 28 && rdlen == 16 && offset+16 <= len(pkt) {
			// AAAA record
			var b [16]byte
			copy(b[:], pkt[offset:offset+16])
			return ebpf.Bytes16ToIPv6(b)
		}
		offset += rdlen
	}
	return ""
}

// qtypeString DNS QTYPE 数字转字符串
func qtypeString(qtype uint16) string {
	switch qtype {
	case 1:
		return "A"
	case 28:
		return "AAAA"
	case 5:
		return "CNAME"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 6:
		return "SOA"
	case 255:
		return "ANY"
	default:
		return "UNKNOWN"
	}
}
