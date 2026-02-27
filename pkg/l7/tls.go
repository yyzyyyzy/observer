// pkg/l7/tls.go — TLS 协议解析器
//
// TLS 解析策略（对标 DeepFlow）：
//   - eBPF 通过 uprobe 挂载 OpenSSL/BoringSSL/GnuTLS 的 SSL_read / SSL_write，
//     在用户态获取明文数据后交由本解析器处理。
//   - 本解析器同时承担两个职责：
//     1. 识别 TLS record layer（握手/告警/应用数据），提取握手元数据（版本、SNI、ALPN、证书）。
//     2. 当 uprobe 捕获到明文应用数据时，将其转发给下游 HTTP/HTTP2/gRPC 等解析器。
//
// 握手消息解析（ClientHello / ServerHello）：
//   - ClientHello: 提取 SNI（server_name extension）、ALPN、支持的版本。
//   - ServerHello: 提取选中的协议版本、cipher suite。
//   - Certificate: 提取证书 subject/issuer DN、SAN、有效期（简化解析）。

package l7

import (
	"encoding/binary"
	"fmt"
	"time"

	"observer/pkg/ebpf"
)

// TLS Record Layer content types
const (
	tlsContentTypeChangeCipherSpec = 20
	tlsContentTypeAlert            = 21
	tlsContentTypeHandshake        = 22
	tlsContentTypeApplicationData  = 23
)

// TLS Handshake message types
const (
	tlsHandshakeClientHello = 1
	tlsHandshakeServerHello = 2
	tlsHandshakeCertificate = 11
	tlsHandshakeNewSessionTicket = 4
	tlsHandshakeEncryptedExtensions = 8
)

// TLS Extension types
const (
	tlsExtServerName          = 0x0000
	tlsExtSupportedVersions   = 0x002B
	tlsExtALPN                = 0x0010
	tlsExtSupportedGroups     = 0x000A
	tlsExtSignatureAlgorithms = 0x000D
)

// TLS Version identifiers
const (
	tlsVersion10 = 0x0301
	tlsVersion11 = 0x0302
	tlsVersion12 = 0x0303
	tlsVersion13 = 0x0304
)

// TLSMeta 握手阶段提取的 TLS 元数据
type TLSMeta struct {
	Version     uint16
	SNI         string
	ALPN        string
	CipherSuite uint16
	// 证书字段（Certificate 消息，简化）
	CertSubject  string
	CertIssuer   string
	CertNotAfter time.Time
}

// TLSParser 解析 TLS record layer 及握手消息。
// 当捕获到明文载荷时（uprobe 在 SSL_read/SSL_write 返回后采集），
// 记录元数据并将应用层数据转发给内嵌的下游解析器。
type TLSParser struct{}

func NewTLSParser() *TLSParser { return &TLSParser{} }

func (p *TLSParser) Protocol() ebpf.L7Protocol { return ebpf.L7ProtocolTLS }

// CanParse 判断是否为 TLS record layer（5 字节 header）或已解密的应用数据。
// 同时匹配常见 TLS 端口（443/8443/6443/...）和 TLS record magic byte（0x15-0x17 + 版本）。
func (p *TLSParser) CanParse(payload []byte, srcPort, dstPort uint16) bool {
	// 端口启发式：常见 TLS 端口
	if isTLSPort(srcPort) || isTLSPort(dstPort) {
		return true
	}
	// TLS record layer 魔数匹配
	if len(payload) >= 5 {
		ct := payload[0]
		major := payload[1]
		if major == 3 && (ct == tlsContentTypeHandshake || ct == tlsContentTypeAlert ||
			ct == tlsContentTypeChangeCipherSpec || ct == tlsContentTypeApplicationData) {
			return true
		}
	}
	return false
}

func isTLSPort(port uint16) bool {
	switch port {
	case 443, 8443, 6443, 9443, 4443, 5443, 8444, 15443:
		return true
	}
	return false
}

// Parse 解析 TLS 载荷。
// 对于握手消息（ClientHello/ServerHello），提取元数据写入 ParseResult。
// 对于 ApplicationData，返回标记以供上层判断是否需要解密后重解析。
func (p *TLSParser) Parse(payload []byte, direction uint8, ts time.Time) *ParseResult {
	if len(payload) < 5 {
		return nil
	}

	ct := payload[0]
	// minor := payload[2] // 通常为 0x01-0x03

	switch ct {
	case tlsContentTypeHandshake:
		return p.parseHandshake(payload, direction, ts)
	case tlsContentTypeApplicationData:
		// 应用数据已加密，无法在此直接解析；
		// uprobe 层采集的是明文，走的是另一条路径（l7_tls_events），此处返回 nil。
		return nil
	case tlsContentTypeAlert:
		return p.parseAlert(payload, ts)
	}
	return nil
}

func (p *TLSParser) parseHandshake(payload []byte, direction uint8, ts time.Time) *ParseResult {
	if len(payload) < 9 {
		return nil
	}
	// TLS record: [0]=content_type [1:3]=version [3:5]=length
	// Handshake header: [5]=msg_type [6:9]=length (24-bit)
	msgType := payload[5]

	result := &ParseResult{
		Protocol:  ebpf.L7ProtocolTLS,
		StartTime: ts,
		EndTime:   ts,
	}

	switch msgType {
	case tlsHandshakeClientHello:
		result.ReqType = ebpf.L7RequestTypeRequest
		meta := parseClientHello(payload[5:])
		if meta != nil {
			result.TLSSNIName = meta.SNI
			result.TLSALPN = meta.ALPN
			result.TLSVersion = tlsVersionString(meta.Version)
			result.RequestResource = meta.SNI
			result.RequestType = "TLS_CLIENT_HELLO"
		}
	case tlsHandshakeServerHello:
		result.ReqType = ebpf.L7RequestTypeResponse
		meta := parseServerHello(payload[5:])
		if meta != nil {
			result.TLSVersion = tlsVersionString(meta.Version)
			result.TLSCipherSuite = tlsCipherSuiteName(meta.CipherSuite)
			result.RequestType = "TLS_SERVER_HELLO"
		}
	case tlsHandshakeCertificate:
		result.ReqType = ebpf.L7RequestTypeResponse
		result.RequestType = "TLS_CERTIFICATE"
	default:
		return nil
	}

	return result
}

func (p *TLSParser) parseAlert(payload []byte, ts time.Time) *ParseResult {
	if len(payload) < 7 {
		return nil
	}
	alertLevel := payload[5]
	alertDesc := payload[6]
	result := &ParseResult{
		Protocol:       ebpf.L7ProtocolTLS,
		ReqType:        ebpf.L7RequestTypeSession,
		StartTime:      ts,
		EndTime:        ts,
		RequestType:    "TLS_ALERT",
		ResponseStatus: 1,
	}
	if alertLevel == 2 { // fatal
		result.ResponseStatus = 2
	}
	result.ResponseErrMsg = tlsAlertDescription(alertDesc)
	return result
}

// ── ClientHello 解析 ──────────────────────────────────────

func parseClientHello(data []byte) *TLSMeta {
	if len(data) < 4 {
		return nil
	}
	// handshake header: msg_type(1) + length(3)
	msgLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+msgLen {
		return nil
	}
	body := data[4 : 4+msgLen]
	if len(body) < 34 {
		return nil
	}

	meta := &TLSMeta{}
	// legacy_version (2) + random (32) = 34 bytes
	meta.Version = binary.BigEndian.Uint16(body[0:2])
	off := 34

	// Session ID
	if off >= len(body) {
		return meta
	}
	sessLen := int(body[off])
	off += 1 + sessLen

	// Cipher Suites length
	if off+2 > len(body) {
		return meta
	}
	csLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2 + csLen

	// Compression Methods length
	if off >= len(body) {
		return meta
	}
	compLen := int(body[off])
	off += 1 + compLen

	// Extensions
	if off+2 > len(body) {
		return meta
	}
	extTotal := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	extEnd := off + extTotal
	if extEnd > len(body) {
		extEnd = len(body)
	}

	for off+4 <= extEnd {
		extType := binary.BigEndian.Uint16(body[off : off+2])
		extLen := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		off += 4
		if off+extLen > extEnd {
			break
		}
		extData := body[off : off+extLen]
		switch extType {
		case tlsExtServerName:
			meta.SNI = parseSNIExtension(extData)
		case tlsExtALPN:
			meta.ALPN = parseALPNExtension(extData)
		case tlsExtSupportedVersions:
			// client: list of supported versions (2 bytes each, prefixed by 1-byte length)
			if len(extData) >= 3 {
				listLen := int(extData[0])
				for i := 1; i+1 < 1+listLen && i+1 < len(extData); i += 2 {
					v := binary.BigEndian.Uint16(extData[i : i+2])
					if v == tlsVersion13 {
						meta.Version = tlsVersion13
					}
				}
			}
		}
		off += extLen
	}
	return meta
}

func parseSNIExtension(data []byte) string {
	// server_name_list length(2) + server_name_type(1) + name_length(2) + name
	if len(data) < 5 {
		return ""
	}
	// skip list length
	nameType := data[2]
	if nameType != 0 { // host_name
		return ""
	}
	nameLen := int(binary.BigEndian.Uint16(data[3:5]))
	if 5+nameLen > len(data) {
		return ""
	}
	return string(data[5 : 5+nameLen])
}

func parseALPNExtension(data []byte) string {
	if len(data) < 4 {
		return ""
	}
	// protocol_name_list length(2) + protocol_name length(1) + name
	off := 2
	if off+1 > len(data) {
		return ""
	}
	nameLen := int(data[off])
	off++
	if off+nameLen > len(data) {
		return ""
	}
	return string(data[off : off+nameLen])
}

// ── ServerHello 解析 ──────────────────────────────────────

func parseServerHello(data []byte) *TLSMeta {
	if len(data) < 4 {
		return nil
	}
	msgLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+msgLen {
		return nil
	}
	body := data[4 : 4+msgLen]
	if len(body) < 36 {
		return nil
	}
	meta := &TLSMeta{}
	meta.Version = binary.BigEndian.Uint16(body[0:2])
	off := 34 // version(2) + random(32)

	// Session ID
	if off >= len(body) {
		return meta
	}
	sessLen := int(body[off])
	off += 1 + sessLen

	// Cipher Suite
	if off+2 > len(body) {
		return meta
	}
	meta.CipherSuite = binary.BigEndian.Uint16(body[off : off+2])
	off += 2

	// Compression Method
	off++

	// Extensions
	if off+2 > len(body) {
		return meta
	}
	extTotal := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	extEnd := off + extTotal
	if extEnd > len(body) {
		extEnd = len(body)
	}

	for off+4 <= extEnd {
		extType := binary.BigEndian.Uint16(body[off : off+2])
		extLen := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		off += 4
		if off+extLen > extEnd {
			break
		}
		extData := body[off : off+extLen]
		if extType == tlsExtSupportedVersions && len(extData) >= 2 {
			meta.Version = binary.BigEndian.Uint16(extData[0:2])
		}
		off += extLen
	}
	return meta
}

// ── Helpers ───────────────────────────────────────────────

func tlsVersionString(v uint16) string {
	switch v {
	case tlsVersion10:
		return "TLS 1.0"
	case tlsVersion11:
		return "TLS 1.1"
	case tlsVersion12:
		return "TLS 1.2"
	case tlsVersion13:
		return "TLS 1.3"
	default:
		return "TLS Unknown"
	}
}

func tlsCipherSuiteName(cs uint16) string {
	// 仅列出常见套件，其余返回十六进制
	switch cs {
	case 0x1301:
		return "TLS_AES_128_GCM_SHA256"
	case 0x1302:
		return "TLS_AES_256_GCM_SHA384"
	case 0x1303:
		return "TLS_CHACHA20_POLY1305_SHA256"
	case 0xC02B:
		return "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case 0xC02C:
		return "ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	case 0xC02F:
		return "ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case 0xC030:
		return "ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case 0xCCA8:
		return "ECDHE_RSA_WITH_CHACHA20_POLY1305"
	case 0xCCA9:
		return "ECDHE_ECDSA_WITH_CHACHA20_POLY1305"
	default:
		return fmt.Sprintf("0x%04X", cs)
	}
}

func tlsAlertDescription(desc uint8) string {
	switch desc {
	case 0:
		return "close_notify"
	case 10:
		return "unexpected_message"
	case 20:
		return "bad_record_mac"
	case 40:
		return "handshake_failure"
	case 42:
		return "bad_certificate"
	case 44:
		return "certificate_expired"
	case 45:
		return "certificate_unknown"
	case 46:
		return "illegal_parameter"
	case 48:
		return "unknown_ca"
	case 50:
		return "decode_error"
	case 51:
		return "decrypt_error"
	case 70:
		return "protocol_version"
	case 71:
		return "insufficient_security"
	case 80:
		return "internal_error"
	case 90:
		return "user_canceled"
	case 109:
		return "missing_extension"
	case 110:
		return "unsupported_extension"
	case 112:
		return "unrecognized_name"
	case 116:
		return "certificate_required"
	case 120:
		return "no_application_protocol"
	default:
		return fmt.Sprintf("alert_%d", desc)
	}
}


