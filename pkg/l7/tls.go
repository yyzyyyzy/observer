// pkg/l7/tls.go
// TLS 明文路由解析器
//
// 工作原理：
//   eBPF uprobe 挂载在 SSL_read / SSL_write / SSL_read_ex / SSL_write_ex，
//   在 OpenSSL/BoringSSL/libssl 完成加解密后捕获明文 buffer，经由
//   tls_events ringbuf 发送到用户态。
//
//   TLSParser 本身不解析应用协议，而是将已解密的明文转发给内嵌子解析器：
//     gRPC → HTTP/2 → HTTP/1.x（按置信度从高到低）
//
//   所有子解析器的 CanParse 传入 port=0，改为完全依靠 payload 结构识别。
//
// 挂载点：SSL_read / SSL_write / SSL_read_ex / SSL_write_ex
// 支持库：OpenSSL 1.1.x / 3.x / BoringSSL

package l7

import (
	"bytes"
	"time"

	"observer/pkg/ebpf"
)

// TLSParser 处理来自 SSL uprobe 的已解密明文载荷。
type TLSParser struct {
	grpcParser  Parser
	http2Parser Parser
	httpParser  Parser
}

func NewTLSParser() *TLSParser {
	return &TLSParser{
		grpcParser:  NewGRPCParser(),
		http2Parser: NewHTTP2Parser(),
		httpParser:  NewHTTPParser(),
	}
}

func (p *TLSParser) Protocol() ebpf.L7Protocol { return ebpf.L7ProtocolTLS }

// CanParse 判断是否应由 TLSParser 处理。
func (p *TLSParser) CanParse(payload []byte, srcPort, dstPort uint16) bool {
	if isTLSPort(srcPort) || isTLSPort(dstPort) {
		return true
	}
	return isHTTPPlaintext(payload) || isHTTP2Preface(payload)
}

// Parse 依次尝试 gRPC → HTTP/2 → HTTP/1.x。
// 在结果的 TLSVersion 字段附加 "TLS" 标记。
func (p *TLSParser) Parse(payload []byte, direction uint8, ts time.Time) *ParseResult {
	if len(payload) == 0 {
		return nil
	}
	if p.grpcParser.CanParse(payload, 0, 0) {
		if result := p.grpcParser.Parse(payload, direction, ts); result != nil {
			result.TLSVersion = "TLS"
			return result
		}
	}
	if p.http2Parser.CanParse(payload, 0, 0) {
		if result := p.http2Parser.Parse(payload, direction, ts); result != nil {
			result.TLSVersion = "TLS"
			return result
		}
	}
	if p.httpParser.CanParse(payload, 0, 0) {
		if result := p.httpParser.Parse(payload, direction, ts); result != nil {
			result.TLSVersion = "TLS"
			return result
		}
	}
	return nil
}

// isTLSPort 常见 HTTPS / gRPC-TLS 端口。
func isTLSPort(port uint16) bool {
	switch port {
	case 443, 8443, 6443, 9443, 4443, 5443, 8444, 15443:
		return true
	}
	return false
}

// isHTTPPlaintext payload 以常见 HTTP/1.x 方法或响应行前缀开头。
func isHTTPPlaintext(payload []byte) bool {
	if len(payload) < 4 {
		return false
	}
	for _, pf := range []string{"GET ", "POST", "PUT ", "DELE", "HEAD", "OPTI", "PATC", "HTTP"} {
		if len(payload) >= len(pf) && string(payload[:len(pf)]) == pf {
			return true
		}
	}
	return false
}

// isHTTP2Preface payload 以 HTTP/2 连接前言或有效帧头开头。
func isHTTP2Preface(payload []byte) bool {
	if bytes.HasPrefix(payload, h2PrefaceBytes) {
		return true
	}
	return isValidH2FrameHeader(payload)
}
