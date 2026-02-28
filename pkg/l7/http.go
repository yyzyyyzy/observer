// pkg/l7/http.go
// HTTP/1.x 协议解析器（RFC 7230）
//
// 协议识别策略：
//   CanParse：
//     优先匹配请求行 method 前缀（"GET "/"POST "等）或响应行前缀（"HTTP/"），
//     这是 HTTP/1.x 最强的 magic bytes，误判率极低。
//     端口 80/8080 作为补充启发，但必须 payload 符合 ASCII 可见字符范围
//     才可返回 true（避免把 Kafka/MySQL 的二进制数据误判为 HTTP）。
//
//   Parse：
//     使用 net/http 标准库做精确解析。
//     请求报文 → ReadRequest，响应报文 → ReadResponse。
//     任一失败返回 nil，驱动 Registry 继续尝试下一个解析器。

package l7

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"time"

	"observer/pkg/ebpf"
)

// httpMethods 所有 HTTP/1.x 方法的请求行前缀，用于 magic bytes 识别。
// 按使用频率排序，减少平均比较次数。
var httpMethods = [][]byte{
	[]byte("GET "),
	[]byte("POST "),
	[]byte("HTTP/"),  // 响应行：HTTP/1.0 或 HTTP/1.1
	[]byte("PUT "),
	[]byte("DELETE "),
	[]byte("HEAD "),
	[]byte("OPTIONS "),
	[]byte("PATCH "),
	[]byte("CONNECT "),
	[]byte("TRACE "),
}

// HTTPParser HTTP/1.x 协议解析器。
type HTTPParser struct{}

func NewHTTPParser() *HTTPParser { return &HTTPParser{} }

func (p *HTTPParser) Protocol() ebpf.L7Protocol { return ebpf.L7ProtocolHTTP }

// CanParse 识别 HTTP/1.x 报文。
// 优先检查 method/响应 前缀（高置信度），其次做端口 + 可见字符双重校验。
func (p *HTTPParser) CanParse(payload []byte, srcPort, dstPort uint16) bool {
	if len(payload) < 7 {
		return false
	}
	// Magic bytes：任意 HTTP 方法或响应行前缀
	for _, prefix := range httpMethods {
		if bytes.HasPrefix(payload, prefix) {
			return true
		}
	}
	// 端口补充启发（仅在 payload 看起来是 ASCII 文本时生效）
	if srcPort == 80 || dstPort == 80 || srcPort == 8080 || dstPort == 8080 {
		return isPrintableASCII(payload[:minInt(32, len(payload))])
	}
	return false
}

// Parse 精确解析 HTTP/1.x 请求或响应。
func (p *HTTPParser) Parse(payload []byte, direction uint8, ts time.Time) *ParseResult {
	// 尝试解析为请求
	if req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(payload))); err == nil {
		result := &ParseResult{
			Protocol:        ebpf.L7ProtocolHTTP,
			ReqType:         ebpf.L7RequestTypeRequest,
			StartTime:       ts,
			EndTime:         ts,
			HTTPMethod:      req.Method,
			HTTPPath:        req.URL.Path,
			HTTPHost:        req.Host,
			HTTPUserAgent:   req.UserAgent(),
			HTTPReferer:     req.Referer(),
			RequestResource: req.URL.Path,
			RequestType:     req.Method,
		}
		if req.ContentLength > 0 {
			result.HTTPReqBodySize = req.ContentLength
		}
		return result
	}

	// 尝试解析为响应
	if resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(payload)), nil); err == nil {
		result := &ParseResult{
			Protocol:       ebpf.L7ProtocolHTTP,
			ReqType:        ebpf.L7RequestTypeResponse,
			StartTime:      ts,
			EndTime:        ts,
			HTTPStatusCode: uint16(resp.StatusCode),
			ResponseCode:   int64(resp.StatusCode),
		}
		if resp.ContentLength > 0 {
			result.HTTPRespBodySize = resp.ContentLength
		}
		switch {
		case resp.StatusCode >= 500:
			result.ResponseStatus = 2
			result.ResponseErrMsg = fmt.Sprintf("HTTP %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
		case resp.StatusCode >= 400:
			result.ResponseStatus = 1
			result.ResponseErrMsg = fmt.Sprintf("HTTP %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
		default:
			result.ResponseStatus = 0
		}
		return result
	}

	return nil
}

// isPrintableASCII 判断 data 是否全部由可打印 ASCII 字符（0x20~0x7E）
// 或常见控制字符（\t \r \n）组成。
func isPrintableASCII(data []byte) bool {
	for _, b := range data {
		if b < 0x20 && b != '\t' && b != '\r' && b != '\n' {
			return false
		}
		if b > 0x7E {
			return false
		}
	}
	return true
}
