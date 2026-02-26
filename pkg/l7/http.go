// pkg/l7/http.go
// HTTP/1.1 L7 协议解析器。

package l7

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"time"

	"observer/pkg/ebpf"
)

// HTTPParser HTTP/1.1 协议解析器（包含 HTTP → gRPC 升级检测）。
type HTTPParser struct{}

func NewHTTPParser() *HTTPParser { return &HTTPParser{} }

func (p *HTTPParser) Protocol() ebpf.L7Protocol { return ebpf.L7ProtocolHTTP }

func (p *HTTPParser) CanParse(payload []byte, srcPort, dstPort uint16) bool {
	if len(payload) < 7 {
		return false
	}
	prefixes := [][]byte{
		[]byte("GET "), []byte("POST "), []byte("PUT "),
		[]byte("DELETE "), []byte("HEAD "), []byte("OPTIONS "),
		[]byte("PATCH "), []byte("HTTP/"),
	}
	for _, pf := range prefixes {
		if bytes.HasPrefix(payload, pf) {
			return true
		}
	}
	return srcPort == 80 || dstPort == 80 ||
		srcPort == 8080 || dstPort == 8080
}

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
