// pkg/l7/http2.go
// HTTP/2 协议解析器（帧解析）+ gRPC 协议解析器（基于 HTTP/2 实现）。
//
// HTTP/2 帧格式（前 9 字节固定帧头）：
//   [0:3]  Length（24bit，帧 payload 长度）
//   [3]    Type（0=DATA 1=HEADERS 4=SETTINGS 7=GOAWAY ...）
//   [4]    Flags
//   [5:9]  StreamID（31bit，最高位保留为 0）

package l7

import (
	"bytes"
	"encoding/binary"
	"strings"
	"time"

	"observer/pkg/ebpf"
)

// ── HTTP/2 帧类型常量 ─────────────────────────────────────────────────────────

const (
	h2FrameData         = 0x0
	h2FrameHeaders      = 0x1
	h2FrameSettings     = 0x4
	h2FramePushPromise  = 0x5
	h2FramePing         = 0x6
	h2FrameGoaway       = 0x7
	h2FrameWindowUpdate = 0x8
	h2FrameContinuation = 0x9

	// HTTP/2 连接前言（Magic）
	h2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	h2PrefaceLen    = 24
)

// HTTP/2 SETTINGS 帧最小长度（9 字节帧头 + 0 个 setting）
const h2SettingsMinLen = 9

// ── HTTP2Parser ───────────────────────────────────────────────────────────────

// HTTP2Parser 解析原始 HTTP/2 帧流（非 TLS）。
// 主要识别 SETTINGS 帧（连接建立）和 HEADERS 帧（请求/响应头）。
type HTTP2Parser struct{}

func NewHTTP2Parser() *HTTP2Parser { return &HTTP2Parser{} }

func (p *HTTP2Parser) Protocol() ebpf.L7Protocol { return ebpf.L7ProtocolHTTP2 }

func (p *HTTP2Parser) CanParse(payload []byte, _, _ uint16) bool {
	if len(payload) < 9 {
		return false
	}
	// HTTP/2 客户端连接前言
	if bytes.HasPrefix(payload, []byte(h2ClientPreface[:len(h2ClientPreface)])) {
		return true
	}
	// 检查帧头合法性（Length≤16384, Type∈已知类型, StreamID 最高位为 0）
	frameLen := uint32(payload[0])<<16 | uint32(payload[1])<<8 | uint32(payload[2])
	frameType := payload[3]
	streamID := binary.BigEndian.Uint32(payload[5:9]) & 0x7fffffff

	return frameLen <= 16384 &&
		(frameType <= h2FrameContinuation) &&
		(streamID < 0x7fffffff) &&
		len(payload) >= int(9+frameLen)
}

func (p *HTTP2Parser) Parse(payload []byte, direction uint8, ts time.Time) *ParseResult {
	result := &ParseResult{
		Protocol:  ebpf.L7ProtocolHTTP2,
		StartTime: ts,
		EndTime:   ts,
	}

	// 跳过客户端连接前言
	data := payload
	if bytes.HasPrefix(data, []byte(h2ClientPreface)) {
		data = data[h2PrefaceLen:]
		result.ReqType = ebpf.L7RequestTypeRequest
	}

	if len(data) < 9 {
		if result.ReqType != 0 {
			return result
		}
		return nil
	}

	frameType := data[3]
	frameLen := uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])
	streamID := binary.BigEndian.Uint32(data[5:9]) & 0x7fffffff

	switch frameType {
	case h2FrameSettings:
		result.ReqType = ebpf.L7RequestTypeRequest
		result.RequestType = "SETTINGS"
	case h2FrameHeaders:
		// HEADERS 帧：包含 HPACK 压缩的头部
		// 简单启发式：streamID 为奇数=客户端发起请求，偶数=服务端推送
		if streamID%2 == 1 {
			result.ReqType = ebpf.L7RequestTypeRequest
		} else {
			result.ReqType = ebpf.L7RequestTypeResponse
		}
		result.RequestType = "HEADERS"
		if len(data) > 9 {
			headerPayload := data[9 : min64(9+int(frameLen), len(data))]
			result.RequestResource = extractH2Path(headerPayload)
			result.HTTPHost = extractH2Authority(headerPayload)
		}
	case h2FrameData:
		result.ReqType = ebpf.L7RequestTypeSession
		result.RequestType = "DATA"
		result.HTTPReqBodySize = int64(frameLen)
	case h2FrameGoaway:
		result.ReqType = ebpf.L7RequestTypeSession
		result.RequestType = "GOAWAY"
	default:
		result.ReqType = ebpf.L7RequestTypeSession
		result.RequestType = "FRAME"
	}

	return result
}

// extractH2Path 从未压缩的伪头部提取 :path（仅适用于未 HPACK 压缩的头部）。
func extractH2Path(data []byte) string {
	s := string(data)
	if idx := strings.Index(s, ":path"); idx >= 0 {
		rest := s[idx+5:]
		if len(rest) > 0 {
			return strings.Fields(rest)[0]
		}
	}
	return ""
}

// extractH2Authority 从伪头部提取 :authority。
func extractH2Authority(data []byte) string {
	s := string(data)
	if idx := strings.Index(s, ":authority"); idx >= 0 {
		rest := s[idx+10:]
		if len(rest) > 0 {
			return strings.Fields(rest)[0]
		}
	}
	return ""
}

func min64(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── GRPCParser ────────────────────────────────────────────────────────────────

// GRPCParser 解析 gRPC over HTTP/2 协议。
//
// gRPC 请求/响应帧格式（Length-Prefixed Message）：
//   [0]    Compressed flag（0=未压缩 1=压缩）
//   [1:5]  Message length（big-endian uint32）
//   [5:]   Protobuf encoded message
//
// gRPC 使用 HTTP/2 的 HEADERS 帧传递请求头（Content-Type: application/grpc），
// 使用 DATA 帧传递请求/响应体。

const grpcContentType = "application/grpc"

// GRPCParser gRPC 协议解析器（识别 Content-Type: application/grpc 特征）。
type GRPCParser struct{}

func NewGRPCParser() *GRPCParser { return &GRPCParser{} }

func (p *GRPCParser) Protocol() ebpf.L7Protocol { return ebpf.L7ProtocolGRPC }

func (p *GRPCParser) CanParse(payload []byte, srcPort, dstPort uint16) bool {
	if len(payload) < 5 {
		return false
	}
	// gRPC 端口启发式
	if srcPort == 50051 || dstPort == 50051 {
		return true
	}
	// 检测 gRPC Content-Type 特征
	if bytes.Contains(payload, []byte(grpcContentType)) {
		return true
	}
	// 检测 gRPC 数据帧 magic（Compressed=0, Length>0）
	if payload[0] == 0 || payload[0] == 1 {
		msgLen := binary.BigEndian.Uint32(payload[1:5])
		return msgLen > 0 && msgLen < 4*1024*1024 // 合理消息大小 <4MB
	}
	return false
}

func (p *GRPCParser) Parse(payload []byte, direction uint8, ts time.Time) *ParseResult {
	result := &ParseResult{
		Protocol:  ebpf.L7ProtocolGRPC,
		StartTime: ts,
		EndTime:   ts,
	}

	// 检测 Content-Type 头部 → 这是 HTTP/2 HEADERS 帧，包含 gRPC 元数据
	s := string(payload)
	if bytes.Contains(payload, []byte(grpcContentType)) {
		// 提取路径（:path 伪头部格式："/package.Service/Method"）
		if idx := strings.Index(s, ":path"); idx >= 0 {
			rest := strings.Fields(s[idx+5:])
			if len(rest) > 0 {
				result.HTTPPath = rest[0]
				result.RequestResource = rest[0]
				// 从路径提取服务名和方法名
				parts := strings.Split(strings.TrimPrefix(rest[0], "/"), "/")
				if len(parts) >= 2 {
					result.HTTPMethod = parts[len(parts)-1] // Method name
				}
			}
		}
		if idx := strings.Index(s, ":authority"); idx >= 0 {
			rest := strings.Fields(s[idx+10:])
			if len(rest) > 0 {
				result.HTTPHost = rest[0]
			}
		}
		// grpc-status 存在于响应 Trailers 中
		if idx := strings.Index(s, "grpc-status:"); idx >= 0 {
			rest := strings.Fields(s[idx+12:])
			if len(rest) > 0 {
				var code uint32
				for _, c := range rest[0] {
					if c >= '0' && c <= '9' {
						code = code*10 + uint32(c-'0')
					}
				}
				result.GRPCStatusCode = code
				if code == 0 {
					result.ResponseStatus = 0
				} else {
					result.ResponseStatus = 2 // server error
					result.ResponseCode = int64(code)
				}
				result.ReqType = ebpf.L7RequestTypeResponse
				return result
			}
		}
		result.ReqType = ebpf.L7RequestTypeRequest
		result.RequestType = "UNARY"
		return result
	}

	// gRPC 数据帧（Length-Prefixed Message）
	if len(payload) >= 5 {
		compressed := payload[0]
		msgLen := binary.BigEndian.Uint32(payload[1:5])
		result.RequestType = "DATA"
		if compressed == 0 {
			result.HTTPReqBodySize = int64(msgLen)
		}
		result.ReqType = ebpf.L7RequestTypeSession
	}

	return result
}
