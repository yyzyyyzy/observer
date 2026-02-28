// pkg/l7/http2.go
// HTTP/2 协议解析器（RFC 7540）+ gRPC 协议解析器
//
// ── HTTP/2 帧结构 ────────────────────────────────────────────────────────────
//
//   ┌─────────────────────────────────────────────┐
//   │  Length (24 bit)   │  Type (8 bit)           │  偏移 0–3
//   ├─────────────────────────────────────────────┤
//   │  Flags (8 bit)     │  R │ Stream ID (31 bit)  │  偏移 4–8
//   ├─────────────────────────────────────────────┤
//   │  Frame Payload (Length bytes)               │  偏移 9+
//   └─────────────────────────────────────────────┘
//
//   帧类型（RFC 7540 §6）：
//     0x0 DATA  0x1 HEADERS  0x2 PRIORITY  0x3 RST_STREAM
//     0x4 SETTINGS  0x5 PUSH_PROMISE  0x6 PING
//     0x7 GOAWAY  0x8 WINDOW_UPDATE  0x9 CONTINUATION
//
// ── gRPC Length-Prefixed Message ─────────────────────────────────────────────
//
//   ┌──────────────────────────┐
//   │  Compressed Flag (1 B)  │  0=未压缩  1=压缩
//   ├──────────────────────────┤
//   │  Message Length (4 B)   │  大端 uint32
//   ├──────────────────────────┤
//   │  Protobuf Message       │
//   └──────────────────────────┘
//
// ── 协议识别策略 ─────────────────────────────────────────────────────────────
//
//   HTTP2Parser.CanParse：
//     首选：24 字节 PRI * preface（客户端连接前言，确定性 100%）
//     次选：端口 80/8080/8443 + 严格帧头校验（5 个独立条件 AND）
//       • frameLen ≤ 16384（单帧最大 payload，RFC 7540 §4.2 默认值）
//       • frameType ∈ [0x0, 0x9]
//       • Flags 高 3 位 = 0（RFC 保留位）
//       • StreamID 最高位 = 0（RFC 保留位）
//       • payload 长度 ≥ 9 + frameLen（帧数据完整）
//
//   GRPCParser.CanParse：
//     端口 50051（gRPC 默认端口）
//     或 payload 含 "application/grpc"（HEADERS 帧中的 Content-Type）
//     或 payload 含 "grpc-status"（响应 Trailers）

package l7

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"
	"time"

	"observer/pkg/ebpf"
)

// ── HTTP/2 常量 ───────────────────────────────────────────────────────────────

const (
	h2FrameData         uint8 = 0x0
	h2FrameHeaders      uint8 = 0x1
	h2FramePriority     uint8 = 0x2
	h2FrameRSTStream    uint8 = 0x3
	h2FrameSettings     uint8 = 0x4
	h2FramePushPromise  uint8 = 0x5
	h2FramePing         uint8 = 0x6
	h2FrameGoaway       uint8 = 0x7
	h2FrameWindowUpdate uint8 = 0x8
	h2FrameContinuation uint8 = 0x9

	// HTTP/2 客户端连接前言（RFC 7540 §3.5）
	h2Preface    = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	h2PrefaceLen = 24

	// RFC 7540 §4.2: 默认最大帧 payload 16384 字节
	h2MaxFramePayload = 16384
)

var h2PrefaceBytes = []byte(h2Preface)

// ── HTTP2Parser ───────────────────────────────────────────────────────────────

// HTTP2Parser 解析明文（h2c）或经 TLS uprobe 还原的 HTTP/2 帧流。
// 主要识别：SETTINGS（连接建立）、HEADERS（请求/响应头）、DATA（正文）、GOAWAY。
type HTTP2Parser struct{}

func NewHTTP2Parser() *HTTP2Parser { return &HTTP2Parser{} }

func (p *HTTP2Parser) Protocol() ebpf.L7Protocol { return ebpf.L7ProtocolHTTP2 }

func (p *HTTP2Parser) CanParse(payload []byte, srcPort, dstPort uint16) bool {
	if len(payload) < 9 {
		return false
	}
	// 最强特征：客户端连接前言（PRI * HTTP/2.0...）
	if bytes.HasPrefix(payload, h2PrefaceBytes) {
		return true
	}
	// 端口启发 + 严格帧头校验（5 AND 条件）
	isH2Port := srcPort == 80 || dstPort == 80 ||
		srcPort == 8080 || dstPort == 8080 ||
		srcPort == 8443 || dstPort == 8443
	if !isH2Port {
		return false
	}
	return isValidH2FrameHeader(payload)
}

func (p *HTTP2Parser) Parse(payload []byte, direction uint8, ts time.Time) *ParseResult {
	result := &ParseResult{
		Protocol:  ebpf.L7ProtocolHTTP2,
		StartTime: ts,
		EndTime:   ts,
	}

	data := payload
	// 跳过客户端连接前言
	if bytes.HasPrefix(data, h2PrefaceBytes) {
		data = data[h2PrefaceLen:]
		result.ReqType = ebpf.L7RequestTypeRequest
		result.RequestType = "PREFACE"
	}
	if len(data) < 9 {
		if result.ReqType != 0 {
			return result
		}
		return nil
	}

	frameLen := uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])
	frameType := data[3]
	streamID := binary.BigEndian.Uint32(data[5:9]) & 0x7FFFFFFF

	switch frameType {
	case h2FrameSettings:
		result.ReqType = ebpf.L7RequestTypeRequest
		result.RequestType = "SETTINGS"

	case h2FrameHeaders:
		// StreamID 奇数 = 客户端发起（请求），偶数 = 服务端推送
		if streamID%2 == 1 {
			result.ReqType = ebpf.L7RequestTypeRequest
		} else {
			result.ReqType = ebpf.L7RequestTypeResponse
		}
		result.RequestType = "HEADERS"
		if len(data) > 9 {
			end := 9 + int(frameLen)
			if end > len(data) {
				end = len(data)
			}
			headerPayload := data[9:end]
			result.RequestResource = extractPseudoHeader(headerPayload, ":path")
			result.HTTPHost = extractPseudoHeader(headerPayload, ":authority")
			result.HTTPMethod = extractPseudoHeader(headerPayload, ":method")
		}

	case h2FrameData:
		result.ReqType = ebpf.L7RequestTypeSession
		result.RequestType = "DATA"
		if streamID%2 == 1 {
			result.HTTPReqBodySize = int64(frameLen)
		} else {
			result.HTTPRespBodySize = int64(frameLen)
		}

	case h2FrameRSTStream:
		result.ReqType = ebpf.L7RequestTypeSession
		result.RequestType = "RST_STREAM"
		if len(data) >= 13 {
			errCode := binary.BigEndian.Uint32(data[9:13])
			if errCode != 0 {
				result.ResponseStatus = 2
				result.ResponseCode = int64(errCode)
			}
		}

	case h2FrameGoaway:
		result.ReqType = ebpf.L7RequestTypeSession
		result.RequestType = "GOAWAY"
		if len(data) >= 17 {
			errCode := binary.BigEndian.Uint32(data[13:17])
			if errCode != 0 {
				result.ResponseStatus = 2
				result.ResponseCode = int64(errCode)
			}
		}

	default:
		result.ReqType = ebpf.L7RequestTypeSession
		result.RequestType = "FRAME"
	}

	return result
}

// isValidH2FrameHeader 对 HTTP/2 帧头做严格的 5 AND 条件校验。
func isValidH2FrameHeader(payload []byte) bool {
	if len(payload) < 9 {
		return false
	}
	frameLen := uint32(payload[0])<<16 | uint32(payload[1])<<8 | uint32(payload[2])
	frameType := payload[3]
	flags := payload[4]
	streamIDRaw := binary.BigEndian.Uint32(payload[5:9])

	return frameLen <= h2MaxFramePayload && // 帧长合理
		frameType <= h2FrameContinuation && // 已知帧类型
		flags&0xE0 == 0 && // 高 3 位为保留位（必须为 0）
		streamIDRaw&0x80000000 == 0 && // StreamID 最高位保留为 0
		uint32(len(payload)) >= 9+frameLen // payload 完整
}

// extractPseudoHeader 从未压缩（或已解压）的 HTTP/2 HEADERS 载荷中提取伪头部值。
// 仅用于未经 HPACK 压缩的明文头部（TLS uprobe 解密后的帧通常未压缩）。
func extractPseudoHeader(data []byte, name string) string {
	s := string(data)
	idx := strings.Index(s, name)
	if idx < 0 {
		return ""
	}
	rest := strings.TrimSpace(s[idx+len(name):])
	if len(rest) == 0 {
		return ""
	}
	// 取到下一个 \x00 或换行符为止
	end := strings.IndexAny(rest, "\x00\r\n")
	if end < 0 {
		end = minInt(len(rest), 256)
	}
	return strings.TrimSpace(rest[:end])
}

// ── GRPCParser ────────────────────────────────────────────────────────────────

// GRPCParser gRPC over HTTP/2 协议解析器。
//
// gRPC 在 HTTP/2 之上叠加了两层协议：
//   1. HTTP/2 HEADERS 帧传递 RPC 元数据（Content-Type、:path、grpc-status 等）
//   2. HTTP/2 DATA 帧传递 Length-Prefixed Protobuf 消息
//
// CanParse 依赖 HEADERS 帧中的字符串特征，而非帧结构（HTTP/2Parser 已覆盖帧结构）。
type GRPCParser struct{}

func NewGRPCParser() *GRPCParser { return &GRPCParser{} }

func (p *GRPCParser) Protocol() ebpf.L7Protocol { return ebpf.L7ProtocolGRPC }

func (p *GRPCParser) CanParse(payload []byte, srcPort, dstPort uint16) bool {
	if len(payload) < 5 {
		return false
	}
	// gRPC 默认端口
	if srcPort == 50051 || dstPort == 50051 {
		return true
	}
	// gRPC 应用层特征（出现在 HTTP/2 HEADERS 帧的 header block 中）
	return bytes.Contains(payload, []byte("application/grpc")) ||
		bytes.Contains(payload, []byte("grpc-status")) ||
		bytes.Contains(payload, []byte("grpc-message"))
}

func (p *GRPCParser) Parse(payload []byte, direction uint8, ts time.Time) *ParseResult {
	result := &ParseResult{
		Protocol:  ebpf.L7ProtocolGRPC,
		StartTime: ts,
		EndTime:   ts,
	}

	s := string(payload)

	// ── 识别 HEADERS 帧（含 Content-Type: application/grpc）────────────────
	if bytes.Contains(payload, []byte("application/grpc")) {
		// 提取 RPC 路径（格式：/package.ServiceName/MethodName）
		if path := extractPseudoHeader(payload, ":path"); path != "" {
			result.HTTPPath = path
			result.RequestResource = path
			// 从 /pkg.Service/Method 提取方法名
			parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 2)
			if len(parts) == 2 {
				result.HTTPMethod = parts[1] // MethodName
			}
		}
		result.HTTPHost = extractPseudoHeader(payload, ":authority")

		// grpc-status 出现表示这是响应 Trailers
		if idx := strings.Index(s, "grpc-status:"); idx >= 0 {
			codeStr := strings.TrimSpace(s[idx+len("grpc-status:"):])
			end := strings.IndexAny(codeStr, "\x00\r\n ")
			if end > 0 {
				codeStr = codeStr[:end]
			}
			if code, err := strconv.ParseUint(codeStr, 10, 32); err == nil {
				result.GRPCStatusCode = uint32(code)
				if code == 0 {
					result.ResponseStatus = 0
				} else {
					result.ResponseStatus = 2
					result.ResponseCode = int64(code)
					// grpc-message 字段包含错误描述
					if idx2 := strings.Index(s, "grpc-message:"); idx2 >= 0 {
						msg := strings.TrimSpace(s[idx2+len("grpc-message:"):])
						end2 := strings.IndexAny(msg, "\x00\r\n")
						if end2 > 0 {
							msg = msg[:end2]
						}
						result.ResponseErrMsg = msg
					}
				}
				result.ReqType = ebpf.L7RequestTypeResponse
				return result
			}
		}

		result.ReqType = ebpf.L7RequestTypeRequest
		result.RequestType = "UNARY"
		return result
	}

	// ── 识别 DATA 帧（Length-Prefixed Message）───────────────────────────────
	// 格式：[Compressed(1)][Length(4)][Protobuf...]
	// 仅检查 Compressed flag 合法性（0 或 1）和 Length 合理性
	if len(payload) >= 5 {
		compressed := payload[0]
		if compressed <= 1 {
			msgLen := binary.BigEndian.Uint32(payload[1:5])
			if msgLen > 0 && msgLen <= 4*1024*1024 { // 最大 4MB
				result.HTTPReqBodySize = int64(msgLen)
				result.RequestType = "DATA"
				result.ReqType = ebpf.L7RequestTypeSession
				return result
			}
		}
	}

	return nil
}
