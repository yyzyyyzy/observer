// pkg/l7/redis.go
// Redis RESP（REdis Serialization Protocol）协议解析器
//
// ── RESP 协议格式（RESP2，Redis 1.x~6.x 默认）────────────────────────────────
//
//   类型标识字节（首字节）：
//     '+' Simple String   → "+OK\r\n"
//     '-' Error           → "-ERR unknown command\r\n"
//     ':' Integer         → ":1000\r\n"
//     '$' Bulk String     → "$6\r\nfoobar\r\n"  （-1 表示 Null bulk string）
//     '*' Array           → "*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n"
//
//   客户端请求：始终使用 Array 格式（*N\r\n$len\r\ncmd\r\n...）
//   服务端响应：使用 Simple String、Error、Integer、Bulk String 或 Array
//
// ── RESP3（Redis 7.0+）新增类型 ──────────────────────────────────────────────
//
//   '_' Null   ',' Double  '#' Boolean  '(' Big Number
//   '!' Blob Error  '=' Verbatim String  '%' Map  '~' Set  '>' Push
//   本解析器对 RESP3 新增类型做 fallback 处理（识别但不深度解析）。
//
// ── 协议识别策略 ─────────────────────────────────────────────────────────────
//
//   CanParse：
//     端口 6379（最强特征）。
//     首字节必须是 RESP2/RESP3 合法类型字节之一。
//     不做 payload 长度语义校验（避免截断包误判）。
//
//   Parse：
//     '*' Array：解析请求（命令 + 第一个 key）
//     '+' / ':' / '$'：响应成功
//     '-'：响应错误（提取错误消息）
//     RESP3 新增类型：作为会话包返回（不丢弃）

package l7

import (
	"bytes"
	"strings"
	"time"

	"observer/pkg/ebpf"
)

// resp2Types RESP2 合法首字节集合（用于 CanParse）
var resp2Types = map[byte]bool{
	'+': true, '-': true, ':': true, '$': true, '*': true,
}

// resp3Types RESP3 新增首字节
var resp3Types = map[byte]bool{
	'_': true, ',': true, '#': true, '(': true,
	'!': true, '=': true, '%': true, '~': true, '>': true,
}

// RedisParser Redis RESP2/RESP3 协议解析器。
type RedisParser struct{}

func NewRedisParser() *RedisParser { return &RedisParser{} }

func (p *RedisParser) Protocol() ebpf.L7Protocol { return ebpf.L7ProtocolRedis }

func (p *RedisParser) CanParse(payload []byte, srcPort, dstPort uint16) bool {
	if srcPort == 6379 || dstPort == 6379 {
		return true
	}
	if len(payload) == 0 {
		return false
	}
	return resp2Types[payload[0]] || resp3Types[payload[0]]
}

func (p *RedisParser) Parse(payload []byte, direction uint8, ts time.Time) *ParseResult {
	if len(payload) == 0 {
		return nil
	}

	switch payload[0] {
	case '*':
		// Array → 客户端命令请求
		cmd, key, argc := parseRESPArray(payload)
		if cmd == "" {
			return nil
		}
		result := &ParseResult{
			Protocol:        ebpf.L7ProtocolRedis,
			ReqType:         ebpf.L7RequestTypeRequest,
			StartTime:       ts,
			EndTime:         ts,
			RedisCmd:        cmd,
			RedisKey:        key,
			RequestType:     cmd,
			RequestResource: key,
		}
		_ = argc
		return result

	case '+':
		// Simple String 响应（"+OK\r\n" 最常见）
		msg := extractInlineValue(payload[1:])
		return &ParseResult{
			Protocol:       ebpf.L7ProtocolRedis,
			ReqType:        ebpf.L7RequestTypeResponse,
			StartTime:      ts,
			EndTime:        ts,
			ResponseStatus: 0,
			RequestResource: msg,
		}

	case '-':
		// Error 响应（"-ERR message\r\n"）
		errMsg := extractInlineValue(payload[1:])
		return &ParseResult{
			Protocol:       ebpf.L7ProtocolRedis,
			ReqType:        ebpf.L7RequestTypeResponse,
			StartTime:      ts,
			EndTime:        ts,
			RedisErrMsg:    errMsg,
			ResponseStatus: 2,
			ResponseCode:   1,
			ResponseErrMsg: errMsg,
		}

	case ':':
		// Integer 响应（":1000\r\n"）
		return &ParseResult{
			Protocol:       ebpf.L7ProtocolRedis,
			ReqType:        ebpf.L7RequestTypeResponse,
			StartTime:      ts,
			EndTime:        ts,
			ResponseStatus: 0,
		}

	case '$':
		// Bulk String 响应（"$6\r\nfoobar\r\n" 或 "$-1\r\n"）
		return &ParseResult{
			Protocol:       ebpf.L7ProtocolRedis,
			ReqType:        ebpf.L7RequestTypeResponse,
			StartTime:      ts,
			EndTime:        ts,
			ResponseStatus: 0,
		}

	case '!':
		// RESP3 Blob Error
		errMsg := extractInlineValue(payload[1:])
		return &ParseResult{
			Protocol:       ebpf.L7ProtocolRedis,
			ReqType:        ebpf.L7RequestTypeResponse,
			StartTime:      ts,
			EndTime:        ts,
			ResponseStatus: 2,
			ResponseErrMsg: errMsg,
		}
	}

	// RESP3 其他类型（Map、Set、Push 等）作为会话包，不丢弃
	if resp3Types[payload[0]] {
		return &ParseResult{
			Protocol:  ebpf.L7ProtocolRedis,
			ReqType:   ebpf.L7RequestTypeSession,
			StartTime: ts,
			EndTime:   ts,
		}
	}

	return nil
}

// parseRESPArray 解析 RESP Array 格式的命令。
// 返回：命令名（大写）、第一个 key（可为空）、参数个数。
//
// 格式示例：
//
//	*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n
func parseRESPArray(data []byte) (cmd, key string, argc int) {
	lines := bytes.Split(data, []byte("\r\n"))
	// lines[0] = "*N"（N 为参数个数）
	// lines[1] = "$M"（命令字节长度）
	// lines[2] = CMD
	// lines[3] = "$K"（key 字节长度）
	// lines[4] = KEY
	if len(lines) < 3 || len(lines[0]) < 2 || lines[0][0] != '*' {
		return "", "", 0
	}

	// 解析参数个数
	for _, b := range lines[0][1:] {
		if b >= '0' && b <= '9' {
			argc = argc*10 + int(b-'0')
		}
	}

	// 命令名（lines[2]）
	if len(lines) >= 3 {
		cmd = strings.ToUpper(string(lines[2]))
	}
	if cmd == "" {
		return "", "", 0
	}

	// 第一个 key（lines[4]）
	if len(lines) >= 5 {
		key = string(lines[4])
		if len(key) > 256 {
			key = key[:256] + "…"
		}
	}

	return cmd, key, argc
}

// extractInlineValue 从 RESP inline 行中提取值（去掉 \r\n）。
func extractInlineValue(data []byte) string {
	s := string(data)
	s = strings.TrimRight(s, "\r\n")
	if len(s) > 256 {
		s = s[:256] + "…"
	}
	return s
}
