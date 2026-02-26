// pkg/l7/redis.go
// Redis RESP（REdis Serialization Protocol）协议解析器
package l7

import (
	"bytes"
	"strings"
	"time"

	"observer/pkg/ebpf"
)

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
	// RESP 协议首字节
	return payload[0] == '*' || payload[0] == '+' ||
		payload[0] == '-' || payload[0] == ':' || payload[0] == '$'
}

func (p *RedisParser) Parse(payload []byte, direction uint8, ts time.Time) *ParseResult {
	if len(payload) == 0 {
		return nil
	}

	switch payload[0] {
	case '*':
		// Array: 请求命令（如 *3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar）
		cmd, key := parseRESPArray(payload)
		if cmd == "" {
			return nil
		}
		return &ParseResult{
			Protocol:  ebpf.L7ProtocolRedis,
			ReqType:   ebpf.L7RequestTypeRequest,
			StartTime: ts,
			EndTime:   ts,
			RedisCmd:  cmd,
			RedisKey:  key,
		}

	case '+':
		// Simple String 响应（OK）
		return &ParseResult{
			Protocol:       ebpf.L7ProtocolRedis,
			ReqType:        ebpf.L7RequestTypeResponse,
			StartTime:      ts,
			EndTime:        ts,
			ResponseStatus: 0,
			ResponseCode:   0,
		}

	case '-':
		// Error 响应
		errMsg := strings.TrimRight(string(payload[1:]), "\r\n")
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

	case ':', '$':
		// Integer / Bulk String 响应
		return &ParseResult{
			Protocol:       ebpf.L7ProtocolRedis,
			ReqType:        ebpf.L7RequestTypeResponse,
			StartTime:      ts,
			EndTime:        ts,
			ResponseStatus: 0,
		}
	}
	return nil
}

// parseRESPArray 解析 RESP Array 格式的命令
// 返回命令名和第一个 key
func parseRESPArray(data []byte) (cmd, key string) {
	lines := bytes.Split(data, []byte("\r\n"))
	// lines[0] = "*N"
	// lines[1] = "$M"  (len of cmd)
	// lines[2] = CMD
	// lines[3] = "$K"  (len of key)
	// lines[4] = KEY
	if len(lines) < 3 {
		return "", ""
	}
	if len(lines[0]) < 2 || lines[0][0] != '*' {
		return "", ""
	}
	// 命令在 lines[2]
	if len(lines) >= 3 {
		cmd = strings.ToUpper(string(lines[2]))
	}
	// key 在 lines[4]
	if len(lines) >= 5 {
		key = string(lines[4])
		// 截断过长的 key
		if len(key) > 256 {
			key = key[:256] + "..."
		}
	}
	return cmd, key
}
