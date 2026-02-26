// pkg/l7/mysql.go
// MySQL 协议解析器（MySQL Client/Server Protocol 4.1+）
package l7

import (
	"encoding/binary"
	"strings"
	"time"

	"observer/pkg/ebpf"
)

// MySQL 命令字节
const (
	mysqlComQuery       = 0x03
	mysqlComStmtPrepare = 0x16
	mysqlComStmtExecute = 0x17
	mysqlComQuit        = 0x01
	mysqlComInitDB      = 0x02
	mysqlComPing        = 0x0E
)

// MySQL 响应包类型
const (
	mysqlOK    = 0x00
	mysqlErr   = 0xFF
	mysqlEOF   = 0xFE
)

type MySQLParser struct{}

func NewMySQLParser() *MySQLParser { return &MySQLParser{} }

func (p *MySQLParser) Protocol() ebpf.L7Protocol { return ebpf.L7ProtocolMySQL }

func (p *MySQLParser) CanParse(payload []byte, srcPort, dstPort uint16) bool {
	// 端口 heuristic
	if srcPort == 3306 || dstPort == 3306 {
		return true
	}
	// MySQL 包格式：3字节长度 + 1字节序列号 + 内容
	if len(payload) < 5 {
		return false
	}
	pktLen := uint32(payload[0]) | uint32(payload[1])<<8 | uint32(payload[2])<<16
	// 包长度合理性检查（>0 且 <= payload 剩余大小）
	return pktLen > 0 && pktLen <= uint32(len(payload)-4)
}

func (p *MySQLParser) Parse(payload []byte, direction uint8, ts time.Time) *ParseResult {
	if len(payload) < 5 {
		return nil
	}
	// MySQL packet header: [payload_length:3][seq_id:1]
	pktLen := uint32(payload[0]) | uint32(payload[1])<<8 | uint32(payload[2])<<16
	seqID := payload[3]
	_ = seqID

	if int(4+pktLen) > len(payload) {
		return nil
	}
	body := payload[4 : 4+pktLen]
	if len(body) == 0 {
		return nil
	}

	cmd := body[0]

	switch cmd {
	case mysqlComQuery, mysqlComStmtPrepare:
		if len(body) < 2 {
			return nil
		}
		sql := string(body[1:])
		sqlCmd, table := parseSQLStatement(sql)
		return &ParseResult{
			Protocol:  ebpf.L7ProtocolMySQL,
			ReqType:   ebpf.L7RequestTypeRequest,
			StartTime: ts,
			EndTime:   ts,
			SQLCmd:    sqlCmd,
			SQLTable:  table,
		}

	case mysqlOK:
		// OK packet: [0x00][affected_rows:varint][last_insert_id:varint]...
		if len(body) < 3 {
			return nil
		}
		affectedRows, _ := readLenEncInt(body[1:])
		return &ParseResult{
			Protocol:       ebpf.L7ProtocolMySQL,
			ReqType:        ebpf.L7RequestTypeResponse,
			StartTime:      ts,
			EndTime:        ts,
			SQLRows:        int64(affectedRows),
			ResponseStatus: 0,
			ResponseCode:   0,
		}

	case mysqlErr:
		// ERR packet: [0xFF][error_code:2][sql_state_marker:1][sql_state:5][error_msg]
		if len(body) < 9 {
			return nil
		}
		errCode := int32(binary.LittleEndian.Uint16(body[1:3]))
		errMsg := ""
		if len(body) > 9 {
			errMsg = string(body[9:])
		}
		return &ParseResult{
			Protocol:       ebpf.L7ProtocolMySQL,
			ReqType:        ebpf.L7RequestTypeResponse,
			StartTime:      ts,
			EndTime:        ts,
			SQLErrno:       errCode,
			ResponseStatus: 2,
			ResponseCode:   int64(errCode),
			ResponseErrMsg: errMsg,
		}
	}

	return nil
}

// parseSQLStatement 提取 SQL 命令类型和主表名
func parseSQLStatement(sql string) (cmd, table string) {
	sql = strings.TrimSpace(sql)
	upper := strings.ToUpper(sql)

	keywords := []string{"SELECT", "INSERT", "UPDATE", "DELETE", "CREATE",
		"DROP", "ALTER", "TRUNCATE", "REPLACE", "SHOW", "USE", "SET"}

	for _, kw := range keywords {
		if strings.HasPrefix(upper, kw) {
			cmd = kw
			break
		}
	}
	if cmd == "" {
		return "UNKNOWN", ""
	}

	// 简单提取主表名
	parts := strings.Fields(sql)
	switch cmd {
	case "SELECT":
		// SELECT ... FROM <table>
		for i, p := range parts {
			if strings.ToUpper(p) == "FROM" && i+1 < len(parts) {
				table = stripBackticks(parts[i+1])
				break
			}
		}
	case "INSERT", "REPLACE":
		// INSERT INTO <table>
		for i, p := range parts {
			if strings.ToUpper(p) == "INTO" && i+1 < len(parts) {
				table = stripBackticks(parts[i+1])
				break
			}
		}
	case "UPDATE":
		if len(parts) > 1 {
			table = stripBackticks(parts[1])
		}
	case "DELETE":
		for i, p := range parts {
			if strings.ToUpper(p) == "FROM" && i+1 < len(parts) {
				table = stripBackticks(parts[i+1])
				break
			}
		}
	}
	return cmd, table
}

func stripBackticks(s string) string {
	s = strings.TrimSuffix(s, ",")
	s = strings.Trim(s, "`")
	return s
}

// readLenEncInt 解析 MySQL length-encoded integer
func readLenEncInt(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	first := b[0]
	switch {
	case first <= 0xFB:
		return uint64(first), 1
	case first == 0xFC:
		if len(b) < 3 {
			return 0, 1
		}
		return uint64(b[1]) | uint64(b[2])<<8, 3
	case first == 0xFD:
		if len(b) < 4 {
			return 0, 1
		}
		return uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16, 4
	default:
		if len(b) < 9 {
			return 0, 1
		}
		return binary.LittleEndian.Uint64(b[1:9]), 9
	}
}
