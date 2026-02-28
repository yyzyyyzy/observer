// pkg/l7/mysql.go
// MySQL Client/Server Protocol 解析器（MySQL 4.1+ / MySQL 8.0）
//
// ── 协议结构 ─────────────────────────────────────────────────────────────────
//
//   每个数据包（Packet）：
//     ┌──────────────────────────────────────────────┐
//     │  payload_length (3 bytes, LE)                │
//     │  sequence_id   (1 byte)                      │
//     │  payload       (payload_length bytes)         │
//     └──────────────────────────────────────────────┘
//
//   客户端命令包（sequence_id=0）：
//     payload[0] = command_type（见常量定义）
//     payload[1:] = command data（SQL 文本、DB 名称等）
//
//   服务端响应包：
//     OK  packet: payload[0] = 0x00
//     ERR packet: payload[0] = 0xFF，[1:3] 错误码（LE），[3] '#'，[4:9] SQLSTATE，[9:] 消息
//     EOF packet: payload[0] = 0xFE（仅当 payload_length < 9 时为 EOF，否则为结果集数据）
//     ResultSet:  payload[0] = 非以上值 → 字段数（length-encoded integer）
//
// ── 协议识别策略 ─────────────────────────────────────────────────────────────
//
//   CanParse：
//     端口 3306（最强特征，直接返回 true）。
//     无端口时：3 字节 LE 包长 + 已知命令字节的双重校验。
//     必须同时满足：
//       • pktLen > 0 且 pktLen ≤ payload 实际长度 - 4
//       • payload[4] ∈ 已知命令字节集合
//
//   Parse：
//     sequence_id 0 → 命令包（请求）
//     sequence_id > 0 → 响应包（OK / ERR / EOF / ResultSet）
//     对于 COM_QUERY / COM_STMT_PREPARE：提取 SQL 文本并解析 command + table

package l7

import (
	"encoding/binary"
	"strings"
	"time"

	"observer/pkg/ebpf"
)

// ── MySQL 命令字节常量（RFC: https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_command.html）

const (
	comSleep            = 0x00 // 内部使用
	comQuit             = 0x01 // COM_QUIT
	comInitDB           = 0x02 // COM_INIT_DB（USE db）
	comQuery            = 0x03 // COM_QUERY（最常见的 SQL 查询）
	comFieldList        = 0x04
	comCreateDB         = 0x05
	comDropDB           = 0x06
	comRefresh          = 0x07
	comStatistics       = 0x09
	comProcessInfo      = 0x0A
	comConnect          = 0x0B
	comProcessKill      = 0x0C
	comDebug            = 0x0D
	comPing             = 0x0E // COM_PING（心跳）
	comTime             = 0x0F
	comChangeUser       = 0x11
	comStmtPrepare      = 0x16 // COM_STMT_PREPARE（预处理语句）
	comStmtExecute      = 0x17 // COM_STMT_EXECUTE
	comStmtSendLongData = 0x18
	comStmtClose        = 0x19
	comStmtReset        = 0x1A
	comSetOption        = 0x1B
	comStmtFetch        = 0x1C
	comDaemon           = 0x1D
	comResetConnection  = 0x1F
	comCloneClient      = 0x21
)

// MySQL 响应包首字节
const (
	respOK  = 0x00 // OK packet
	respERR = 0xFF // ERR packet
	respEOF = 0xFE // EOF packet（payload_length < 9）
)

// knownCommands 用于 CanParse 无端口时的快速过滤
var knownCommands = map[byte]bool{
	comQuit: true, comInitDB: true, comQuery: true,
	comPing: true, comStmtPrepare: true, comStmtExecute: true,
	comStmtClose: true, comStmtReset: true, comChangeUser: true,
	comResetConnection: true, comFieldList: true, comStatistics: true,
	comRefresh: true, comProcessInfo: true,
}

// MySQLParser MySQL 4.1+ 协议解析器。
type MySQLParser struct{}

func NewMySQLParser() *MySQLParser { return &MySQLParser{} }

func (p *MySQLParser) Protocol() ebpf.L7Protocol { return ebpf.L7ProtocolMySQL }

func (p *MySQLParser) CanParse(payload []byte, srcPort, dstPort uint16) bool {
	if srcPort == 3306 || dstPort == 3306 {
		return true
	}
	if len(payload) < 5 {
		return false
	}
	// 3 字节 LE 包长校验
	pktLen := uint32(payload[0]) | uint32(payload[1])<<8 | uint32(payload[2])<<16
	if pktLen == 0 || int(pktLen)+4 > len(payload) {
		return false
	}
	cmd := payload[4] // sequence_id = payload[3]，命令字节在 payload[4]
	return knownCommands[cmd] || cmd == respOK || cmd == respERR || cmd == respEOF
}

func (p *MySQLParser) Parse(payload []byte, direction uint8, ts time.Time) *ParseResult {
	if len(payload) < 5 {
		return nil
	}
	pktLen := uint32(payload[0]) | uint32(payload[1])<<8 | uint32(payload[2])<<16
	seqID := payload[3]

	if int(pktLen)+4 > len(payload) || pktLen == 0 {
		return nil
	}
	body := payload[4 : 4+pktLen]

	cmd := body[0]

	// ── 命令包（客户端 → 服务端，sequence_id 通常为 0）────────────────────────
	if seqID == 0 {
		switch cmd {
		case comQuery, comStmtPrepare:
			if len(body) < 2 {
				return nil
			}
			sql := strings.TrimSpace(string(body[1:]))
			sqlCmd, table := parseSQLStatement(sql)
			return &ParseResult{
				Protocol:        ebpf.L7ProtocolMySQL,
				ReqType:         ebpf.L7RequestTypeRequest,
				StartTime:       ts,
				EndTime:         ts,
				SQLCmd:          sqlCmd,
				SQLTable:        table,
				RequestResource: table,
				RequestType:     sqlCmd,
			}

		case comInitDB:
			db := strings.TrimSpace(string(body[1:]))
			return &ParseResult{
				Protocol:        ebpf.L7ProtocolMySQL,
				ReqType:         ebpf.L7RequestTypeRequest,
				StartTime:       ts,
				EndTime:         ts,
				SQLCmd:          "USE",
				SQLTable:        db,
				RequestResource: db,
				RequestType:     "USE",
			}

		case comPing:
			return &ParseResult{
				Protocol:    ebpf.L7ProtocolMySQL,
				ReqType:     ebpf.L7RequestTypeRequest,
				StartTime:   ts,
				EndTime:     ts,
				RequestType: "PING",
			}

		case comQuit:
			return &ParseResult{
				Protocol:    ebpf.L7ProtocolMySQL,
				ReqType:     ebpf.L7RequestTypeRequest,
				StartTime:   ts,
				EndTime:     ts,
				RequestType: "QUIT",
			}

		case comStmtExecute:
			return &ParseResult{
				Protocol:    ebpf.L7ProtocolMySQL,
				ReqType:     ebpf.L7RequestTypeRequest,
				StartTime:   ts,
				EndTime:     ts,
				SQLCmd:      "EXECUTE",
				RequestType: "STMT_EXECUTE",
			}
		}
	}

	// ── 响应包（服务端 → 客户端，sequence_id ≥ 1）────────────────────────────
	switch cmd {
	case respOK:
		// OK packet: [0x00][affected_rows:varint][last_insert_id:varint][status_flags:2][warnings:2]
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

	case respERR:
		// ERR packet: [0xFF][error_code:2LE][sql_state_marker:1][sql_state:5][error_msg]
		if len(body) < 4 {
			return nil
		}
		errCode := int32(binary.LittleEndian.Uint16(body[1:3]))
		errMsg := ""
		if len(body) > 9 {
			errMsg = strings.TrimRight(string(body[9:]), "\x00")
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

	case respEOF:
		// EOF packet（payload_length < 9 时才是 EOF，否则是行数据）
		if pktLen < 9 {
			return &ParseResult{
				Protocol:       ebpf.L7ProtocolMySQL,
				ReqType:        ebpf.L7RequestTypeResponse,
				StartTime:      ts,
				EndTime:        ts,
				ResponseStatus: 0,
			}
		}
		// 否则为 ResultSet 行数据，作为会话包处理
		return &ParseResult{
			Protocol:  ebpf.L7ProtocolMySQL,
			ReqType:   ebpf.L7RequestTypeSession,
			StartTime: ts,
			EndTime:   ts,
		}
	}

	return nil
}

// parseSQLStatement 提取 SQL 命令类型（SELECT/INSERT/...）和主表名。
func parseSQLStatement(sql string) (cmd, table string) {
	upper := strings.ToUpper(strings.TrimSpace(sql))

	cmds := []string{
		"SELECT", "INSERT", "UPDATE", "DELETE",
		"CREATE", "DROP", "ALTER", "TRUNCATE",
		"REPLACE", "SHOW", "SET", "USE", "CALL",
		"EXPLAIN", "DESCRIBE", "LOCK", "UNLOCK",
	}
	for _, kw := range cmds {
		if strings.HasPrefix(upper, kw) {
			cmd = kw
			break
		}
	}
	if cmd == "" {
		return "UNKNOWN", ""
	}

	parts := strings.Fields(sql)
	switch cmd {
	case "SELECT", "DELETE":
		for i, p := range parts {
			if strings.ToUpper(p) == "FROM" && i+1 < len(parts) {
				table = cleanSQLIdent(parts[i+1])
				break
			}
		}
	case "INSERT", "REPLACE":
		for i, p := range parts {
			if strings.ToUpper(p) == "INTO" && i+1 < len(parts) {
				table = cleanSQLIdent(parts[i+1])
				break
			}
		}
	case "UPDATE":
		if len(parts) > 1 {
			table = cleanSQLIdent(parts[1])
		}
	case "CREATE", "DROP", "ALTER", "TRUNCATE":
		// CREATE TABLE xxx / DROP TABLE xxx / ALTER TABLE xxx
		for i, p := range parts {
			if strings.ToUpper(p) == "TABLE" && i+1 < len(parts) {
				table = cleanSQLIdent(parts[i+1])
				break
			}
		}
	}
	return cmd, table
}

// cleanSQLIdent 去除表名的反引号、括号、分号等修饰符。
func cleanSQLIdent(s string) string {
	s = strings.TrimRight(s, ",(;")
	s = strings.Trim(s, "`\"")
	// 去除 schema 前缀（db.table → table）
	if idx := strings.LastIndex(s, "."); idx >= 0 {
		s = s[idx+1:]
	}
	return s
}

// readLenEncInt 解析 MySQL length-encoded integer（RFC: 15.1.3）
func readLenEncInt(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	switch first := b[0]; {
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
	default: // 0xFE
		if len(b) < 9 {
			return 0, 1
		}
		return binary.LittleEndian.Uint64(b[1:9]), 9
	}
}
