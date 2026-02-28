// pkg/l7/parser.go
// L7 协议解析框架
//
// 协议识别策略（对齐 DeepFlow）：
//
//   阶段一 — Infer（推断）：
//     CanParse() 基于端口 + magic bytes 做快速预判，O(1)，在热路径上调用。
//     端口专属协议直接返回 true，无需检查 payload。
//     通用端口协议必须同时满足结构特征才可返回 true。
//
//   阶段二 — Detect（精确解析）：
//     Parse() 按照协议规范做严格解析，失败时返回 nil。
//     CanParse 通过但 Parse 返回 nil 时，继续尝试下一个解析器。
//
//   注册顺序 = 优先级（越早注册越先匹配）：
//     1. 端口专属、确定性最高：DNS(53) Redis(6379) MySQL(3306) Kafka(9092)
//     2. Magic bytes 确定性高：HTTP/1.x
//     3. 结构特征复杂：HTTP/2（preface or 严格帧头）
//     4. 依赖上层特征：gRPC（content-type: application/grpc）
//     5. 兜底（TLS uprobe 明文）：TLSParser
//     6. 消息队列：MQTT（port=1883/8883 or CONNECT magic）
//
//   TCP/UDP/ICMP 传输层状态机在 pkg/flow 层维护，不在此处处理。
//   WASM 仅用于企业自定义协议，不覆盖任何内置协议。

package l7

import (
	"context"
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"observer/pkg/ebpf"
	"observer/pkg/storage"
)

// ── ParseResult ───────────────────────────────────────────────────────────────

// ParseResult 单次 L7 请求/响应的解析结果。
// 字段设计对齐 DeepFlow l7_flow_log schema。
type ParseResult struct {
	Protocol  ebpf.L7Protocol
	ReqType   ebpf.L7RequestType
	StartTime time.Time
	EndTime   time.Time

	// 响应时延（请求到响应的微秒数），由 Registry 在配对后填充
	ResponseUs uint32

	// 协议无关抽象字段（DeepFlow: request_resource / request_type）
	RequestResource string // 资源标识符（HTTP path、SQL table、Redis key、Kafka topic 等）
	RequestType     string // 操作类型（HTTP method、SQL command、Redis command 等）

	// ── HTTP / HTTP2 / gRPC ──
	HTTPMethod       string
	HTTPPath         string
	HTTPHost         string
	HTTPUserAgent    string
	HTTPReferer      string
	HTTPStatusCode   uint16
	HTTPReqBodySize  int64
	HTTPRespBodySize int64
	GRPCStatusCode   uint32

	// ── MySQL ──
	SQLCmd   string // SELECT / INSERT / UPDATE / DELETE / ...
	SQLTable string // 主表名
	SQLRows  int64  // affected_rows（来自 OK packet）
	SQLErrno int32  // 错误码（来自 ERR packet）

	// ── Redis ──
	RedisCmd    string
	RedisKey    string
	RedisErrMsg string

	// ── DNS ──
	DNSQueryName string
	DNSQueryType uint16
	DNSRCode     uint16
	DNSAnswerIP  string

	// ── Kafka ──
	KafkaAPIKey    uint16
	KafkaTopic     string
	KafkaPartition int32
	KafkaCorrelID  int32
	KafkaErrCode   int16
	KafkaMsgCount  int32
	KafkaMsgBytes  int64

	// ── MQTT ──
	MQTTPacketType  uint8  // 1=CONNECT 2=CONNACK 3=PUBLISH ... 14=DISCONNECT
	MQTTTopic       string
	MQTTClientID    string
	MQTTQoS         uint8
	MQTTReturnCode  uint8
	MQTTPayloadSize int32

	// ── ICMP / Ping ──
	ICMPType  uint8
	ICMPCode  uint8
	ICMPSeq   uint16
	ICMPID    uint16
	PingRTTUs uint32

	// ── TLS 握手元数据 ──
	TLSSNIName     string // Server Name Indication
	TLSALPN        string // Application-Layer Protocol Negotiation（h2 / http/1.1）
	TLSVersion     string // TLS 1.2 / TLS 1.3
	TLSCipherSuite string // 协商的密码套件

	// ── 通用响应状态 ──
	// 0=success  1=client_error（4xx）  2=server_error（5xx / protocol error）
	ResponseStatus uint8
	ResponseCode   int64
	ResponseErrMsg string

	// ── WASM 扩展属性（JSON 字符串） ──
	ExtAttributes string
}

// ── Parser 接口 ───────────────────────────────────────────────────────────────

// Parser L7 协议解析器接口。
// 每种协议实现一个 Parser，通过 Registry.Register 注册。
type Parser interface {
	// Protocol 返回本解析器对应的协议枚举值。
	Protocol() ebpf.L7Protocol

	// CanParse 快速预判：payload 是否可能属于本协议。
	// 实现要求：
	//   - 纯端口匹配时直接返回 true（端口专属协议）
	//   - 通用端口时必须同时检查 magic bytes / 报头结构
	//   - 不得有任何内存分配，O(1) 时间复杂度
	CanParse(payload []byte, srcPort, dstPort uint16) bool

	// Parse 精确解析 payload。
	// direction: 0=ingress（进入本机）  1=egress（离开本机）
	// ts: BPF 捕获时间戳
	// 返回 nil 表示解析失败（CanParse 通过但结构不符合协议规范）。
	Parse(payload []byte, direction uint8, ts time.Time) *ParseResult
}

// ── Session：请求/响应配对 ────────────────────────────────────────────────────

// sessionKey 五元组，用于配对同一 TCP 连接上的请求和响应。
// 请求 key = (clientIP, serverIP, clientPort, serverPort)
// 响应 key = (serverIP, clientIP, serverPort, clientPort)  → 查 sessions 时翻转
type sessionKey struct {
	srcIP   uint32
	dstIP   uint32
	srcPort uint16
	dstPort uint16
	proto   uint8
}

type pendingRequest struct {
	result *ParseResult
	ts     time.Time // 插入时间，用于 GC 超时判断
}

// ── Registry ─────────────────────────────────────────────────────────────────

// Registry 管理所有 L7 协议解析器。
// 职责：
//   - 维护解析器优先级列表
//   - 驱动 CanParse → Parse 两段式协议识别
//   - 维护会话表进行请求/响应配对
//   - 将配对结果写入 ClickHouse l7_flow_log
type Registry struct {
	parsers []Parser    // 有序列表，索引越小优先级越高
	mu      sync.RWMutex

	sessions map[sessionKey]*pendingRequest
	sessmu   sync.Mutex

	// portFilter Go 层端口黑名单（BPF 层过滤的补充）。
	// nil 时不做端口过滤（向后兼容）。
	portFilter *PortFilter

	store *storage.ClickHouseClient
}

// NewRegistry 构建并初始化协议注册表（不带端口过滤）。
// 内置解析器按优先级顺序注册；WASM 自定义解析器通过 Register 方法追加。
func NewRegistry(store *storage.ClickHouseClient) *Registry {
	return NewRegistryWithFilter(store, nil)
}

// NewRegistryWithFilter 构建协议注册表，同时注入端口过滤器。
// filter 为 nil 时等同于 NewRegistry，不做端口过滤。
//
// 推荐从 config.EffectiveSkipPorts() 构建 filter：
//
//	filter := l7.NewPortFilter(cfg.EffectiveSkipPorts())
//	registry := l7.NewRegistryWithFilter(chClient, filter)
func NewRegistryWithFilter(store *storage.ClickHouseClient, filter *PortFilter) *Registry {
	r := &Registry{
		sessions:   make(map[sessionKey]*pendingRequest),
		store:      store,
		portFilter: filter,
	}

	// ── 注册顺序即优先级 ──────────────────────────────────────────────────────
	//
	// 端口专属协议（确定性最高）：
	r.Register(NewDNSParser())    // UDP/TCP port=53，magic: 固定 12 字节头部
	r.Register(NewRedisParser())  // port=6379，magic: RESP 首字节 * + - : $
	r.Register(NewMySQLParser())  // port=3306，magic: 3 字节 LE 包长 + 序列号 + 命令字节
	r.Register(NewKafkaParser())  // port=9092/9093，magic: 4 字节大端长度 + API Key 范围
	r.Register(NewMQTTParser())   // port=1883/8883，magic: CONNECT 0x10 固定头

	// 结构特征协议（Magic bytes 确定性高）：
	r.Register(NewHTTPParser())   // magic: "GET "/"POST "/"HTTP/" 等 ASCII 前缀
	r.Register(NewHTTP2Parser())  // magic: 24 字节 PRI * preface 或严格帧头校验
	r.Register(NewGRPCParser())   // 依赖 HTTP/2 HEADERS 中 content-type: application/grpc

	// TLS 兜底（处理 SSL uprobe 捕获的已解密明文）：
	r.Register(NewTLSParser())

	go r.sessionGCLoop(context.Background())

	return r
}

// Register 向注册表末尾追加一个解析器（低优先级）。
// WASM 自定义解析器通过此方法注册，始终排在内置解析器之后。
func (r *Registry) Register(p Parser) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.parsers = append(r.parsers, p)
	log.WithField("protocol", p.Protocol()).Debug("L7 parser registered")
}

// HandleL7Event 处理来自 BPF 的 L7 载荷事件。
// 事件携带已捕获的 payload（最多 4096 字节），函数负责：
//   1. Go 层端口过滤（portFilter），对黑名单端口立即丢弃，不走 parser
//   2. 依优先级遍历解析器，找到第一个能匹配的
//   3. 根据 ReqType 决定缓存请求 or 配对响应
//   4. 配对成功后计算 ResponseUs 并写入存储
func (r *Registry) HandleL7Event(ev *ebpf.L7Event) {
	if ev.PayloadSize == 0 {
		return
	}

	// ── Go 层端口过滤（BPF 层的补充）────────────────────────────────────────
	// 对自身服务端口、加密协议端口等直接丢弃，不进入任何 parser。
	// BPF 层已过滤一部分，Go 层此处是热路径的第二道防线（O(1) 数组查表）。
	if r.portFilter != nil && r.portFilter.ShouldSkip(ev.SPort, ev.DPort) {
		return
	}
	sz := ev.PayloadSize
	if sz > uint32(len(ev.Payload)) {
		sz = uint32(len(ev.Payload))
	}
	payload := ev.Payload[:sz]

	r.mu.RLock()
	parsers := r.parsers
	r.mu.RUnlock()

	for _, p := range parsers {
		if !p.CanParse(payload, ev.SPort, ev.DPort) {
			continue
		}

		result := p.Parse(payload, ev.Direction, time.Unix(0, int64(ev.TimestampNs)))
		if result == nil {
			// CanParse 通过但 Parse 失败：此 payload 不符合该协议规范，继续尝试下一个
			continue
		}

		key := sessionKey{
			srcIP:   ev.SAddr,
			dstIP:   ev.DAddr,
			srcPort: ev.SPort,
			dstPort: ev.DPort,
			proto:   ev.Protocol,
		}

		switch result.ReqType {
		case ebpf.L7RequestTypeRequest:
			r.sessmu.Lock()
			r.sessions[key] = &pendingRequest{result: result, ts: time.Now()}
			r.sessmu.Unlock()

		case ebpf.L7RequestTypeResponse:
			// 响应的 key 是请求 key 的翻转（src/dst 互换）
			reqKey := sessionKey{
				srcIP:   ev.DAddr,
				dstIP:   ev.SAddr,
				srcPort: ev.DPort,
				dstPort: ev.SPort,
				proto:   ev.Protocol,
			}
			r.sessmu.Lock()
			pending, ok := r.sessions[reqKey]
			if ok {
				delete(r.sessions, reqKey)
			}
			r.sessmu.Unlock()

			if ok {
				result.StartTime = pending.result.StartTime
				result.ResponseUs = uint32(result.EndTime.Sub(result.StartTime).Microseconds())
				mergeRequestFields(result, pending.result)
			}
			r.emitL7Log(ev, result)

		case ebpf.L7RequestTypeSession:
			// 无需配对的协议（DNS、ICMP 等单包会话）直接写入
			r.emitL7Log(ev, result)
		}
		return // 一个事件只匹配第一个成功解析的协议
	}

	log.WithFields(log.Fields{
		"sport":       ev.SPort,
		"dport":       ev.DPort,
		"payload_len": ev.PayloadSize,
		"hex":         fmt.Sprintf("%X", payload[:clampInt(len(payload), 16)]),
	}).Debug("L7 event: no parser matched")
}

// mergeRequestFields 将请求侧字段合并进响应记录。
// 仅在字段为零值时覆盖，避免响应包中已有的字段被覆盖。
func mergeRequestFields(resp, req *ParseResult) {
	if resp.HTTPMethod == "" {
		resp.HTTPMethod = req.HTTPMethod
		resp.HTTPPath = req.HTTPPath
		resp.HTTPHost = req.HTTPHost
		resp.HTTPUserAgent = req.HTTPUserAgent
		resp.HTTPReferer = req.HTTPReferer
		resp.HTTPReqBodySize = req.HTTPReqBodySize
	}
	if resp.SQLCmd == "" {
		resp.SQLCmd = req.SQLCmd
		resp.SQLTable = req.SQLTable
	}
	if resp.RedisCmd == "" {
		resp.RedisCmd = req.RedisCmd
		resp.RedisKey = req.RedisKey
	}
	if resp.KafkaTopic == "" {
		resp.KafkaTopic = req.KafkaTopic
		resp.KafkaAPIKey = req.KafkaAPIKey
		resp.KafkaPartition = req.KafkaPartition
		resp.KafkaCorrelID = req.KafkaCorrelID
		resp.KafkaMsgCount = req.KafkaMsgCount
		resp.KafkaMsgBytes = req.KafkaMsgBytes
	}
	if resp.MQTTTopic == "" {
		resp.MQTTTopic = req.MQTTTopic
		resp.MQTTClientID = req.MQTTClientID
		resp.MQTTQoS = req.MQTTQoS
	}
	if resp.RequestResource == "" {
		resp.RequestResource = req.RequestResource
		resp.RequestType = req.RequestType
	}
}

func (r *Registry) emitL7Log(ev *ebpf.L7Event, result *ParseResult) {
	if r.store == nil {
		return
	}
	evTime := time.Unix(0, int64(ev.TimestampNs))
	if result.StartTime.IsZero() {
		result.StartTime = evTime
	}
	if result.EndTime.IsZero() {
		result.EndTime = evTime
	}
	r.store.WriteL7FlowLog(storage.L7FlowLog{
		StartTime:  result.StartTime,
		EndTime:    result.EndTime,
		ResponseUs: result.ResponseUs,

		SrcIP:    storage.SafeIPv4(ebpf.Uint32ToIP(ev.SAddr)),
		DstIP:    storage.SafeIPv4(ebpf.Uint32ToIP(ev.DAddr)),
		SrcPort:  ev.SPort,
		DstPort:  ev.DPort,
		Protocol: ev.Protocol,

		PID:         ev.PID,
		ProcessName: ebpf.ParseCommField(ev.Comm),

		L7Protocol: uint16(result.Protocol),
		L7ProtName: result.Protocol.String(),
		ReqType:    uint8(result.ReqType),

		RequestResource: result.RequestResource,
		RequestType:     result.RequestType,

		HTTPMethod:       result.HTTPMethod,
		HTTPPath:         result.HTTPPath,
		HTTPHost:         result.HTTPHost,
		HTTPUserAgent:    result.HTTPUserAgent,
		HTTPReferer:      result.HTTPReferer,
		HTTPStatusCode:   result.HTTPStatusCode,
		HTTPReqBodySize:  result.HTTPReqBodySize,
		HTTPRespBodySize: result.HTTPRespBodySize,
		GRPCStatusCode:   result.GRPCStatusCode,

		SQLCmd:   result.SQLCmd,
		SQLTable: result.SQLTable,
		SQLRows:  result.SQLRows,
		SQLErrno: result.SQLErrno,

		RedisCmd:    result.RedisCmd,
		RedisKey:    result.RedisKey,
		RedisErrMsg: result.RedisErrMsg,

		DNSQueryName: result.DNSQueryName,
		DNSQueryType: result.DNSQueryType,
		DNSRCode:     result.DNSRCode,
		DNSAnswerIP:  result.DNSAnswerIP,

		KafkaAPIKey:    result.KafkaAPIKey,
		KafkaTopic:     result.KafkaTopic,
		KafkaPartition: result.KafkaPartition,
		KafkaCorrelID:  result.KafkaCorrelID,
		KafkaErrCode:   result.KafkaErrCode,
		KafkaMsgCount:  result.KafkaMsgCount,
		KafkaMsgBytes:  result.KafkaMsgBytes,

		MQTTPacketType:  result.MQTTPacketType,
		MQTTTopic:       result.MQTTTopic,
		MQTTClientID:    result.MQTTClientID,
		MQTTQoS:         result.MQTTQoS,
		MQTTReturnCode:  result.MQTTReturnCode,
		MQTTPayloadSize: result.MQTTPayloadSize,

		ICMPType:  result.ICMPType,
		ICMPCode:  result.ICMPCode,
		ICMPSeq:   result.ICMPSeq,
		ICMPID:    result.ICMPID,
		PingRTTUs: result.PingRTTUs,

		TLSSNIName:     result.TLSSNIName,
		TLSALPN:        result.TLSALPN,
		TLSVersion:     result.TLSVersion,
		TLSCipherSuite: result.TLSCipherSuite,

		ResponseStatus: result.ResponseStatus,
		ResponseCode:   result.ResponseCode,
		ResponseErrMsg: result.ResponseErrMsg,

		ExtAttributes: result.ExtAttributes,
	})
}

// sessionGCLoop 定期清理超时未配对的请求（默认 10 秒超时）。
func (r *Registry) sessionGCLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			timeout := time.Now().Add(-10 * time.Second)
			r.sessmu.Lock()
			for k, v := range r.sessions {
				if v.ts.Before(timeout) {
					delete(r.sessions, k)
				}
			}
			r.sessmu.Unlock()
		}
	}
}

// ── 内联工具函数 ──────────────────────────────────────────────────────────────

func clampInt(v, max int) int {
	if v > max {
		return max
	}
	return v
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func minUint32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}
