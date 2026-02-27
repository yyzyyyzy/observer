// pkg/l7/parser.go
// L7 协议解析框架 — 内置 HTTP1/2、gRPC、MySQL、Redis、DNS、Kafka、Ping 解析器，
// 支持通过 WASM 插件扩展私有协议。

package l7

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"observer/pkg/ebpf"
	"observer/pkg/storage"
)

// ── ParseResult L7 解析结果（单次请求/响应） ─────────────────────────────────

type ParseResult struct {
	Protocol   ebpf.L7Protocol
	ReqType    ebpf.L7RequestType
	StartTime  time.Time
	EndTime    time.Time
	ResponseUs uint32

	// 协议无关抽象（对齐 DeepFlow request_resource / request_type）
	RequestResource string
	RequestType     string

	// HTTP / HTTP2 / gRPC
	HTTPMethod       string
	HTTPPath         string
	HTTPHost         string
	HTTPUserAgent    string
	HTTPReferer      string
	HTTPStatusCode   uint16
	HTTPReqBodySize  int64
	HTTPRespBodySize int64
	GRPCStatusCode   uint32

	// MySQL
	SQLCmd   string
	SQLTable string
	SQLRows  int64
	SQLErrno int32

	// Redis
	RedisCmd    string
	RedisKey    string
	RedisErrMsg string

	// DNS
	DNSQueryName string
	DNSQueryType uint16
	DNSRCode     uint16
	DNSAnswerIP  string

	// Kafka
	KafkaAPIKey    uint16
	KafkaTopic     string
	KafkaPartition int32
	KafkaCorrelID  int32
	KafkaErrCode   int16
	KafkaMsgCount  int32
	KafkaMsgBytes  int64

	// ICMP / Ping
	ICMPType  uint8
	ICMPCode  uint8
	ICMPSeq   uint16
	ICMPID    uint16
	PingRTTUs uint32

	// TLS（握手元数据）
	TLSSNIName     string
	TLSALPN        string
	TLSVersion     string
	TLSCipherSuite string

	// 通用响应状态（0=success 1=client_error 2=server_error）
	ResponseStatus uint8
	ResponseCode   int64
	ResponseErrMsg string

	// WASM 扩展属性（JSON）
	ExtAttributes string
}

// ── Parser 接口 ───────────────────────────────────────────────────────────────

// Parser L7 协议解析器接口。每种协议实现一个 Parser，注册到 Registry。
type Parser interface {
	Protocol() ebpf.L7Protocol
	// CanParse 快速判断 payload 是否属于本协议（magic bytes / 端口启发式）
	CanParse(payload []byte, srcPort, dstPort uint16) bool
	// Parse 解析载荷。direction: 0=ingress 1=egress。返回 nil 表示解析失败。
	Parse(payload []byte, direction uint8, ts time.Time) *ParseResult
}

// ── Session：请求/响应配对追踪 ───────────────────────────────────────────────

type sessionKey struct {
	srcIP   uint32
	dstIP   uint32
	srcPort uint16
	dstPort uint16
	proto   uint8
}

type pendingRequest struct {
	result *ParseResult
	ts     time.Time
}

// ── Registry：协议解析器注册表 ───────────────────────────────────────────────

// Registry 管理所有协议解析器，处理请求/响应配对，向 ClickHouse 写入 l7_flow_log。
type Registry struct {
	parsers []Parser
	mu      sync.RWMutex

	sessions map[sessionKey]*pendingRequest
	sessmu   sync.Mutex

	store *storage.ClickHouseClient
}

func NewRegistry(store *storage.ClickHouseClient) *Registry {
	r := &Registry{
		sessions: make(map[sessionKey]*pendingRequest),
		store:    store,
	}

	// 内置解析器（按优先级注册：magic bytes 确定性高的优先）
	r.Register(NewHTTPParser())
	r.Register(NewHTTP2Parser())
	r.Register(NewGRPCParser())
	r.Register(NewMySQLParser())
	r.Register(NewRedisParser())
	r.Register(NewDNSParser())
	r.Register(NewKafkaParser())
	r.Register(NewPingParser())
	r.Register(NewTLSParser())

	go r.sessionGCLoop(context.Background())

	return r
}

func (r *Registry) Register(p Parser) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.parsers = append(r.parsers, p)
	log.WithField("protocol", p.Protocol()).Info("L7 parser registered")
}

// HandleL7Event 处理来自 BPF 的 L7 载荷事件。
func (r *Registry) HandleL7Event(ev *ebpf.L7Event) {
	if ev.PayloadSize == 0 {
		return
	}
	payload := ev.Payload[:minUint32(ev.PayloadSize, uint32(len(ev.Payload)))]

	r.mu.RLock()
	parsers := r.parsers
	r.mu.RUnlock()

	for _, p := range parsers {
		if !p.CanParse(payload, ev.SPort, ev.DPort) {
			continue
		}

		result := p.Parse(payload, ev.Direction, time.Unix(0, int64(ev.TimestampNs)))
		if result == nil {
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
			r.sessmu.Lock()
			reqKey := sessionKey{
				srcIP:   ev.DAddr,
				dstIP:   ev.SAddr,
				srcPort: ev.DPort,
				dstPort: ev.SPort,
				proto:   ev.Protocol,
			}
			pending, ok := r.sessions[reqKey]
			if ok {
				delete(r.sessions, reqKey)
			}
			r.sessmu.Unlock()

			if ok {
				// 合并请求侧字段到响应记录
				result.StartTime = pending.result.StartTime
				result.ResponseUs = uint32(result.EndTime.Sub(result.StartTime).Microseconds())
				mergeRequestFields(result, pending.result)
			}
			r.emitL7Log(ev, result)

		case ebpf.L7RequestTypeSession:
			// DNS、Ping 等一问一答协议：直接输出
			r.emitL7Log(ev, result)
		}
		break // 一个事件只匹配第一个能解析的协议
	}
}

// mergeRequestFields 将请求侧解析结果合并到响应记录中。
func mergeRequestFields(resp, req *ParseResult) {
	// HTTP / gRPC
	if resp.HTTPMethod == "" {
		resp.HTTPMethod = req.HTTPMethod
		resp.HTTPPath = req.HTTPPath
		resp.HTTPHost = req.HTTPHost
		resp.HTTPUserAgent = req.HTTPUserAgent
		resp.HTTPReferer = req.HTTPReferer
		resp.HTTPReqBodySize = req.HTTPReqBodySize
		resp.GRPCStatusCode = req.GRPCStatusCode
	}
	// MySQL
	if resp.SQLCmd == "" {
		resp.SQLCmd = req.SQLCmd
		resp.SQLTable = req.SQLTable
	}
	// Redis
	if resp.RedisCmd == "" {
		resp.RedisCmd = req.RedisCmd
		resp.RedisKey = req.RedisKey
	}
	// Kafka
	if resp.KafkaTopic == "" {
		resp.KafkaTopic = req.KafkaTopic
		resp.KafkaAPIKey = req.KafkaAPIKey
		resp.KafkaPartition = req.KafkaPartition
		resp.KafkaCorrelID = req.KafkaCorrelID
		resp.KafkaMsgCount = req.KafkaMsgCount
		resp.KafkaMsgBytes = req.KafkaMsgBytes
	}
	// 请求资源抽象
	if resp.RequestResource == "" {
		resp.RequestResource = req.RequestResource
		resp.RequestType = req.RequestType
	}
}

func (r *Registry) emitL7Log(ev *ebpf.L7Event, result *ParseResult) {
	if r.store == nil {
		return
	}
	// 确保时间字段有效：BPF 事件时间戳作为兜底
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

// sessionGCLoop 清理超时未配对的请求。
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

func minUint32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}
