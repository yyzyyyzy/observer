// pkg/collector/l7_meta_dispatcher.go — 内核态 L7 协议推断事件分发器
//
// 接收来自 l7_inference_tracer.c 的元数据事件（L7MetaEvent），
// 将已识别的协议元数据直接写入 ClickHouse，无需原始 payload 解析。
//
// 这是 TCP L7 全量 payload 路径（l7_tracer → Registry → parser）的高效替代：
//   - 对于已知高频协议（HTTP/MySQL/Redis/DNS/Kafka），直接使用内核推断结果
//   - 对于 BPF 未能推断的协议，继续走用户态 parser 兜底
//
// 写入 storage 时会做请求/响应配对（仅 HTTP/MySQL/Redis/Kafka 需要），
// DNS/MQTT 等 session 类型直接写入。

package collector

import (
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"observer/pkg/ebpf"
	"observer/pkg/storage"
)

// sessionKey 配对用的五元组键
type metaSessionKey struct {
	srcIP   uint32
	dstIP   uint32
	srcPort uint16
	dstPort uint16
	proto   uint8
}

type metaPendingReq struct {
	event *ebpf.L7MetaEvent
	ts    time.Time
}

// L7MetaDispatcher 处理内核态 L7 推断结果
type L7MetaDispatcher struct {
	store *storage.ClickHouseClient

	mu       sync.Mutex
	sessions map[metaSessionKey]*metaPendingReq
}

// NewL7MetaDispatcher 构建分发器并启动会话 GC
func NewL7MetaDispatcher(store *storage.ClickHouseClient) *L7MetaDispatcher {
	d := &L7MetaDispatcher{
		store:    store,
		sessions: make(map[metaSessionKey]*metaPendingReq),
	}
	go d.gcLoop()
	return d
}

// HandleL7MetaEvent 实现 ebpf.L7MetaEventHandler 接口
func (d *L7MetaDispatcher) HandleL7MetaEvent(ev *ebpf.L7MetaEvent) {
	if d.store == nil {
		return
	}
	now := ev.StartTime()

	switch ev.ReqType {
	case 1: // request
		key := metaSessionKey{
			srcIP: ev.SAddr, dstIP: ev.DAddr,
			srcPort: ev.SPort, dstPort: ev.DPort,
			proto: ev.Proto,
		}
		d.mu.Lock()
		d.sessions[key] = &metaPendingReq{event: ev, ts: now}
		d.mu.Unlock()

	case 2: // response
		reqKey := metaSessionKey{
			srcIP: ev.DAddr, dstIP: ev.SAddr,
			srcPort: ev.DPort, dstPort: ev.SPort,
			proto: ev.Proto,
		}
		d.mu.Lock()
		pending, ok := d.sessions[reqKey]
		if ok {
			delete(d.sessions, reqKey)
		}
		d.mu.Unlock()

		var responseUs uint32
		var startTime time.Time
		if ok {
			startTime = pending.event.StartTime()
			responseUs = uint32(now.Sub(startTime).Microseconds())
			d.writeMetaLog(pending.event, ev, startTime, now, responseUs)
		} else {
			d.writeMetaLog(nil, ev, now, now, 0)
		}

	case 3: // session（DNS 等无需配对）
		d.writeMetaLog(ev, nil, now, now, 0)

	default:
		log.WithField("req_type", ev.ReqType).Debug("L7 meta: unknown req_type")
	}
}

// writeMetaLog 将推断结果写入 ClickHouse
func (d *L7MetaDispatcher) writeMetaLog(
	req, resp *ebpf.L7MetaEvent,
	startTime, endTime time.Time,
	responseUs uint32,
) {
	// 选取主事件（request 为主，session 也是 req）
	primary := req
	if primary == nil {
		primary = resp
	}
	if primary == nil {
		return
	}

	log := storage.L7FlowLog{
		StartTime:  startTime,
		EndTime:    endTime,
		ResponseUs: responseUs,

		SrcIP:    storage.SafeIPv4(ebpf.Uint32ToIP(primary.SAddr)),
		DstIP:    storage.SafeIPv4(ebpf.Uint32ToIP(primary.DAddr)),
		SrcPort:  primary.SPort,
		DstPort:  primary.DPort,
		Protocol: primary.Proto,

		PID:         primary.PID,
		ProcessName: ebpf.ParseCommField(primary.Comm),

		L7Protocol: uint16(ebpf.L7Protocol(primary.L7Proto)),
		L7ProtName: ebpf.L7MetaProtoString(primary.L7Proto),
		ReqType:    primary.ReqType,
	}

	switch primary.L7Proto {
	case 1: // HTTP
		if req != nil {
			log.HTTPMethod = httpMethodString(req.HTTPMethod)
			// URL hash 无法反向，仅记录 hash 值到 RequestResource
		}
		if resp != nil {
			log.HTTPStatusCode = resp.HTTPStatus
			log.ResponseStatus = httpStatusClass(resp.HTTPStatus)
			log.ResponseCode = int64(resp.HTTPStatus)
		}
		log.RequestType = log.HTTPMethod

	case 3: // MySQL
		log.SQLCmd = mysqlCmdString(primary.MySQLCmd)
		log.RequestType = log.SQLCmd

	case 4: // Redis
		cmd := string(primary.RedisCmd[:])
		for i, c := range cmd {
			if c == 0 {
				cmd = cmd[:i]
				break
			}
		}
		log.RedisCmd = cmd
		log.RequestType = cmd

	case 5: // DNS
		log.DNSQueryType = primary.DNSTxID // txid 记录在此字段备查
		if resp != nil {
			log.DNSRCode = resp.DNSFlags & 0x000F
		}
		log.ReqType = uint8(ebpf.L7RequestTypeSession)

	case 6: // Kafka
		if req != nil {
			log.KafkaAPIKey = req.KafkaAPIKey
			log.KafkaCorrelID = int32(req.KafkaCorrel)
		}
	}

	d.store.WriteL7FlowLog(log)
}

// gcLoop 定期清理超时未配对的请求（10 秒超时）
func (d *L7MetaDispatcher) gcLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		timeout := time.Now().Add(-10 * time.Second)
		d.mu.Lock()
		for k, v := range d.sessions {
			if v.ts.Before(timeout) {
				delete(d.sessions, k)
			}
		}
		d.mu.Unlock()
	}
}

// ── 辅助转换 ──────────────────────────────────────────────

func httpMethodString(method uint8) string {
	switch method {
	case 1:
		return "GET"
	case 2:
		return "POST"
	case 3:
		return "PUT"
	case 4:
		return "DELETE"
	case 5:
		return "HEAD"
	case 6:
		return "PATCH"
	case 7:
		return "OPTIONS"
	default:
		return "UNKNOWN"
	}
}

func httpStatusClass(status uint16) uint8 {
	switch {
	case status >= 500:
		return 2 // server error
	case status >= 400:
		return 1 // client error
	default:
		return 0 // success
	}
}

func mysqlCmdString(cmd uint8) string {
	switch cmd {
	case 0x01:
		return "COM_QUIT"
	case 0x02:
		return "COM_INIT_DB"
	case 0x03:
		return "COM_QUERY"
	case 0x04:
		return "COM_FIELD_LIST"
	case 0x0e:
		return "COM_PING"
	case 0x16:
		return "COM_STMT_PREPARE"
	case 0x17:
		return "COM_STMT_EXECUTE"
	case 0x19:
		return "COM_STMT_CLOSE"
	default:
		return "UNKNOWN"
	}
}
