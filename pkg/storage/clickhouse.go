// pkg/storage/clickhouse.go
// ClickHouse 存储层，对齐 DeepFlow flow_log.l4_flow_log / flow_log.l7_flow_log 表结构

package storage

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	log "github.com/sirupsen/logrus"

	"observer/pkg/config"
)

// ── L4FlowLog 对应 DeepFlow flow_log.l4_flow_log ─────────────────────────────
//
// 字段分组：时间 | 五元组 | 进程 | 流属性 | 云标签 | 吞吐 | 时延 | TCP异常

type L4FlowLog struct {
	// 时间
	StartTime  time.Time `ch:"start_time"`
	EndTime    time.Time `ch:"end_time"`
	DurationUs uint64    `ch:"duration_us"`

	// 网络五元组
	SrcIP    net.IP `ch:"src_ip"`
	DstIP    net.IP `ch:"dst_ip"`
	SrcPort  uint16 `ch:"src_port"`
	DstPort  uint16 `ch:"dst_port"`
	Protocol uint8  `ch:"protocol"`

	// 进程
	PID         uint32 `ch:"pid"`
	ProcessName string `ch:"process_name"`

	// 流属性：role(0=unknown 1=client 2=server), close_type(1=FIN 2=RST 3=TIMEOUT)
	Role      uint8  `ch:"role"`
	CloseType uint8  `ch:"close_type"`
	FlowID    uint64 `ch:"flow_id"`

	// 云/K8s 标签（AutoTagging 注入）
	PodName      string `ch:"pod_name"`
	PodNamespace string `ch:"pod_namespace"`
	ServiceName  string `ch:"service_name"`
	NodeName     string `ch:"node_name"`
	PodIP        net.IP `ch:"pod_ip"`
	Region       string `ch:"region"`
	AZ           string `ch:"az"`
	AppLabels    string `ch:"app_labels"`

	// 吞吐
	BytesSent       uint64 `ch:"bytes_sent"`
	BytesReceived   uint64 `ch:"bytes_recv"`
	PacketsSent     uint64 `ch:"pkts_sent"`
	PacketsReceived uint64 `ch:"pkts_recv"`

	// 时延 μs — SYN RTT（三段），数据层 RTT，服务响应时延 SRT
	SynRttUs       uint32 `ch:"syn_rtt_us"`
	SynRttClientUs uint32 `ch:"syn_rtt_client_us"`
	SynRttServerUs uint32 `ch:"syn_rtt_server_us"`
	RTTMinUs       uint32 `ch:"rtt_min_us"`
	RTTMeanUs      uint32 `ch:"rtt_mean_us"`
	RTTMaxUs       uint32 `ch:"rtt_max_us"`
	SRTMeanUs      uint32 `ch:"srt_mean_us"`
	SRTMaxUs       uint32 `ch:"srt_max_us"`

	// TCP 异常
	RetransCnt    uint32  `ch:"retrans_cnt"`
	RetransBytes  uint64  `ch:"retrans_bytes"`
	RetransRatio  float32 `ch:"retrans_ratio"`
	ZeroWndCnt    uint32  `ch:"zero_wnd_cnt"`
	ZeroWndUs     uint64  `ch:"zero_wnd_us"`
	RSTCnt        uint8   `ch:"rst_cnt"`
	SynRetransCnt uint8   `ch:"syn_retrans_cnt"`
}

// ── L7FlowLog 对应 DeepFlow flow_log.l7_flow_log ─────────────────────────────
//
// 字段分组：时间 | 五元组 | 进程 | L7协议 | 请求资源 | 各协议字段 | 响应状态 | 云标签 | 扩展

type L7FlowLog struct {
	// 时间
	StartTime  time.Time `ch:"start_time"`
	EndTime    time.Time `ch:"end_time"`
	ResponseUs uint32    `ch:"response_us"`

	// 网络五元组
	SrcIP    net.IP `ch:"src_ip"`
	DstIP    net.IP `ch:"dst_ip"`
	SrcPort  uint16 `ch:"src_port"`
	DstPort  uint16 `ch:"dst_port"`
	Protocol uint8  `ch:"protocol"`

	// 进程
	PID         uint32 `ch:"pid"`
	ProcessName string `ch:"process_name"`

	// L7 协议（枚举值 + 字符串 + req_type: 1=request 2=response 3=session）
	L7Protocol uint16 `ch:"l7_protocol"`
	L7ProtName string `ch:"l7_prot_name"`
	ReqType    uint8  `ch:"req_type"`

	// 请求资源抽象（DeepFlow: request_resource / request_type）
	RequestResource string `ch:"request_resource"`
	RequestType     string `ch:"request_type"`

	// HTTP / HTTP2 / gRPC
	HTTPMethod       string `ch:"http_method"`
	HTTPPath         string `ch:"http_path"`
	HTTPHost         string `ch:"http_host"`
	HTTPUserAgent    string `ch:"http_user_agent"`
	HTTPReferer      string `ch:"http_referer"`
	HTTPStatusCode   uint16 `ch:"http_status_code"`
	HTTPReqBodySize  int64  `ch:"http_req_body_size"`
	HTTPRespBodySize int64  `ch:"http_resp_body_size"`
	GRPCStatusCode   uint32 `ch:"grpc_status_code"`

	// MySQL
	SQLCmd   string `ch:"sql_cmd"`
	SQLTable string `ch:"sql_table"`
	SQLRows  int64  `ch:"sql_rows"`
	SQLErrno int32  `ch:"sql_errno"`

	// Redis
	RedisCmd    string `ch:"redis_cmd"`
	RedisKey    string `ch:"redis_key"`
	RedisErrMsg string `ch:"redis_err_msg"`

	// DNS
	DNSQueryName string `ch:"dns_query_name"`
	DNSQueryType uint16 `ch:"dns_query_type"`
	DNSRCode     uint16 `ch:"dns_rcode"`
	DNSAnswerIP  string `ch:"dns_answer_ip"`

	// Kafka
	KafkaAPIKey    uint16 `ch:"kafka_api_key"`
	KafkaTopic     string `ch:"kafka_topic"`
	KafkaPartition int32  `ch:"kafka_partition"`
	KafkaCorrelID  int32  `ch:"kafka_correl_id"`
	KafkaErrCode   int16  `ch:"kafka_err_code"`
	KafkaMsgCount  int32  `ch:"kafka_msg_count"`
	KafkaMsgBytes  int64  `ch:"kafka_msg_bytes"`

	// ICMP / Ping
	ICMPType  uint8  `ch:"icmp_type"`
	ICMPCode  uint8  `ch:"icmp_code"`
	ICMPSeq   uint16 `ch:"icmp_seq"`
	ICMPID    uint16 `ch:"icmp_id"`
	PingRTTUs uint32 `ch:"ping_rtt_us"`

	// 通用响应状态（0=success 1=client_error 2=server_error）
	ResponseStatus uint8  `ch:"response_status"`
	ResponseCode   int64  `ch:"response_code"`
	ResponseErrMsg string `ch:"response_err_msg"`

	// 云/K8s 标签
	PodName      string `ch:"pod_name"`
	PodNamespace string `ch:"pod_namespace"`
	ServiceName  string `ch:"service_name"`
	NodeName     string `ch:"node_name"`
	AppLabels    string `ch:"app_labels"`

	// WASM 扩展属性（JSON）
	ExtAttributes string `ch:"ext_attributes"`
}

// ── ClickHouseClient ──────────────────────────────────────────────────────────

type ClickHouseClient struct {
	conn   driver.Conn
	cfg    config.ClickHouseConfig
	closed bool

	l4mu    sync.Mutex
	l4Batch []L4FlowLog
	l4Timer *time.Ticker

	l7mu    sync.Mutex
	l7Batch []L7FlowLog
	l7Timer *time.Ticker

	stopCh chan struct{}
	wg     sync.WaitGroup
}

func NewClickHouseClient(cfg config.ClickHouseConfig) (*ClickHouseClient, error) {
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: cfg.Addresses,
		Auth: clickhouse.Auth{
			Database: cfg.Database,
			Username: cfg.Username,
			Password: cfg.Password,
		},
		MaxOpenConns:    cfg.MaxOpenConns,
		MaxIdleConns:    cfg.MaxIdleConns,
		ConnMaxLifetime: 3600 * time.Second,
		DialTimeout:     cfg.DialTimeout,
		Debug:           false,
		Compression: &clickhouse.Compression{
			Method: clickhouse.CompressionLZ4,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("open clickhouse: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := conn.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping clickhouse: %w", err)
	}

	c := &ClickHouseClient{
		conn:   conn,
		cfg:    cfg,
		stopCh: make(chan struct{}),
	}

	if err := c.initSchema(context.Background()); err != nil {
		return nil, fmt.Errorf("init schema: %w", err)
	}

	c.l4Timer = time.NewTicker(cfg.L4FlushInterval)
	c.l7Timer = time.NewTicker(cfg.L7FlushInterval)

	c.wg.Add(2)
	go c.l4FlushLoop()
	go c.l7FlushLoop()

	log.WithField("addresses", cfg.Addresses).Info("ClickHouse client connected")
	return c, nil
}

// safeIPv4 将字符串 IP 转换为 net.IP（4 字节形式），空字符串或无效 IP 返回 0.0.0.0。
// ClickHouse IPv4 列不接受空字符串，必须传入合法 net.IP，否则会报
// "converting  to IPv4 is unsupported" 错误。
func SafeIPv4(s string) net.IP {
	if s == "" {
		return net.IPv4zero.To4()
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return net.IPv4zero.To4()
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	// IPv6 地址，当前表结构不支持，以 0.0.0.0 占位
	return net.IPv4zero.To4()
}

// BuildL4FlowLog 从字符串 IP 构造 L4FlowLog，并确保 IP 字段合法。
func BuildL4FlowLog(srcIP, dstIP, podIP string) L4FlowLog {
	return L4FlowLog{
		SrcIP: SafeIPv4(srcIP),
		DstIP: SafeIPv4(dstIP),
		PodIP: SafeIPv4(podIP),
	}
}

// BuildL7FlowLog 从字符串 IP 构造 L7FlowLog。
func BuildL7FlowLog(srcIP, dstIP string) L7FlowLog {
	return L7FlowLog{
		SrcIP: SafeIPv4(srcIP),
		DstIP: SafeIPv4(dstIP),
	}
}

// initSchema 建库建表（幂等）
func (c *ClickHouseClient) initSchema(ctx context.Context) error {
	sqls := []string{
		fmt.Sprintf(`CREATE DATABASE IF NOT EXISTS %s`, c.cfg.Database),
		c.l4FlowLogDDL(),
		c.l7FlowLogDDL(),
	}
	for _, sql := range sqls {
		if err := c.conn.Exec(ctx, sql); err != nil {
			return fmt.Errorf("exec DDL: %w\nSQL: %s", err, sql)
		}
	}
	log.Info("ClickHouse schema initialized")
	return nil
}

func (c *ClickHouseClient) l4FlowLogDDL() string {
	return fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s.l4_flow_log (
    start_time          DateTime64(6, 'UTC') CODEC(Delta, ZSTD),
    end_time            DateTime64(6, 'UTC') CODEC(Delta, ZSTD),
    duration_us         UInt64               CODEC(Delta, ZSTD),
    src_ip              IPv4  CODEC(ZSTD),
    dst_ip              IPv4  CODEC(ZSTD),
    src_port            UInt16 CODEC(ZSTD),
    dst_port            UInt16 CODEC(ZSTD),
    protocol            UInt8,
    pid                 UInt32 CODEC(ZSTD),
    process_name        LowCardinality(String),
    role                UInt8,
    close_type          UInt8,
    flow_id             UInt64 CODEC(ZSTD),
    pod_name            LowCardinality(String),
    pod_namespace       LowCardinality(String),
    service_name        LowCardinality(String),
    node_name           LowCardinality(String),
    pod_ip              IPv4  CODEC(ZSTD),
    region              LowCardinality(String),
    az                  LowCardinality(String),
    app_labels          String CODEC(ZSTD),
    bytes_sent          UInt64 CODEC(Delta, ZSTD),
    bytes_recv          UInt64 CODEC(Delta, ZSTD),
    pkts_sent           UInt64 CODEC(Delta, ZSTD),
    pkts_recv           UInt64 CODEC(Delta, ZSTD),
    syn_rtt_us          UInt32 CODEC(ZSTD),
    syn_rtt_client_us   UInt32 CODEC(ZSTD),
    syn_rtt_server_us   UInt32 CODEC(ZSTD),
    rtt_min_us          UInt32 CODEC(ZSTD),
    rtt_mean_us         UInt32 CODEC(ZSTD),
    rtt_max_us          UInt32 CODEC(ZSTD),
    srt_mean_us         UInt32 CODEC(ZSTD),
    srt_max_us          UInt32 CODEC(ZSTD),
    retrans_cnt         UInt32  CODEC(ZSTD),
    retrans_bytes       UInt64  CODEC(ZSTD),
    retrans_ratio       Float32,
    zero_wnd_cnt        UInt32  CODEC(ZSTD),
    zero_wnd_us         UInt64  CODEC(ZSTD),
    rst_cnt             UInt8,
    syn_retrans_cnt     UInt8
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(start_time)
ORDER BY (toStartOfMinute(start_time), src_ip, dst_ip, src_port, dst_port)
TTL toDate(start_time) + INTERVAL %d DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1
`, c.cfg.Database, c.cfg.L4RetentionDays)
}

func (c *ClickHouseClient) l7FlowLogDDL() string {
	return fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s.l7_flow_log (
    start_time          DateTime64(6, 'UTC') CODEC(Delta, ZSTD),
    end_time            DateTime64(6, 'UTC') CODEC(Delta, ZSTD),
    response_us         UInt32 CODEC(ZSTD),
    src_ip              IPv4  CODEC(ZSTD),
    dst_ip              IPv4  CODEC(ZSTD),
    src_port            UInt16 CODEC(ZSTD),
    dst_port            UInt16 CODEC(ZSTD),
    protocol            UInt8,
    pid                 UInt32 CODEC(ZSTD),
    process_name        LowCardinality(String),
    l7_protocol         UInt16,
    l7_prot_name        LowCardinality(String),
    req_type            UInt8,
    request_resource    String CODEC(ZSTD),
    request_type        LowCardinality(String),
    http_method         LowCardinality(String),
    http_path           String CODEC(ZSTD),
    http_host           String CODEC(ZSTD),
    http_user_agent     String CODEC(ZSTD),
    http_referer        String CODEC(ZSTD),
    http_status_code    UInt16,
    http_req_body_size  Int64  CODEC(ZSTD),
    http_resp_body_size Int64  CODEC(ZSTD),
    grpc_status_code    UInt32,
    sql_cmd             LowCardinality(String),
    sql_table           String CODEC(ZSTD),
    sql_rows            Int64  CODEC(ZSTD),
    sql_errno           Int32,
    redis_cmd           LowCardinality(String),
    redis_key           String CODEC(ZSTD),
    redis_err_msg       String CODEC(ZSTD),
    dns_query_name      String CODEC(ZSTD),
    dns_query_type      UInt16,
    dns_rcode           UInt16,
    dns_answer_ip       String CODEC(ZSTD),
    kafka_api_key       UInt16,
    kafka_topic         String CODEC(ZSTD),
    kafka_partition     Int32,
    kafka_correl_id     Int32,
    kafka_err_code      Int16,
    kafka_msg_count     Int32,
    kafka_msg_bytes     Int64  CODEC(ZSTD),
    icmp_type           UInt8,
    icmp_code           UInt8,
    icmp_seq            UInt16,
    icmp_id             UInt16,
    ping_rtt_us         UInt32 CODEC(ZSTD),
    response_status     UInt8,
    response_code       Int64,
    response_err_msg    String CODEC(ZSTD),
    pod_name            LowCardinality(String),
    pod_namespace       LowCardinality(String),
    service_name        LowCardinality(String),
    node_name           LowCardinality(String),
    app_labels          String CODEC(ZSTD),
    ext_attributes      String CODEC(ZSTD)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(start_time)
ORDER BY (toStartOfMinute(start_time), l7_protocol, src_ip, dst_ip)
TTL toDate(start_time) + INTERVAL %d DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1
`, c.cfg.Database, c.cfg.L7RetentionDays)
}

// ── 写入接口 ──────────────────────────────────────────────────────────────────

func (c *ClickHouseClient) WriteL4FlowLog(r L4FlowLog) {
	c.l4mu.Lock()
	c.l4Batch = append(c.l4Batch, r)
	shouldFlush := len(c.l4Batch) >= c.cfg.L4BatchSize
	c.l4mu.Unlock()
	if shouldFlush {
		c.flushL4()
	}
}

func (c *ClickHouseClient) WriteL7FlowLog(r L7FlowLog) {
	c.l7mu.Lock()
	c.l7Batch = append(c.l7Batch, r)
	shouldFlush := len(c.l7Batch) >= c.cfg.L7BatchSize
	c.l7mu.Unlock()
	if shouldFlush {
		c.flushL7()
	}
}

func (c *ClickHouseClient) l4FlushLoop() {
	defer c.wg.Done()
	for {
		select {
		case <-c.l4Timer.C:
			c.flushL4()
		case <-c.stopCh:
			c.flushL4()
			return
		}
	}
}

func (c *ClickHouseClient) l7FlushLoop() {
	defer c.wg.Done()
	for {
		select {
		case <-c.l7Timer.C:
			c.flushL7()
		case <-c.stopCh:
			c.flushL7()
			return
		}
	}
}

func (c *ClickHouseClient) flushL4() {
	c.l4mu.Lock()
	if len(c.l4Batch) == 0 {
		c.l4mu.Unlock()
		return
	}
	batch := c.l4Batch
	c.l4Batch = nil
	c.l4mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	b, err := c.conn.PrepareBatch(ctx,
		fmt.Sprintf("INSERT INTO %s.l4_flow_log", c.cfg.Database))
	if err != nil {
		log.WithError(err).Error("Prepare l4_flow_log batch failed")
		return
	}

	zero4 := net.IPv4zero.To4()
	for i := range batch {
		r := &batch[i]
		// 确保 net.IP 字段不为 nil（无 K8s 环境 PodIP 为空字符串时不报错）
		if r.SrcIP == nil {
			r.SrcIP = zero4
		}
		if r.DstIP == nil {
			r.DstIP = zero4
		}
		if r.PodIP == nil {
			r.PodIP = zero4
		}
		if err := b.AppendStruct(r); err != nil {
			log.WithError(err).Warn("Append l4_flow_log row failed")
		}
	}

	if err := b.Send(); err != nil {
		log.WithError(err).Error("Send l4_flow_log batch failed")
		return
	}
	log.WithField("rows", len(batch)).Debug("l4_flow_log batch flushed")
}

func (c *ClickHouseClient) flushL7() {
	c.l7mu.Lock()
	if len(c.l7Batch) == 0 {
		c.l7mu.Unlock()
		return
	}
	batch := c.l7Batch
	c.l7Batch = nil
	c.l7mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	b, err := c.conn.PrepareBatch(ctx,
		fmt.Sprintf("INSERT INTO %s.l7_flow_log", c.cfg.Database))
	if err != nil {
		log.WithError(err).Error("Prepare l7_flow_log batch failed")
		return
	}

	zero4 := net.IPv4zero.To4()
	for i := range batch {
		r := &batch[i]
		if r.SrcIP == nil {
			r.SrcIP = zero4
		}
		if r.DstIP == nil {
			r.DstIP = zero4
		}
		if err := b.AppendStruct(r); err != nil {
			log.WithError(err).Warn("Append l7_flow_log row failed")
		}
	}

	if err := b.Send(); err != nil {
		log.WithError(err).Error("Send l7_flow_log batch failed")
		return
	}
	log.WithField("rows", len(batch)).Debug("l7_flow_log batch flushed")
}

func (c *ClickHouseClient) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	close(c.stopCh)
	c.wg.Wait()
	c.l4Timer.Stop()
	c.l7Timer.Stop()
	return c.conn.Close()
}
