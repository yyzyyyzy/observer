-- Observer ClickHouse 初始化脚本
-- 数据库 flow_metrics 对应 DeepFlow flow_log schema

CREATE DATABASE IF NOT EXISTS flow_metrics;

-- ── l4_flow_log：L4 聚合流日志 ────────────────────────────────────────────────
-- 对应 DeepFlow flow_log.l4_flow_log
-- 每条记录代表一条完整 TCP/UDP 流（生命周期结束后写入）
CREATE TABLE IF NOT EXISTS flow_metrics.l4_flow_log (
    -- 时间
    start_time          DateTime64(6, 'UTC') CODEC(Delta, ZSTD),
    end_time            DateTime64(6, 'UTC') CODEC(Delta, ZSTD),
    duration_us         UInt64               CODEC(Delta, ZSTD),

    -- 网络五元组
    src_ip              IPv4  CODEC(ZSTD),
    dst_ip              IPv4  CODEC(ZSTD),
    src_port            UInt16 CODEC(ZSTD),
    dst_port            UInt16 CODEC(ZSTD),
    protocol            UInt8,                        -- 6=TCP 17=UDP

    -- 进程
    pid                 UInt32 CODEC(ZSTD),
    process_name        LowCardinality(String),

    -- 流属性
    role                UInt8,                        -- 0=unknown 1=client 2=server
    close_type          UInt8,                        -- 1=FIN 2=RST 3=TIMEOUT
    flow_id             UInt64 CODEC(ZSTD),

    -- 云/K8s 标签（无 K8s 环境时为空字符串 / 0.0.0.0）
    pod_name            LowCardinality(String),
    pod_namespace       LowCardinality(String),
    service_name        LowCardinality(String),
    node_name           LowCardinality(String),
    pod_ip              IPv4  CODEC(ZSTD),
    region              LowCardinality(String),
    az                  LowCardinality(String),
    app_labels          String CODEC(ZSTD),           -- K8s app labels（JSON）

    -- 吞吐
    bytes_sent          UInt64 CODEC(Delta, ZSTD),
    bytes_recv          UInt64 CODEC(Delta, ZSTD),
    pkts_sent           UInt64 CODEC(Delta, ZSTD),
    pkts_recv           UInt64 CODEC(Delta, ZSTD),

    -- 时延（μs）
    syn_rtt_us          UInt32 CODEC(ZSTD),           -- 全程建连时延
    syn_rtt_client_us   UInt32 CODEC(ZSTD),           -- SYN+ACK→ACK
    syn_rtt_server_us   UInt32 CODEC(ZSTD),           -- SYN→SYN+ACK
    rtt_min_us          UInt32 CODEC(ZSTD),
    rtt_mean_us         UInt32 CODEC(ZSTD),
    rtt_max_us          UInt32 CODEC(ZSTD),
    srt_mean_us         UInt32 CODEC(ZSTD),           -- 服务响应时延（SRT）
    srt_max_us          UInt32 CODEC(ZSTD),

    -- TCP 异常
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
TTL toDate(start_time) + INTERVAL 7 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

-- ── l7_flow_log：L7 请求日志 ──────────────────────────────────────────────────
-- 对应 DeepFlow flow_log.l7_flow_log
-- 每条记录代表一次完整的 L7 请求/响应（请求+响应配对后写入）
CREATE TABLE IF NOT EXISTS flow_metrics.l7_flow_log (
    -- 时间
    start_time          DateTime64(6, 'UTC') CODEC(Delta, ZSTD),
    end_time            DateTime64(6, 'UTC') CODEC(Delta, ZSTD),
    response_us         UInt32 CODEC(ZSTD),           -- 请求→响应时延 μs

    -- 网络五元组
    src_ip              IPv4  CODEC(ZSTD),
    dst_ip              IPv4  CODEC(ZSTD),
    src_port            UInt16 CODEC(ZSTD),
    dst_port            UInt16 CODEC(ZSTD),
    protocol            UInt8,

    -- 进程
    pid                 UInt32 CODEC(ZSTD),
    process_name        LowCardinality(String),

    -- L7 协议
    l7_protocol         UInt16,                       -- 枚举值
    l7_prot_name        LowCardinality(String),       -- 协议名称
    req_type            UInt8,                        -- 1=request 2=response 3=session

    -- 请求资源（协议无关抽象）
    request_resource    String CODEC(ZSTD),           -- HTTP: path | gRPC: method | Kafka: topic
    request_type        LowCardinality(String),       -- HTTP: method | MySQL: cmd | Kafka: API name

    -- HTTP / HTTP2 / gRPC
    http_method         LowCardinality(String),
    http_path           String CODEC(ZSTD),
    http_host           String CODEC(ZSTD),
    http_user_agent     String CODEC(ZSTD),
    http_referer        String CODEC(ZSTD),
    http_status_code    UInt16,
    http_req_body_size  Int64  CODEC(ZSTD),
    http_resp_body_size Int64  CODEC(ZSTD),
    grpc_status_code    UInt32,                       -- 0=OK，非零为 gRPC 错误码

    -- MySQL
    sql_cmd             LowCardinality(String),
    sql_table           String CODEC(ZSTD),
    sql_rows            Int64  CODEC(ZSTD),
    sql_errno           Int32,

    -- Redis
    redis_cmd           LowCardinality(String),
    redis_key           String CODEC(ZSTD),
    redis_err_msg       String CODEC(ZSTD),

    -- DNS
    dns_query_name      String CODEC(ZSTD),
    dns_query_type      UInt16,                       -- 1=A 28=AAAA 5=CNAME
    dns_rcode           UInt16,                       -- 0=NOERROR 3=NXDOMAIN
    dns_answer_ip       String CODEC(ZSTD),

    -- Kafka
    kafka_api_key       UInt16,                       -- 0=Produce 1=Fetch
    kafka_topic         String CODEC(ZSTD),
    kafka_partition     Int32,
    kafka_correl_id     Int32,
    kafka_err_code      Int16,
    kafka_msg_count     Int32,
    kafka_msg_bytes     Int64  CODEC(ZSTD),

    -- ICMP / Ping
    icmp_type           UInt8,                        -- 8=EchoRequest 0=EchoReply
    icmp_code           UInt8,
    icmp_seq            UInt16,
    icmp_id             UInt16,
    ping_rtt_us         UInt32 CODEC(ZSTD),

    -- TLS 握手元数据
    tls_sni_name        String CODEC(ZSTD),
    tls_alpn            LowCardinality(String),
    tls_version         LowCardinality(String),
    tls_cipher_suite    LowCardinality(String),

    -- 通用响应状态
    response_status     UInt8,                        -- 0=success 1=client_error 2=server_error
    response_code       Int64,
    response_err_msg    String CODEC(ZSTD),

    -- 云/K8s 标签
    pod_name            LowCardinality(String),
    pod_namespace       LowCardinality(String),
    service_name        LowCardinality(String),
    node_name           LowCardinality(String),
    app_labels          String CODEC(ZSTD),

    -- WASM 扩展属性（JSON）
    ext_attributes      String CODEC(ZSTD)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(start_time)
ORDER BY (toStartOfMinute(start_time), l7_protocol, src_ip, dst_ip)
TTL toDate(start_time) + INTERVAL 3 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

-- ── 常用聚合视图 ──────────────────────────────────────────────────────────────

-- L4 每分钟聚合（RTT / 吞吐 / 异常统计）
CREATE VIEW IF NOT EXISTS flow_metrics.v_l4_minute AS
SELECT
    toStartOfMinute(start_time)     AS ts,
    src_ip, dst_ip, dst_port, protocol,
    pod_namespace, service_name,
    count()                         AS flow_count,
    avg(rtt_mean_us)                AS avg_rtt_us,
    quantile(0.95)(rtt_mean_us)     AS p95_rtt_us,
    avg(syn_rtt_us)                 AS avg_syn_rtt_us,
    avg(srt_mean_us)                AS avg_srt_us,
    sum(bytes_sent + bytes_recv)    AS total_bytes,
    sum(retrans_cnt)                AS total_retrans,
    countIf(close_type = 2)         AS rst_count,
    countIf(close_type = 3)         AS timeout_count
FROM flow_metrics.l4_flow_log
GROUP BY ts, src_ip, dst_ip, dst_port, protocol, pod_namespace, service_name;

-- L7 HTTP 每分钟聚合（P50/P95/P99 响应时延 + 错误率）
CREATE VIEW IF NOT EXISTS flow_metrics.v_l7_http_minute AS
SELECT
    toStartOfMinute(start_time)     AS ts,
    http_host, http_path, http_method,
    pod_namespace, service_name,
    count()                         AS req_count,
    quantile(0.50)(response_us)     AS p50_us,
    quantile(0.95)(response_us)     AS p95_us,
    quantile(0.99)(response_us)     AS p99_us,
    countIf(response_status != 0)   AS error_count,
    countIf(http_status_code >= 500) AS server_error_count,
    countIf(http_status_code >= 400 AND http_status_code < 500) AS client_error_count
FROM flow_metrics.l7_flow_log
WHERE l7_protocol IN (1, 2, 7)  -- HTTP / HTTP2 / gRPC
GROUP BY ts, http_host, http_path, http_method, pod_namespace, service_name;

-- L7 Kafka 每分钟聚合
CREATE VIEW IF NOT EXISTS flow_metrics.v_l7_kafka_minute AS
SELECT
    toStartOfMinute(start_time)     AS ts,
    kafka_topic, kafka_partition, kafka_api_key,
    pod_namespace, service_name,
    count()                         AS op_count,
    quantile(0.95)(response_us)     AS p95_us,
    sum(kafka_msg_bytes)            AS total_msg_bytes,
    countIf(kafka_err_code != 0)    AS error_count
FROM flow_metrics.l7_flow_log
WHERE l7_protocol = 6  -- Kafka
GROUP BY ts, kafka_topic, kafka_partition, kafka_api_key, pod_namespace, service_name;
