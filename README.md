# Observer — eBPF Network Observability Agent

基于 eBPF 的网络可观测性 Agent，捕获 TCP/UDP L4 流和 HTTP、MySQL、Redis、DNS、Kafka、gRPC、Ping/ICMP、TLS 等 L7 协议，写入 ClickHouse `flow_metrics.l4_flow_log` / `flow_metrics.l7_flow_log`，兼容 DeepFlow 表结构。

---

## 架构

```
kprobe/tcp_sendmsg + tcp_recvmsg
        │
        ▼
   l7_tracer.o (ring buffer: l7_events)
        │
        ▼
   L7 Event Loop → Protocol Registry
        │   HTTP / HTTP2 / gRPC / MySQL / Redis / DNS / Kafka / Ping / TLS
        ▼
   ClickHouse: flow_metrics.l7_flow_log

kprobe/tcp_connect + inet_csk_accept + tcp_set_state ...
        │
        ▼
   tcp_tracer.o (ring buffer: tcp_events)
        │
        ▼
   TCP Flow Cache → ClickHouse: flow_metrics.l4_flow_log

kprobe/udp_sendmsg + udp_recvmsg
        │
        ▼
   udp_tracer.o → UDP Flow Cache → ClickHouse: flow_metrics.l4_flow_log

TC classifier (ingress + egress, 可选)
        │
        ▼
   tc_tracer.o → Prometheus metrics
```

---

## 快速开始

### 前置条件

- Linux kernel ≥ 5.10（推荐 6.x）
- BTF 支持（`/sys/kernel/btf/vmlinux` 存在）
- Docker + Docker Compose
- clang ≥ 14、libbpf-dev、bpftool（编译 eBPF）

### 编译

```bash
# 编译 eBPF 对象文件
make bpf

# 编译 Go agent
make build

# 一键构建 Docker 镜像
make docker-build
```

### 启动基础设施

```bash
docker-compose up -d clickhouse prometheus grafana
```

ClickHouse 自动执行 `deployments/clickhouse/init.sql` 创建 `flow_metrics` 数据库及所有表。

### 启动 Agent

```bash
# 以 root 运行（需要 CAP_BPF / CAP_SYS_ADMIN）
sudo ./observer-agent --config config.yaml
```

或 Docker 方式：

```bash
docker-compose up -d observer
```

---

## 配置说明

`config.yaml` 主要参数：

| 配置项 | 说明 |
|--------|------|
| `ebpf.bpf_obj_dir` | 编译好的 `.o` 文件目录 |
| `clickhouse.addresses` | ClickHouse 地址列表 |
| `clickhouse.database` | 数据库名（默认 `flow_metrics`） |
| `l7.enabled` | 是否开启 L7 协议解析 |
| `collector.tc.interfaces` | TC hook 监听的网卡名（如 `eth0`） |
| `cloud_meta.enabled` | 是否开启 K8s Pod 自动标签 |

---

## 协议测试方法与预期结果

所有测试前确认 Agent 已运行且 ClickHouse 可访问：

```bash
curl -s http://localhost:8080/health
# 预期：{"status":"ok","version":"10.0.0","ts":...}
```

等待 `l7_flush_interval`（默认 3 秒）后查询 ClickHouse。

---

### 1. HTTP/1.1

**测试方法：**

```bash
# 用 curl 发送请求
curl -s http://httpbin.org/get
curl -s -X POST http://httpbin.org/post -d '{"test":1}'

# 本机测试（loopback 同样可以捕获）
python3 -m http.server 8888 &
curl -s http://localhost:8888/
```

**ClickHouse 查询：**

```sql
SELECT start_time, src_ip, dst_ip, src_port, dst_port,
       l7_prot_name, http_method, http_path, http_host,
       http_status_code, response_us
FROM flow_metrics.l7_flow_log
WHERE l7_protocol = 1
ORDER BY start_time DESC LIMIT 10;
```

**预期结果：**

```
l7_prot_name     = 'HTTP'
http_method      = 'GET' 或 'POST'
http_path        = '/get' 或 '/post'
http_host        = 'httpbin.org'
http_status_code = 200
response_us      > 0
```

---

### 2. MySQL

**测试方法：**

```bash
docker run -d --name mysql-test -e MYSQL_ROOT_PASSWORD=test -p 3306:3306 mysql:8
mysql -h 127.0.0.1 -P 3306 -uroot -ptest \
  -e "SELECT 1; SHOW DATABASES; SELECT * FROM information_schema.tables LIMIT 5;"
```

**ClickHouse 查询：**

```sql
SELECT start_time, src_ip, dst_ip, dst_port,
       l7_prot_name, sql_cmd, sql_table, sql_rows, sql_errno, response_us
FROM flow_metrics.l7_flow_log
WHERE l7_protocol = 3
ORDER BY start_time DESC LIMIT 10;
```

**预期结果：**

```
l7_prot_name = 'MySQL'
sql_cmd      = 'SELECT' 或 'SHOW'
sql_table    = 'tables'（视查询而定）
sql_errno    = 0
response_us  > 0
```

---

### 3. Redis

**测试方法：**

```bash
docker run -d --name redis-test -p 6379:6379 redis:7
redis-cli -p 6379 SET mykey "hello"
redis-cli -p 6379 GET mykey
redis-cli -p 6379 HSET myhash field1 value1
redis-cli -p 6379 HGET myhash field1
redis-cli -p 6379 MSET k1 v1 k2 v2 k3 v3
redis-cli -p 6379 KEYS '*'
```

**ClickHouse 查询：**

```sql
SELECT start_time, src_ip, dst_ip, dst_port,
       l7_prot_name, redis_cmd, redis_key, redis_err_msg, response_us
FROM flow_metrics.l7_flow_log
WHERE l7_protocol = 4
ORDER BY start_time DESC LIMIT 10;
```

**预期结果：**

```
l7_prot_name  = 'Redis'
redis_cmd     = 'SET' / 'GET' / 'HSET' / 'HGET' / 'MSET' / 'KEYS'
redis_key     = 'mykey' / 'myhash' / 'k1' 等
redis_err_msg = ''（成功时为空）
response_us   > 0
```

---

### 4. DNS

**测试方法：**

```bash
# 强制走 TCP（L7 tracer 可直接捕获 TCP DNS）
dig +tcp google.com @8.8.8.8
dig +tcp github.com @8.8.8.8

# 批量生成
for i in $(seq 1 10); do dig +tcp "$i.example.com" @8.8.8.8 +short; done
```

**ClickHouse 查询：**

```sql
SELECT start_time, src_ip, dst_ip, dst_port,
       l7_prot_name, dns_query_name, dns_query_type,
       dns_rcode, dns_answer_ip, response_us
FROM flow_metrics.l7_flow_log
WHERE l7_protocol = 5
ORDER BY start_time DESC LIMIT 10;
```

**预期结果：**

```
l7_prot_name   = 'DNS'
dns_query_name = 'google.com'
dns_query_type = 1（A 记录）或 28（AAAA）
dns_rcode      = 0（NOERROR）
dns_answer_ip  = '142.250.x.x'
response_us    > 0
```

> **说明：** DNS 默认走 UDP。L7 tracer 通过 `kprobe/tcp_sendmsg` 捕获 TCP DNS（`dig +tcp`）；UDP DNS 需配置 `udp_tracer` payload 捕获（当前版本不支持 UDP payload 解析）。

---

### 5. Kafka

**测试方法：**

先在 `config.yaml` 中设置 `l7.protocols.kafka.enabled: true` 并重启 agent。

```bash
docker run -d --name kafka-test \
  -e KAFKA_CFG_NODE_ID=0 \
  -e KAFKA_CFG_PROCESS_ROLES=controller,broker \
  -e KAFKA_CFG_LISTENERS=PLAINTEXT://:9092,CONTROLLER://:9093 \
  -e KAFKA_CFG_ADVERTISED_LISTENERS=PLAINTEXT://127.0.0.1:9092 \
  -e KAFKA_CFG_CONTROLLER_QUORUM_VOTERS=0@localhost:9093 \
  -e KAFKA_CFG_CONTROLLER_LISTENER_NAMES=CONTROLLER \
  -p 9092:9092 bitnami/kafka:latest

# 生产消息
echo "hello observer" | kafka-console-producer.sh \
  --bootstrap-server localhost:9092 --topic test-topic

# 消费消息
kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 --topic test-topic \
  --from-beginning --max-messages 5
```

**ClickHouse 查询：**

```sql
SELECT start_time, src_ip, dst_ip, dst_port,
       l7_prot_name, kafka_api_key, kafka_topic, kafka_partition,
       kafka_msg_count, kafka_msg_bytes, kafka_err_code, response_us
FROM flow_metrics.l7_flow_log
WHERE l7_protocol = 6
ORDER BY start_time DESC LIMIT 10;
```

**预期结果：**

```
l7_prot_name    = 'Kafka'
kafka_api_key   = 0（Produce）或 1（Fetch）
kafka_topic     = 'test-topic'
kafka_partition = 0
kafka_msg_count > 0
kafka_err_code  = 0
response_us     > 0
```

---

### 6. gRPC

**测试方法：**

先在 `config.yaml` 中设置 `l7.protocols.grpc.enabled: true` 并重启 agent。

```bash
# 安装 grpcurl（https://github.com/fullstorydev/grpcurl）
# 启动 gRPC server（以 grpc-helloworld 示例为例）
docker run -d --name grpc-test -p 50051:50051 \
  grpc/java-example-hostname:latest

# 发送 gRPC 请求
grpcurl -plaintext -d '{"name":"observer"}' \
  localhost:50051 helloworld.Greeter/SayHello
```

**ClickHouse 查询：**

```sql
SELECT start_time, src_ip, dst_ip, dst_port,
       l7_prot_name, http_method, http_path, http_host,
       http_status_code, grpc_status_code, response_us
FROM flow_metrics.l7_flow_log
WHERE l7_protocol = 7
ORDER BY start_time DESC LIMIT 10;
```

**预期结果：**

```
l7_prot_name     = 'gRPC'
http_path        = '/helloworld.Greeter/SayHello'
http_status_code = 200
grpc_status_code = 0（OK）
response_us      > 0
```

---

### 7. Ping / ICMP

**测试方法：**

确保 `config.yaml` 的 `collector.tc.interfaces` 中配置了正确的网卡名（如 `eth0`、`ens33`），TC hook 捕获原始 ICMP 包。

```bash
ping -c 5 8.8.8.8
ping -c 5 1.1.1.1
```

**ClickHouse 查询：**

```sql
SELECT start_time, src_ip, dst_ip,
       l7_prot_name, icmp_type, icmp_code,
       icmp_seq, icmp_id, ping_rtt_us
FROM flow_metrics.l7_flow_log
WHERE l7_protocol = 8
ORDER BY start_time DESC LIMIT 10;
```

**预期结果：**

```
l7_prot_name = 'Ping'
icmp_type    = 8（EchoRequest）或 0（EchoReply）
icmp_code    = 0
icmp_seq     = 1, 2, 3, 4, 5（递增）
ping_rtt_us  > 0（RTT 微秒）
```

> **说明：** Ping 使用 raw socket，不经过 `tcp_sendmsg`。需通过 TC hook（`tc_tracer.o`）在网卡层捕获，需配置有效的 `interfaces`。

---

### 8. TLS

**测试方法：**

```bash
# TLS Client Hello 由 tcp_sendmsg kprobe 捕获，包含 SNI 等握手信息
curl -s https://www.google.com -o /dev/null
curl -s https://github.com -o /dev/null
curl -s https://api.github.com/octocat -o /dev/null
```

**ClickHouse 查询：**

```sql
SELECT start_time, src_ip, dst_ip, dst_port,
       l7_prot_name, tls_sni_name, tls_version,
       tls_cipher_suite, tls_alpn
FROM flow_metrics.l7_flow_log
WHERE l7_protocol = 9
ORDER BY start_time DESC LIMIT 10;
```

**预期结果：**

```
l7_prot_name     = 'TLS'
tls_sni_name     = 'www.google.com' / 'github.com'
tls_version      = 'TLS 1.3' 或 'TLS 1.2'
tls_cipher_suite = 'TLS_AES_128_GCM_SHA256' 等
tls_alpn         = 'h2' 或 'http/1.1'
```

---

## L4 流日志查询

```sql
-- TCP 流汇总（最近 5 分钟）
SELECT src_ip, dst_ip, dst_port, protocol,
       role, close_type, duration_us,
       bytes_sent, bytes_recv,
       syn_rtt_us, rtt_mean_us, srt_mean_us,
       retrans_cnt, zero_wnd_cnt
FROM flow_metrics.l4_flow_log
WHERE start_time >= now() - INTERVAL 5 MINUTE
ORDER BY start_time DESC LIMIT 20;

-- 高延迟 TCP 连接（SYN RTT > 100ms）
SELECT src_ip, dst_ip, dst_port, syn_rtt_us, rtt_mean_us
FROM flow_metrics.l4_flow_log
WHERE syn_rtt_us > 100000
ORDER BY syn_rtt_us DESC LIMIT 10;

-- 重传最多的连接
SELECT src_ip, dst_ip, dst_port, retrans_cnt, retrans_ratio
FROM flow_metrics.l4_flow_log
WHERE retrans_cnt > 5
ORDER BY retrans_cnt DESC LIMIT 10;
```

---

## 常见问题

### l7_flow_log 为空

1. 确认 `l7.enabled: true`（config.yaml）
2. **确保 ClickHouse 使用最新 `init.sql`**（包含 `tls_sni_name` / `tls_alpn` / `tls_version` / `tls_cipher_suite` 四个 TLS 字段，字段缺失会导致 `AppendStruct` 静默失败）
3. 检查 agent 日志是否出现 `L7 eBPF programs loaded`
4. 检查是否出现 `l7_flow_log batch flushed` 日志
5. 调试时可将 `l7_batch_size` 改为 `1`，触发立即写入

### 重建 ClickHouse 表（已有旧表需更新）

```sql
DROP TABLE IF EXISTS flow_metrics.l7_flow_log;
-- 重新执行 init.sql
```

### BPF verifier 报错

确保 kernel ≥ 5.10，`/sys/kernel/btf/vmlinux` 存在；`l7_tracer.c` 已使用编译期常量 `MAX_PAYLOAD_SIZE=4096` 调用 `bpf_probe_read_user`，规避 verifier 动态 size 检查问题。

### TC hook 无数据

在 `config.yaml` 中 `collector.tc.interfaces` 填写正确网卡名（`ip a` 查看）。loopback（lo）流量已由 kprobe 捕获，不依赖 TC。

---

## 监控

| 地址 | 说明 |
|------|------|
| `http://localhost:8080/metrics` | Prometheus metrics |
| `http://localhost:8080/health` | 健康检查 |
| `http://localhost:8080/debug/cloud_tags` | K8s 云标签调试 |
| `http://localhost:3000` | Grafana（admin/admin） |
| `http://localhost:8123` | ClickHouse HTTP API |
