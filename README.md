# Observer v8 — eBPF 网络可观测性平台

基于 eBPF 的生产级网络监控系统，完全对齐 DeepFlow 架构。

## v8 核心修复（相较 v7）

### 1. L7 流日志为空问题（根本修复）

**根因**：v7 挂 `sys_write/sys_read`，依赖 `fd_to_sock` 映射获取五元组，但该 Map 从未填充，导致 `l7_flow_log` 表永远为空。

**修复方案**（对齐 DeepFlow）：改为挂 `tcp_sendmsg/tcp_recvmsg`：
- 直接从 `struct sock *sk` 读取五元组（`skc_rcv_saddr/skc_daddr/skc_num/skc_dport`）
- 支持 loopback(`127.0.0.1`) 流量（`python3 -m http.server` 场景）
- 无需 `fd_to_sock` 映射，五元组获取 100% 准确

```bash
# 测试 L7 捕获（loopback）
python3 -m http.server 8000 &
for i in {1..1000}; do curl -s -o /dev/null http://127.0.0.1:8000; done

# 验证数据
clickhouse-client --query "SELECT count(), l7_prot_name, http_path FROM flow_metrics.l7_flow_log GROUP BY l7_prot_name, http_path"
```

### 2. tcpCache.Flush() 实现

`pkg/flow/cache.Cache.Flush()` 现已完整实现：
- 将所有活跃流的当前累积指标快照写入 `l4_flow_log`（`close_type=0` 表示中间快照）
- 对长连接（不主动关闭的流）提供实时可见性
- 配合 `stats_window` 周期性执行（默认 60s）

### 3. TC Classifier 完整实现

`pkg/ebpf/manager.go` 中补全 TC 挂载代码（对齐 DeepFlow tap_mode_local）：
- 通过 rtnetlink 创建 `clsact qdisc`（幂等）
- `RTM_NEWTFILTER` 挂载 BPF `cls_bpf` classifier（带 `direct-action`）
- Stop 时通过 `RTM_DELQDISC` 清理，自动移除所有 filters

### 4. Dockerfile 修复

加入 `libbpf-dev`（提供 `bpf/bpf_helpers.h` 等头文件）：
```dockerfile
RUN apt-get install -y clang llvm libelf-dev libbpf-dev linux-headers-generic
```

## 架构

```
Kernel Space
┌─────────────────────────────────────────────────────────┐
│  tcp_sendmsg/tcp_recvmsg ──── L7 载荷捕获 (v8: 修复)    │
│  tcp_connect/inet_csk_accept ─ TCP 流生命周期            │
│  tcp_retransmit_skb ────────── 重传检测                  │
│  udp_sendmsg/udp_recvmsg ───── UDP 流聚合                │
│  TC ingress/egress ─────────── 完整包头捕获 (v8: 完整)   │
└─────────────────────┬───────────────────────────────────┘
                      │ ring buffer
User Space
┌─────────────────────▼───────────────────────────────────┐
│  TCPCollector → flow.Cache → l4_flow_log                │
│  UDPCollector → flow.UDPCache → l4_flow_log             │
│  L7Registry   → HTTP/MySQL/Redis/DNS 解析 → l7_flow_log │
│  TCCollector  → Prometheus metrics                       │
└─────────────────────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│           ClickHouse  /  Prometheus  /  Grafana          │
└─────────────────────────────────────────────────────────┘
```

## 快速开始

```bash
# 1. 启动 ClickHouse + Prometheus + Grafana
docker-compose up -d

# 2. 编译（需要 clang + libbpf-dev）
make all

# 3. 运行（需要 root）
sudo ./observer-agent --config config.yaml --log-level debug

# 4. 验证 L7 数据（关键验证点）
python3 -m http.server 8000 &
for i in {1..100}; do curl -s -o /dev/null http://127.0.0.1:8000; done
sleep 5  # 等待批写入
clickhouse-client --query "SELECT start_time, src_ip, dst_ip, dport, http_method, http_path, http_status_code FROM flow_metrics.l7_flow_log LIMIT 20"
```

## 配置

```yaml
collector:
  tc:
    enabled: true
    interfaces:
      - "ens33"    # 根据 ip a 输出填写主网卡
      # - "eth0"

clickhouse:
  enabled: true
  l7_batch_size: 200      # 降低批大小，减少延迟
  l7_flush_interval: 3s
```

## ClickHouse 查询示例

```sql
-- L7 HTTP 请求统计
SELECT
    toStartOfMinute(start_time) AS minute,
    http_method,
    http_path,
    http_status_code,
    count() AS requests,
    avg(response_us) AS avg_latency_us
FROM flow_metrics.l7_flow_log
WHERE l7_prot_name = 'HTTP'
GROUP BY minute, http_method, http_path, http_status_code
ORDER BY minute DESC, requests DESC
LIMIT 50;

-- TCP 高延迟流
SELECT
    src_ip, dst_ip, src_port, dst_port,
    syn_rtt_us, rtt_mean_us, srt_mean_us,
    retrans_cnt, bytes_sent + bytes_recv AS total_bytes
FROM flow_metrics.l4_flow_log
WHERE syn_rtt_us > 10000  -- > 10ms
ORDER BY syn_rtt_us DESC
LIMIT 20;

-- 实时活跃流快照（close_type=0 表示周期 Flush 的快照）
SELECT src_ip, dst_ip, dst_port, bytes_sent, bytes_recv, duration_us
FROM flow_metrics.l4_flow_log
WHERE close_type = 0
ORDER BY start_time DESC
LIMIT 20;
```

## 项目结构

```
observer-v8/
├── bpf/
│   ├── l7_tracer.c      # v8 重写：挂 tcp_sendmsg/tcp_recvmsg（修复 L7 为空）
│   ├── tcp_tracer.c     # TCP 流追踪（三态 + SYN RTT + SRT + 重传）
│   ├── udp_tracer.c     # UDP 流聚合
│   ├── tc_tracer.c      # TC hook（ingress/egress 包头捕获）
│   └── headers/
│       ├── common.h     # DeepFlow 对齐宏定义
│       └── vmlinux.h    # 内核类型定义（BTF 生成）
├── cmd/agent/main.go    # 程序入口
├── pkg/
│   ├── ebpf/
│   │   ├── manager.go   # v8 补全：TC attach + L7 hook 修复
│   │   ├── types.go     # 所有 BPF 事件类型定义
│   │   └── utils.go     # 辅助函数
│   ├── flow/
│   │   ├── cache.go     # v8 补全：Flush() 方法实现
│   │   └── udp_cache.go # UDP 流聚合缓存
│   ├── collector/       # TCP/UDP/TC 采集器
│   ├── l7/              # HTTP/MySQL/Redis/DNS/Kafka/gRPC 解析器
│   ├── storage/         # ClickHouse 批写入
│   ├── cloudmeta/       # K8s 云标签（SharedInformerFactory）
│   └── config/          # 配置管理
├── Dockerfile           # v8 修复：加 libbpf-dev
├── Makefile             # 支持系统 libbpf 和本地 headers/
├── config.yaml          # v8 默认配置
└── docker-compose.yml   # ClickHouse + Prometheus + Grafana
```

## 注意事项

- **内核版本**：需要 5.8+（ring buffer）、5.10+（BPF CO-RE）
- **权限**：需要 root 或 CAP_BPF + CAP_SYS_ADMIN
- **loopback**：L7 tracer 通过 tcp_sendmsg/tcp_recvmsg kprobe 捕获，TC hook 仅用于外部接口
- **K8s**：无 K8s 环境时 cloud_meta.enabled=false，pod_ip 自动写入 0.0.0.0
