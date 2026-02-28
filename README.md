# observer — eBPF 网络可观测性 Agent

基于 eBPF 的零侵入网络可观测性采集器。通过内核 kprobe/uprobe/TC hook 无感知捕获网络流量，
对 L4 传输层和 L7 应用层进行深度解析，结果写入 ClickHouse，并通过 Prometheus + Grafana 可视化。

---

## 核心能力

| 能力 | 说明 |
|------|------|
| **TCP 流追踪** | SYN RTT、数据 RTT、服务响应时间（SRT）、重传、Zero Window、RST、连接时长 |
| **L7 协议解析** | HTTP/1.x、HTTP/2、gRPC、MySQL、Redis、DNS、Kafka、MQTT、Ping（ICMPv4/v6） |
| **L7 端口过滤** | BPF层 + Go层双重端口黑名单，消除 SSH/监控组件/Agent自身服务的噪声日志 |
| **TLS 明文捕获** | uprobe SSL_read/SSL_write，解密后透传给 HTTP/gRPC 解析器 |
| **UDP 统计** | 流量字节数、包数、连接时长 |
| **TC 包级采样** | 网卡 ingress/egress 原始包采样，支持 IPv4/IPv6 |
| **WASM 插件** | 企业自定义私有协议，wazero 纯 Go 运行时，零 CGo |
| **云原生元数据** | K8s Pod/Service 标签注入 |

---

## L7 端口过滤（DeepFlow 最佳实践）

### 问题背景

eBPF kprobe 捕获**所有 TCP 连接**的载荷，包括无法解析的流量：
- **SSH（port 22）**：payload 已加密，任何明文 parser 均不会命中
- **Agent 自身服务**（metrics :8080、ClickHouse :9000、Prometheus :9090）：自身监控通信
- **VNC/RDP**：图形协议，无 HTTP/DB 解析器匹配

这些端口会产生大量 `L7 event: no parser matched` debug 日志，浪费 ring buffer 带宽，并让 parser 链做无效遍历。

### 解决方案：双层过滤（对齐 DeepFlow l7_skip_port_set）

```
BPF 层（kretprobe submit 前）               Go 层（HandleL7Event 入口）
┌──────────────────────────┐              ┌──────────────────────────┐
│ l7_skip_ports BPF map    │              │ PortFilter [65536]bool   │
│ O(1) hash 查表           │              │ O(1) 数组索引查表         │
│ 命中 → 直接丢弃            │              │ 命中 → 立即 return        │
│ 不进入 ring buffer         │              │ 不走任何 parser           │
└──────────────────────────┘              └──────────────────────────┘
         ▲                                          ▲
         │ 写入（loadL7Programs）                   │ 初始化（NewRegistryWithFilter）
    ManagerOptions.SkipPorts              l7.NewPortFilter(cfg.EffectiveSkipPorts())
```

**层一（BPF）** 在内核态提前丢弃，减少 ring buffer 数据量（降低 CPU 拷贝开销）。

**层二（Go）** 作为补充：兼容旧版 BPF 对象（无 l7_skip_ports map）、支持运行时扩展。

### 配置方式

```yaml
l7:
  skip_ports:
    - 22      # SSH
    - 8080    # Agent HTTP（自身服务，自动推断也会加入）
    - 9000    # ClickHouse
    - 9090    # Prometheus
    - 5990    # VNC
```

**自动推断**：即使 `skip_ports` 留空，`config.EffectiveSkipPorts()` 也会自动追加：
- `http.listen` 解析出的 Agent 自身监听端口
- `advanced.pprof_port`（debug 模式）
- 内置默认黑名单 `DefaultSkipPorts`（含 22/3389/5900-5990/8080/9000/9090 等）

---

## 协议识别架构

### 设计原则（对齐 DeepFlow）

observer 的协议识别分为两个阶段：

**阶段一 — Infer（推断）**

`CanParse()` 在热路径上执行，要求 O(1) 时间复杂度，零内存分配：

- **端口专属协议**（DNS:53、Redis:6379、MySQL:3306、Kafka:9092、MQTT:1883）直接凭端口返回 `true`，不检查 payload
- **通用端口协议**（HTTP、HTTP/2、gRPC）必须同时满足结构特征才返回 `true`，避免误判

**阶段二 — Detect（精确解析）**

`Parse()` 按照协议规范进行严格解析：

- `CanParse` 通过但 `Parse` 返回 `nil` → payload 不符合该协议规范，继续尝试下一个解析器
- 一个事件只匹配第一个成功解析的协议（按注册优先级）

### 内置解析器注册顺序（= 优先级）

```
1. DNS     port=53       magic: 12 字节固定头 + QR/OPCODE 校验
2. Redis   port=6379     magic: RESP 首字节 * + - : $ （含 RESP3）
3. MySQL   port=3306     magic: 3 字节 LE 包长 + 已知命令字节集合
4. Kafka   port=9092/93  magic: BE message_size + API Key 范围 + 版本范围
5. MQTT    port=1883/88  magic: CONNECT 固定头 0x10 + "MQTT"/"MQIsdp" 字符串
6. HTTP    通用端口       magic: "GET "/"POST "/"HTTP/" ASCII 前缀
7. HTTP/2  通用端口       magic: 24 字节 PRI * preface 或严格帧头 5 AND 条件
8. gRPC    port=50051    magic: content-type: application/grpc 或 grpc-status
9. TLS     port=443/8443  SSL uprobe 已解密明文兜底（→ gRPC/HTTP2/HTTP）
```

### WASM 仅用于自定义协议

内置 9 种协议均使用原生 Go 解析器（高性能，无运行时开销）。
WASM 插件运行时（wazero，纯 Go，零 CGo）专门用于企业自定义的私有 L7 协议。
WASM 插件注册在所有内置解析器之后，不会覆盖任何标准协议。

---

## 传输层状态机

### TCP 状态（`pkg/flow`）

| 状态 | 含义 |
|------|------|
| SYN_SENT / SYN_RECV | 三次握手阶段 |
| ESTABLISHED | 连接建立，数据传输 |
| FIN_WAIT1/2 / CLOSE_WAIT | 四次挥手阶段 |
| TIME_WAIT | 等待 2MSL |
| CLOSE / CLOSING / LAST_ACK | 关闭完成 |

销毁原因：`FIN`（正常关闭）/ `RST`（异常重置）/ `TIMEOUT`（超时淘汰）

TCP 流指标：
- `syn_rtt_us` — 三次握手 RTT（SYN → SYN-ACK）
- `rtt_mean_us` / `rtt_max_us` / `rtt_min_us` — 数据包往返时延
- `srt_mean_us` / `srt_max_us` — 服务响应时间
- `retrans_count` / `retrans_bytes` — 重传统计
- `zero_wnd_count` / `zero_wnd_duration` — 零窗口统计

### UDP 统计（`pkg/ebpf`）

UDP 流以五元组为 key，记录 `bytes_sent`、`bytes_recv`、`pkts_sent`、`pkts_recv`、连接时长。

### ICMP / Ping（TC hook）

通过 TC hook 捕获 ICMP Echo Request/Reply（ICMPv4 Type 8/0，ICMPv6 Type 128/129）。
Registry 以 (ID, Sequence) 配对请求和响应，计算 RTT。

---

## TLS 明文捕获原理

```
应用进程 → SSL_write(plaintext) → [uprobe 捕获] → OpenSSL 加密 → TCP 发送
TCP 接收 → OpenSSL 解密 → SSL_read → [uretprobe 捕获] → 应用进程
```

- 挂载点：`SSL_read` / `SSL_write` / `SSL_read_ex` / `SSL_write_ex`
- 支持库：OpenSSL 1.1.x / 3.x / BoringSSL
- 捕获时机：加解密完成后，明文 buffer 在内存中可读时
- 内层协议识别：TLSParser → gRPC / HTTP/2 / HTTP/1.x

---

## CO-RE（Compile Once – Run Everywhere）

所有 eBPF 程序通过 `BPF_CORE_READ` 访问内核结构体，消除硬编码偏移：

- libbpf 在加载时根据目标内核 BTF 自动修正字段偏移
- 支持内核 4.14+（需 `CONFIG_DEBUG_INFO_BTF=y`），已在 Debian 12 / 6.12 验证

---

## 快速开始

```bash
# 安装编译依赖
apt install -y clang llvm libbpf-dev linux-headers-$(uname -r)

# 编译 eBPF + Go
make all

# 运行（需 root / CAP_BPF + CAP_NET_ADMIN）
sudo ./observer-agent --config config.yaml --log-level info
```

### 依赖

- Clang 14+
- libbpf-dev（`bpf_helpers.h` / `bpf_core_read.h`）
- Linux 内核 4.14+（BTF 支持）
- Go 1.21+

---

## 项目结构

```
bpf/
  tcp_tracer.c     — TCP 流追踪（kprobe tcp_connect/tcp_close 等）
  udp_tracer.c     — UDP 流追踪（kprobe udp_sendmsg/recvmsg）
  l7_tracer.c      — L7 载荷捕获（kprobe tcp_sendmsg/recvmsg，CO-RE）
  tls_tracer.c     — TLS 明文捕获（uprobe SSL_read/SSL_write）
  tc_tracer.c      — TC 包级采样（TC classifier，ICMP/IPv6）
  headers/
    vmlinux.h      — 内核 BTF 类型（内核 6.x 生成）
    common.h       — 公共宏和辅助函数

pkg/
  ebpf/
    types.go       — BPF 事件结构体、L7 协议枚举、TCP 状态常量
    manager.go     — eBPF 加载、kprobe/TC 挂载、事件消费循环
    tls_manager.go — libssl 路径发现、TLS uprobe 挂载管理
    utils.go       — IP 转换、comm 解析等工具函数
  l7/
    parser.go      — 协议识别框架（Registry + 两段式识别 + Session 配对）
    http.go        — HTTP/1.x 解析器（net/http 标准库）
    http2.go       — HTTP/2 帧解析器（RFC 7540）+ gRPC 解析器
    mysql.go       — MySQL 4.1+ 协议解析器（命令包/OK/ERR packet）
    redis.go       — Redis RESP2/RESP3 协议解析器
    dns.go         — DNS 解析器（RFC 1035，支持指针压缩 + AAAA）
    kafka.go       — Kafka Wire Protocol 解析器（Produce/Fetch topic 提取）
    mqtt.go        — MQTT 3.1.1/5.0 解析器（CONNECT/PUBLISH/CONNACK）
    tls.go         — TLS 明文路由（→ gRPC/HTTP2/HTTP）
    ping.go        — ICMP/ICMPv6 Echo 解析器
  flow/
    cache.go       — TCP 流缓存（LRU + TTL GC，写 tcp_flow_log）
  collector/       — eBPF 事件分发与协调
  storage/
    clickhouse.go  — ClickHouse 批量写入（tcp_flow_log / l7_flow_log）
  config/          — 配置文件加载（YAML）
  cloudmeta/       — K8s Pod/Service 元数据注入
  wasm/
    runtime.go     — wazero WASM 插件运行时（自定义协议扩展）

cmd/agent/         — 程序入口（flag 解析、组件组装）
plugins/example/   — WASM 插件示例（AssemblyScript/TinyGo）
deployments/
  clickhouse/      — 建表 SQL（tcp_flow_log / l7_flow_log）
  grafana/         — Dashboard JSON
  prometheus/      — Prometheus 采集配置
```

---

## 配置

```yaml
clickhouse:
  addr: "127.0.0.1:9000"
  database: observer
  username: default
  password: ""
  l4_batch_size: 1000
  l7_batch_size: 500
  flush_interval: 5s

ebpf:
  bpf_obj_dir: "./bpf"
  tc_interfaces: ["eth0"]
  l7_payload_size: 4096   # BPF 侧最大捕获 payload 字节数

log_level: info

wasm:
  plugins: []
  # - name: my-protocol
  #   path: ./plugins/my-protocol.wasm
  #   protocol: my-protocol
```

---

## ClickHouse 数据表

| 表名 | 内容 |
|------|------|
| `tcp_flow_log` | TCP 流完整生命周期（RTT/SRT/重传/RST/Zero Window） |
| `l7_flow_log` | L7 请求/响应配对（含 HTTP、gRPC、MySQL、Redis、DNS、Kafka、MQTT 等字段） |

---

## Prometheus 指标

| 指标名 | 类型 | 说明 |
|--------|------|------|
| `flow_syn_rtt_us` | Histogram | TCP 握手 RTT（μs） |
| `flow_rtt_mean_us` | Histogram | 数据 RTT（μs） |
| `flow_art_rtt_us` | Histogram | 服务响应时间（μs） |
| `flow_bytes_tx_total` | Counter | 发送字节数 |
| `flow_bytes_rx_total` | Counter | 接收字节数 |
| `flow_retrans_tx_total` | Counter | 重传次数 |
| `flow_destroy_reason_total` | Counter | 连接关闭原因（FIN/RST/TIMEOUT） |
| `flow_duration_us` | Histogram | 连接时长（μs） |
| `flow_cache_size` | Gauge | 活跃流缓存数量 |
