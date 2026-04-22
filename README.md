# Observer — eBPF Network Observability Agent

高性能、无侵入式网络可观测性 Agent，基于 eBPF CO-RE 技术，深度对齐 DeepFlow 架构设计。

## 架构概览

```
┌─────────────────────────────────────────────────────────────────┐
│                         内核态 eBPF                              │
│                                                                  │
│  tcp_tracer         udp_tracer        fd_sock_tracer            │
│  10 kprobes         3 hooks           sys_enter/exit hooks      │
│  RTT/SRT/重传       UDP 流聚合         PID+FD → 四元组 Map        │
│                                                                  │
│  l7_inference_tracer              tls_tracer                    │
│  协议推断（BPF Tail Call）         OpenSSL uprobe                 │
│  HTTP/MySQL/Redis/DNS/Kafka       SSL_read/SSL_write            │
│  只提取关键元数据                                                  │
│                                                                  │
│  go_tls_tracer                    l7_tracer                     │
│  crypto/tls.(*Conn).Write/Read    tcp_sendmsg/recvmsg           │
│  Go ABI Register 参数读取          全量 payload 上传（兜底）       │
│                                                                  │
│  tc_tracer                                                       │
│  TC ingress + egress，IPv4/IPv6/VLAN                            │
└─────────────────────────────────────────────────────────────────┘
                              ↓ RingBuf
┌─────────────────────────────────────────────────────────────────┐
│                          用户态 Go                               │
│                                                                  │
│  Manager（ebpf 包）                                              │
│  ├── TCP/UDP/TC/TLS/GoTLS/L7/L7Meta 事件循环                     │
│  ├── LookupSockTuple()  FD→Socket L1 快路径查询                  │
│  └── goTLSDiscoveryLoop() 60s 增量 Go 进程扫描                   │
│                                                                  │
│  Dispatcher（collector 包）                                      │
│  ├── TCP → TCPCollector → Flow Cache                            │
│  ├── UDP → UDPCollector → UDP Flow Cache                        │
│  ├── L7 UDP → UDPDispatcher（DNS/NTP 配对写入）                  │
│  └── L7Meta → L7MetaDispatcher（内核推断直写 ClickHouse）         │
│                                                                  │
│  L7 Registry（l7 包）                                            │
│  └── 全量 payload → HTTP/HTTP2/gRPC/MySQL/Redis/DNS/Kafka        │
│      /MQTT/TLS/ICMP 解析器 → 请求响应配对 → ClickHouse           │
└─────────────────────────────────────────────────────────────────┘
```

## 核心能力

### L4 流量追踪
- TCP FLOW_CREATE / FLOW_UPDATE / FLOW_DESTROY 全生命周期
- SYN RTT（三次握手三阶段精确拆分）
- 数据层 RTT min/avg/max，SRT（服务端响应时延）
- 重传包数 / 字节数，Zero-Window 次数 / 总时长
- UDP 流聚合（LRU Hash，idle timeout GC）
- 角色精确判断：CLIENT / SERVER（基于 inet_csk_accept / tcp_connect）
- **FD→Socket 内核态映射**：`pid_fd_sock_map`（pid+fd / pid+sport 双索引）

### L7 协议解析
- HTTP/1.x、HTTP/2、gRPC、MySQL、Redis RESP、DNS（TCP+UDP）
- Kafka、MQTT、TLS 握手元数据、ICMP/Ping
- 请求/响应配对，响应时延（ResponseUs）

### TLS 明文捕获
- **OpenSSL / BoringSSL**：`SSL_read` / `SSL_write` uprobe
- **Go crypto/tls**：`(*Conn).Read` / `(*Conn).Write` uprobe（Go Register ABI，amd64）
- 四元组补全：L1 = BPF `pid_fd_sock_map`（µs 级），L2 = `/proc/net/tcp`（ms 级降级）
- Go 二进制增量发现：每 60 秒扫描新进程自动附加 uprobe

### 内核态 L7 协议推断
- `l7_inference_tracer.c`：kretprobe 内推断协议，仅提取关键元数据（无 payload 拷贝）
- 支持：HTTP（method/status/URL hash）、MySQL（cmd）、Redis（cmd 前 7 字节）、DNS（txid/QR）、Kafka（api_key/correlation_id）
- 百万级 QPS 场景下显著降低 CPU 和 RingBuf 压力
- 无法推断的协议自动降级到 `l7_tracer.c` 全量 payload 路径

### UDP L7 解析
- `UDPDispatcher`：路由 UDP payload 到 DNS/NTP 等协议解析器
- DNS 基于事务 ID 配对请求/响应，计算 response_us 并写入 l7_flow_log
- NTP mode 字段提取

## 目录结构

```
bpf/
  tcp_tracer.c            TCP 流追踪（10 kprobe）
  udp_tracer.c            UDP 流追踪
  l7_tracer.c             L7 载荷捕获（全量 payload 兜底）
  tls_tracer.c            OpenSSL/BoringSSL uprobe
  go_tls_tracer.c         Go crypto/tls uprobe（Register ABI）
  fd_sock_tracer.c        FD→Socket 四元组内核态映射
  l7_inference_tracer.c   内核态协议推断（BPF 元数据提取）
  tc_tracer.c             TC 分类器
  headers/common.h        公共常量

pkg/
  ebpf/
    manager.go              eBPF 加载、事件循环
    fd_sock_manager.go      FD→Socket Map + Go TLS uprobe
    l7_inference_manager.go 内核推断元数据事件
    tls_manager.go          OpenSSL uprobe
    types.go / utils.go
  collector/
    dispatcher.go           统一事件分发（含 UDP L7 + L7Meta）
    udp_l7_dispatcher.go    UDP L7 协议分发（DNS/NTP）
    l7_meta_dispatcher.go   内核推断结果 → ClickHouse
    tcp_collector.go / udp_collector.go / tc_collector.go
  l7/                       L7 协议解析器（HTTP/MySQL/Redis/DNS/Kafka/...）
  flow/                     TCP/UDP 流状态机
  storage/                  ClickHouse 写入
```

## 快速开始

```bash
# 编译所有 BPF 程序 + Go Agent
make all

# 启动（需要 root）
sudo ./observer-agent --config config.yaml --log-level debug

# Docker Compose（含 ClickHouse + Prometheus + Grafana）
make up
```

### 依赖
- Linux kernel ≥ 5.8（BPF Ring Buffer / CO-RE）
- clang ≥ 12，Go ≥ 1.21
- libbpf-dev（可选）

## 配置

```yaml
ebpf:
  bpf_obj_dir: "./bpf"
  max_flows: 65536

l7:
  enabled: true
  skip_ports: [443, 9090]   # BPF 层 + Go 层双重端口过滤

collector:
  tc:
    interfaces: ["eth0"]    # TC 监听网卡（空则禁用）

clickhouse:
  enabled: true
  addr: "localhost:9000"
```

## WASM 自定义协议

通过 wazero 热加载私有协议解析插件，无需重新编译 Agent：

```yaml
wasm:
  enabled: true
  plugins:
    - path: "./plugins/myplugin/myplugin.wasm"
```

## Prometheus 指标

| 指标 | 说明 |
|------|------|
| `observer_tcp_flows_total` | TCP 流总数 |
| `observer_tcp_active_flows` | 当前活跃连接数 |
| `observer_tcp_rtt_mean_us` | RTT 均值（µs 直方图）|
| `observer_tcp_srt_mean_us` | SRT 均值（µs 直方图）|
| `observer_l7_requests_total` | L7 请求数（按协议/方法）|
| `observer_tc_packets_total` | TC 捕获包数 |
