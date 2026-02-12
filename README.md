# Network Observer - 增强版

基于 eBPF 的网络性能可观测性平台，对标 DeepFlow 的网络指标能力。

## 功能特性

### 核心能力
- ✅ **零侵入采集**：基于 eBPF 的内核态数据采集
- ✅ **全栈时延分析**：建连、传输、系统时延细分
- ✅ **TCP 性能监控**：重传、零窗口、异常检测
- ✅ **实时指标导出**：Prometheus 格式指标
- ✅ **可视化分析**：Grafana Dashboard

### 指标体系（对标 DeepFlow）

#### 1. 吞吐指标
- 网络层：字节数、包数、速率（BPS/PPS）
- 传输层：新建连接、关闭连接、活跃连接

#### 2. 时延指标
- 建连时延：SYN RTT、客户端/服务端建连时延
- 数据传输时延：平均 RTT、最大/最小 RTT
- 系统时延：平均 SRT、最大 SRT

#### 3. TCP 性能指标
- 重传：重传包数、重传字节数、重传比例
- 零窗口：零窗口次数、零窗口时长

#### 4. TCP 异常指标
- 建连异常：SYN 重传、建连失败、队列溢出
- 传输异常：端口复用、RST、超时
- 断连异常：半关闭缺失

## 快速开始

### 系统要求
- Linux Kernel >= 5.4（推荐 5.10+）
- 支持 BTF（BPF Type Format）
- Root 权限

### 编译

```bash
# 安装依赖
sudo apt-get install -y clang llvm libbpf-dev

# 编译 eBPF 程序
make bpf

# 编译 Agent
make build
```

### 运行

```bash
# 运行 Agent
sudo ./bin/observer-agent --config config.yaml

# 查看指标
curl http://localhost:8080/metrics
```

### Docker 部署

```bash
# 构建镜像
docker build -t network-observer:latest .

# 运行容器（需要特权模式）
docker run --privileged \
  --pid=host \
  --network=host \
  -v /sys/kernel/debug:/sys/kernel/debug \
  network-observer:latest
```

## 配置

配置文件 `config.yaml`：

```yaml
# HTTP 服务配置
http:
  listen: ":8080"
  metrics_path: "/metrics"

# eBPF 配置
ebpf:
  # Perf buffer 大小（字节）
  perf_buffer_size: 262144  # 256KB
  
  # 连接追踪 Map 大小
  max_flows: 10240
  
  # 采样率（1-100，100 表示全量采集）
  sampling_rate: 100

# 日志配置
log:
  level: "info"  # debug, info, warn, error
  format: "json" # json, text
```

## 指标说明

### 吞吐指标

| 指标名称 | 类型 | 说明 |
|---------|------|------|
| `network_tcp_bytes_sent_total` | Counter | 发送字节总数 |
| `network_tcp_bytes_received_total` | Counter | 接收字节总数 |
| `network_tcp_packets_sent_total` | Counter | 发送包总数 |
| `network_tcp_packets_received_total` | Counter | 接收包总数 |
| `network_tcp_bytes_per_second` | Gauge | 字节速率 (Bps) |
| `network_tcp_packets_per_second` | Gauge | 包速率 (pps) |

### 时延指标

| 指标名称 | 类型 | 说明 |
|---------|------|------|
| `network_tcp_syn_rtt_microseconds` | Histogram | 完整建连时延（微秒） |
| `network_tcp_syn_rtt_client_microseconds` | Histogram | 客户端建连时延（微秒） |
| `network_tcp_syn_rtt_server_microseconds` | Histogram | 服务端建连时延（微秒） |
| `network_tcp_rtt_microseconds` | Histogram | 平均 RTT（微秒） |
| `network_tcp_rtt_max_microseconds` | Gauge | 最大 RTT（微秒） |

### 性能指标

| 指标名称 | 类型 | 说明 |
|---------|------|------|
| `network_tcp_retrans_packets_total` | Counter | 重传包总数 |
| `network_tcp_retrans_bytes_total` | Counter | 重传字节总数 |
| `network_tcp_retrans_ratio` | Gauge | 重传比例 |
| `network_tcp_zero_window_events_total` | Counter | 零窗口事件总数 |
| `network_tcp_zero_window_duration_microseconds_total` | Counter | 零窗口总时长（微秒） |

### 异常指标

| 指标名称 | 类型 | 说明 |
|---------|------|------|
| `network_tcp_client_syn_repeat_total` | Counter | 客户端 SYN 重传 |
| `network_tcp_client_establish_fail_total` | Counter | 客户端建连失败 |
| `network_tcp_server_queue_overflow_total` | Counter | 服务端队列溢出 |
| `network_tcp_rst_total` | Counter | RST 事件总数 |
| `network_tcp_timeout_total` | Counter | 超时事件总数 |

## Grafana Dashboard

预置了 3 个 Dashboard：

1. **网络性能总览** - 吞吐、时延、异常一览
2. **TCP 时延分析** - 建连、传输、系统时延详细分析
3. **TCP 异常监控** - 各类异常事件监控和 Top N

导入方式：
```bash
# 导入 Dashboard
curl -X POST http://grafana:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @deployments/grafana/network-overview.json
```

## 开发指南

### 项目结构

```
observer-enhanced/
├── bpf/                    # eBPF 程序
│   ├── headers/           # 头文件
│   ├── tcp_tracer.c       # TCP 追踪器
│   ├── udp_tracer.c       # UDP 追踪器
│   └── tc_tracer.c        # TC Hook
├── cmd/
│   └── agent/             # Agent 主程序
│       └── main.go
├── pkg/
│   ├── ebpf/             # eBPF 管理
│   │   ├── types.go      # 数据结构
│   │   ├── manager.go    # eBPF 程序管理
│   │   └── loader.go     # 程序加载器
│   ├── collector/        # 数据采集器
│   │   ├── metrics.go    # 指标定义
│   │   ├── tcp_collector.go
│   │   └── dispatcher.go
│   └── config/           # 配置管理
│       └── config.go
├── deployments/          # 部署配置
│   ├── grafana/         # Grafana Dashboards
│   ├── prometheus/      # Prometheus 配置
│   └── docker/          # Docker 配置
├── docs/                # 文档
├── Makefile
├── go.mod
└── README.md
```

### 添加新指标

1. 在 `bpf/tcp_tracer.c` 中添加采集逻辑
2. 在 `pkg/ebpf/types.go` 中定义事件结构
3. 在 `pkg/collector/metrics.go` 中添加 Prometheus 指标
4. 在 `pkg/collector/tcp_collector.go` 中处理事件

### 测试

```bash
# 单元测试
make test

# 集成测试
make test-integration

# 性能测试
make benchmark
```

## 性能

在生产环境测试数据：

- **CPU 开销**：< 3%（1000 连接/秒）
- **内存占用**：< 300MB（10000 活跃连接）
- **事件处理**：> 100K events/sec
- **时延精度**：微秒级

## 故障排查

### eBPF 程序加载失败

```bash
# 检查内核版本
uname -r

# 检查 BTF 支持
ls /sys/kernel/btf/vmlinux

# 查看详细错误
sudo dmesg | tail -n 50
```

### 指标不更新

```bash
# 检查 eBPF 程序状态
sudo bpftool prog show

# 检查 Map 状态
sudo bpftool map show

# 查看事件输出
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## 贡献

欢迎提交 Issue 和 Pull Request！

## 许可证

Apache License 2.0

## 参考资料

- [DeepFlow 文档](https://deepflow.io/docs/)
- [eBPF 文档](https://ebpf.io/)
- [BCC 工具集](https://github.com/iovisor/bcc)
- [Cilium eBPF](https://github.com/cilium/ebpf)

## 作者

Network Observer Team

## 更新日志

### v2.0.0 (2024-02)
- ✨ 新增完整的时延指标体系
- ✨ 新增 TCP 性能和异常监控
- 🎨 优化 eBPF 程序性能
- 📝 完善文档和 Dashboard

### v1.0.0 (2024-01)
- 🎉 初始版本发布
- ✅ 基础吞吐指标
- ✅ TCP/UDP 追踪
