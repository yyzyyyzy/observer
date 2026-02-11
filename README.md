# 🔍 Network Observer

**高性能 eBPF 网络流量监控工具 - 使用 Ring Buffer**

基于 eBPF Ring Buffer 的轻量级、低开销网络监控系统。

## ✨ 核心特性

- 🚀 **TCP 连接追踪** - Ring Buffer 实时监控
- 📦 **UDP 流量监控** - 高效事件处理  
- 🌐 **TC 数据包捕获** - 网络接口层流量分析
- 📊 **Prometheus 集成** - 标准指标导出
- ⚡ **Ring Buffer** - 替代Perf Event Array，性能更优

## 🚀 快速开始

```bash
# 编译
make build

# 运行
sudo ./bin/network-observer \
    --tcp \
    --udp \
    --tc-interface=eth0 \
    --stats \
    --log-level=info
```

## 📊 监控指标

访问 `http://localhost:9090/metrics`

完整文档请查看代码注释。
