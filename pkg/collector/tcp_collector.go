// pkg/collector/tcp_collector.go
// TCP 采集器 v3 — DeepFlow 对齐
//
// 职责简化：该层只负责：
//   1. 将 BPF 事件转发给 Flow Cache（Flow Cache 维护完整状态）
//   2. 维护 Prometheus 兼容的速率指标（BPS/PPS/ActiveFlows）
//   3. 暴露 GetActiveFlows()（从 Flow Cache 查询）
//
// 详细的 Flow 生命周期管理、指标刷新、aging 全部由 pkg/flow.Cache 负责。
package collector

import (
	"sync"
	"time"

	"observer/pkg/ebpf"
	"observer/pkg/flow"

	log "github.com/sirupsen/logrus"
)

// TCPCollector 是 ebpf.TCPEventHandler 的实现
type TCPCollector struct {
	cache   *flow.Cache
	metrics *Metrics

	mu            sync.Mutex
	lastStatsTime time.Time
	lastBytesSent uint64
	lastBytesRecv uint64
}

// NewTCPCollector 创建 TCP 采集器，注入 Flow Cache
func NewTCPCollector(cache *flow.Cache) *TCPCollector {
	return &TCPCollector{
		cache:         cache,
		metrics:       NewMetrics("tcp"),
		lastStatsTime: time.Now(),
	}
}

// HandleTCPEvent 实现 ebpf.TCPEventHandler
// 所有事件直接转发给 Flow Cache，由 Cache 负责状态维护和指标刷新
func (c *TCPCollector) HandleTCPEvent(event *ebpf.TCPEvent) {
	lc := ebpf.FlowLifecycle(event.Lifecycle)
	role := ebpf.FlowRole(event.Role)

	// 委托给 Flow Cache
	c.cache.HandleTCPEvent(event)

	// 更新 Prometheus ActiveFlows gauge（保持向后兼容）
	switch lc {
	case ebpf.FlowCreate:
		c.metrics.ActiveFlows.Inc()
		c.metrics.NewFlows.Inc()
		log.WithFields(log.Fields{
			"src":        ebpf.Uint32ToIP(event.SAddr),
			"dst":        ebpf.Uint32ToIP(event.DAddr),
			"sport":      event.SPort,
			"dport":      event.DPort,
			"role":       role,
			"syn_rtt_us": event.SynRTT,
			"process":    ebpf.ParseCommField(event.Comm),
		}).Debug("TCP FLOW_CREATE")

	case ebpf.FlowUpdate:
		subtype := ebpf.EventSubtype(event.EventSubtype)
		log.WithFields(log.Fields{
			"src":     ebpf.Uint32ToIP(event.SAddr),
			"dst":     ebpf.Uint32ToIP(event.DAddr),
			"subtype": subtype,
			"retrans": event.RetransCount,
		}).Debug("TCP FLOW_UPDATE")

	case ebpf.FlowDestroy:
		c.metrics.ActiveFlows.Dec()
		c.metrics.ClosedFlows.Inc()
	}
}

// CalculateRates 计算并更新 BPS/PPS 速率指标（定期调用）
func (c *TCPCollector) CalculateRates() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(c.lastStatsTime).Seconds()
	if elapsed <= 0 {
		return
	}

	// 从 Flow Cache 聚合当前活跃流的字节数
	var totalSent, totalRecv uint64
	for _, f := range c.cache.ActiveFlows() {
		totalSent += f.BytesSent
		totalRecv += f.BytesReceived
	}

	bytesDelta := (totalSent + totalRecv) - (c.lastBytesSent + c.lastBytesRecv)
	c.metrics.BytesPerSecond.Set(float64(bytesDelta) / elapsed)

	c.lastBytesSent = totalSent
	c.lastBytesRecv = totalRecv
	c.lastStatsTime = now
}

// GetMetrics 返回 Prometheus 指标对象
func (c *TCPCollector) GetMetrics() *Metrics {
	return c.metrics
}

// GetConnectionCount 返回当前活跃连接数（从 Flow Cache 查询）
func (c *TCPCollector) GetConnectionCount() int {
	return c.cache.Size()
}

// Close 清理资源
func (c *TCPCollector) Close() error {
	log.Info("TCP collector closed")
	return nil
}
