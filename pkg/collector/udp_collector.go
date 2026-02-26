// pkg/collector/udp_collector.go
// UDP 采集器 —— 委托 UDPCache 进行流聚合、ClickHouse 写入、云标签注入

package collector

import (
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"observer/pkg/ebpf"
	"observer/pkg/flow"
)

// UDPCollector UDP 数据采集器
type UDPCollector struct {
	cache   *flow.UDPCache
	metrics *Metrics

	mu            sync.Mutex
	lastStatsTime time.Time
	lastBytesSent uint64
	lastBytesRecv uint64
}

// NewUDPCollector 创建简化的 UDP 采集器（不带 ClickHouse）
func NewUDPCollector() *UDPCollector {
	return &UDPCollector{
		cache:         flow.NewUDPCache(flow.CacheConfig{}, nil, nil),
		metrics:       NewMetrics("udp"),
		lastStatsTime: time.Now(),
	}
}

// NewUDPCollectorWithDeps 创建带 UDPCache 的 UDP 采集器
func NewUDPCollectorWithDeps(cache *flow.UDPCache) *UDPCollector {
	return &UDPCollector{
		cache:         cache,
		metrics:       NewMetrics("udp"),
		lastStatsTime: time.Now(),
	}
}

// HandleUDPEvent 实现 ebpf.UDPEventHandler 接口
func (c *UDPCollector) HandleUDPEvent(event *ebpf.UDPFlowEvent) {
	// 委托给 UDPCache 做流聚合、云标签注入、ClickHouse 写入
	c.cache.HandleUDPEvent(event)

	// 更新本地字节统计（用于速率计算）
	c.mu.Lock()
	if event.Direction == ebpf.FlowDirectionEgress {
		c.lastBytesSent += uint64(event.PacketSize)
	} else {
		c.lastBytesRecv += uint64(event.PacketSize)
	}
	c.mu.Unlock()

	// NEW 事件：更新活跃流计数
	if ebpf.UDPEventType(event.EventType) == ebpf.UDPFlowNew {
		c.metrics.ActiveFlows.Inc()
		c.metrics.NewFlows.Inc()
	}

	log.WithFields(log.Fields{
		"src":         ebpf.Uint32ToIP(event.SAddr),
		"dst":         ebpf.Uint32ToIP(event.DAddr),
		"sport":       event.SPort,
		"dport":       event.DPort,
		"type":        ebpf.UDPEventType(event.EventType),
		"role":        ebpf.FlowRole(event.Role),
		"pkt_size":    event.PacketSize,
		"total_bytes": event.TotalBytes,
	}).Debug("UDP flow event")
}

// CalculateRates 计算并更新 BPS 速率（定期调用）
func (c *UDPCollector) CalculateRates() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(c.lastStatsTime).Seconds()
	if elapsed <= 0 {
		return
	}

	total := c.lastBytesSent + c.lastBytesRecv
	c.metrics.BytesPerSecond.Set(float64(total) / elapsed)

	c.lastBytesSent = 0
	c.lastBytesRecv = 0
	c.lastStatsTime = now
}

// RunGC 触发 UDP 流超时清理（建议每 30s 调用）
func (c *UDPCollector) RunGC() int {
	n := c.cache.RunGC()
	if n > 0 {
		c.metrics.ClosedFlows.Add(float64(n))
		c.metrics.ActiveFlows.Sub(float64(n))
	}
	return n
}

func (c *UDPCollector) GetMetrics() *Metrics { return c.metrics }
func (c *UDPCollector) CacheSize() int       { return c.cache.Size() }
func (c *UDPCollector) Close() error {
	log.Info("UDP collector closed")
	return nil
}
