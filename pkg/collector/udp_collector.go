// pkg/collector/udp_collector.go — UDP 采集器

package collector

import (
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"observer/pkg/ebpf"
	"observer/pkg/flow"
)

// UDPCollector 将 BPF UDP 事件委托给 UDPCache 做流聚合
type UDPCollector struct {
	cache   *flow.UDPCache
	metrics *Metrics

	mu            sync.Mutex
	lastStatsTime time.Time
	totalBytesSent uint64
	totalBytesRecv uint64
	totalPktsSent  uint64
	totalPktsRecv  uint64

	prevBytesSent uint64
	prevBytesRecv uint64
	prevPktsSent  uint64
	prevPktsRecv  uint64
}

func NewUDPCollector() *UDPCollector {
	return &UDPCollector{
		cache:         flow.NewUDPCache(flow.CacheConfig{}, nil, nil),
		metrics:       NewMetrics("udp"),
		lastStatsTime: time.Now(),
	}
}

func NewUDPCollectorWithDeps(cache *flow.UDPCache) *UDPCollector {
	return &UDPCollector{
		cache:         cache,
		metrics:       NewMetrics("udp"),
		lastStatsTime: time.Now(),
	}
}

func (c *UDPCollector) HandleUDPEvent(event *ebpf.UDPFlowEvent) {
	c.cache.HandleUDPEvent(event)

	c.mu.Lock()
	if event.Direction == ebpf.FlowDirectionEgress {
		c.totalBytesSent += uint64(event.PacketSize)
		c.totalPktsSent++
	} else {
		c.totalBytesRecv += uint64(event.PacketSize)
		c.totalPktsRecv++
	}
	c.mu.Unlock()

	if ebpf.UDPEventType(event.EventType) == ebpf.UDPFlowNew {
		c.metrics.ActiveFlows.Inc()
		c.metrics.NewFlows.Inc()
	}

	log.WithFields(log.Fields{
		"src":      ebpf.Uint32ToIP(event.SAddr),
		"dst":      ebpf.Uint32ToIP(event.DAddr),
		"sport":    event.SPort,
		"dport":    event.DPort,
		"type":     ebpf.UDPEventType(event.EventType),
		"role":     ebpf.FlowRole(event.Role),
		"pkt_size": event.PacketSize,
	}).Debug("UDP flow event")
}

// CalculateRates 计算并更新 BPS / PPS 速率指标（定期调用）
func (c *UDPCollector) CalculateRates() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(c.lastStatsTime).Seconds()
	if elapsed <= 0 {
		return
	}

	sentDelta := c.totalBytesSent - c.prevBytesSent
	recvDelta := c.totalBytesRecv - c.prevBytesRecv
	pktSentDelta := c.totalPktsSent - c.prevPktsSent
	pktRecvDelta := c.totalPktsRecv - c.prevPktsRecv

	totalBytes := float64(sentDelta+recvDelta) / elapsed
	totalPkts := float64(pktSentDelta+pktRecvDelta) / elapsed

	c.metrics.BytesPerSecond.Set(totalBytes)
	c.metrics.PktsPerSecond.Set(totalPkts)

	c.prevBytesSent = c.totalBytesSent
	c.prevBytesRecv = c.totalBytesRecv
	c.prevPktsSent  = c.totalPktsSent
	c.prevPktsRecv  = c.totalPktsRecv
	c.lastStatsTime = now
}

func (c *UDPCollector) Close() {}
