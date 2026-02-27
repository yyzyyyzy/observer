// pkg/collector/tcp_collector.go — TCP 采集器

package collector

import (
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"observer/pkg/ebpf"
	"observer/pkg/flow"
)

// TCPCollector 将 BPF TCP 事件路由到 Flow Cache，并维护 Prometheus 速率指标
type TCPCollector struct {
	cache   *flow.Cache
	metrics *Metrics

	mu            sync.Mutex
	lastStatsTime time.Time
	lastBytesSent uint64
	lastBytesRecv uint64
	lastPktsSent  uint64
	lastPktsRecv  uint64
	lastNewFlows  uint64
	lastClosed    uint64
}

func NewTCPCollector(cache *flow.Cache) *TCPCollector {
	return &TCPCollector{
		cache:         cache,
		metrics:       NewMetrics("tcp"),
		lastStatsTime: time.Now(),
	}
}

func (c *TCPCollector) HandleTCPEvent(event *ebpf.TCPEvent) {
	lc := ebpf.FlowLifecycle(event.Lifecycle)
	role := ebpf.FlowRole(event.Role)

	c.cache.HandleTCPEvent(event)

	switch lc {
	case ebpf.FlowCreate:
		c.metrics.ActiveFlows.Inc()
		c.metrics.NewFlows.Inc()
		if event.SynRTT > 0 {
			c.metrics.SynRTT.Observe(float64(event.SynRTT))
		}
		if event.SynRTTClient > 0 {
			c.metrics.SynRTTClient.Observe(float64(event.SynRTTClient))
		}
		if event.SynRTTServer > 0 {
			c.metrics.SynRTTServer.Observe(float64(event.SynRTTServer))
		}
		if event.SynRetrans > 0 {
			c.metrics.ClientSynRepeat.Add(float64(event.SynRetrans))
		}
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
		if event.RetransCount > 0 {
			c.metrics.RetransPackets.Add(float64(event.RetransCount))
			c.metrics.RetransBytes.Add(float64(event.RetransBytes))
		}
		if event.ZeroWndCount > 0 {
			c.metrics.ZeroWindowEvents.Add(float64(event.ZeroWndCount))
			c.metrics.ZeroWindowDuration.Add(float64(event.ZeroWndDuration))
		}
		if event.RSTCount > 0 && role == ebpf.RoleServer {
			c.metrics.ServerReset.Add(float64(event.RSTCount))
		}
		log.WithFields(log.Fields{
			"src":     ebpf.Uint32ToIP(event.SAddr),
			"dst":     ebpf.Uint32ToIP(event.DAddr),
			"subtype": subtype,
			"retrans": event.RetransCount,
		}).Debug("TCP FLOW_UPDATE")

	case ebpf.FlowDestroy:
		c.metrics.ActiveFlows.Dec()
		c.metrics.ClosedFlows.Inc()
		if event.RTTMean > 0 {
			c.metrics.RTT.Observe(float64(event.RTTMean))
			c.metrics.RTTMax.Set(float64(event.RTTMax))
			if event.RTTMin < 0xFFFFFFFF {
				c.metrics.RTTMin.Set(float64(event.RTTMin))
			}
		}
		if event.SRTMean > 0 {
			c.metrics.SRT.Observe(float64(event.SRTMean))
			c.metrics.SRTMax.Set(float64(event.SRTMax))
		}
		if event.TimeoutFlag != 0 {
			c.metrics.TCPTimeout.Inc()
		}
		state := ebpf.GetTCPStateName(event.TCPState)
		c.metrics.TCPStateGauge.With(map[string]string{"state": state}).Inc()
	}
}

// CalculateRates 计算并更新速率指标
func (c *TCPCollector) CalculateRates() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(c.lastStatsTime).Seconds()
	if elapsed <= 0 {
		return
	}
	c.lastStatsTime = now

	// 速率计算依赖 Flow Cache 累积统计
	// 此处预留接口，实际速率由 cache.Flush() 更新 Gauge
}

func (c *TCPCollector) Close() {
	// TCPCollector 不持有需要关闭的资源
}
