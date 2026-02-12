// pkg/collector/tcp_collector.go
package collector

import (
	"sync"
	"time"

	"observer/pkg/ebpf"

	log "github.com/sirupsen/logrus"
)

// TCPCollector TCP 数据采集器
type TCPCollector struct {
	mu          sync.RWMutex
	connections map[string]*ebpf.FlowInfo
	metrics     *Metrics

	// 统计窗口
	statsWindow   time.Duration
	lastStatsTime time.Time

	// 速率计算缓存
	lastBytesSent   uint64
	lastBytesRecv   uint64
	lastPacketsSent uint64
	lastPacketsRecv uint64
}

// NewTCPCollector 创建 TCP 采集器
func NewTCPCollector() *TCPCollector {
	return &TCPCollector{
		connections:   make(map[string]*ebpf.FlowInfo),
		metrics:       NewMetrics("tcp"),
		statsWindow:   60 * time.Second,
		lastStatsTime: time.Now(),
	}
}

// HandleTCPEvent 处理 TCP 事件
func (c *TCPCollector) HandleTCPEvent(event *ebpf.TCPEvent) {
	srcIP := ebpf.Uint32ToIP(event.SAddr)
	dstIP := ebpf.Uint32ToIP(event.DAddr)
	processName := ebpf.ParseCommField(event.Comm)

	flowKey := ebpf.GetFlowKey(srcIP, event.SPort, dstIP, event.DPort, "TCP")

	c.mu.Lock()
	defer c.mu.Unlock()

	switch event.EventType {
	case ebpf.EventTypeFlowStart: // ESTABLISHED
		c.handleConnect(event, flowKey, srcIP, dstIP, processName)

	case ebpf.EventTypeFlowEnd: // TCP_CLOSE
		c.handleClose(event, flowKey, srcIP, dstIP)

	case ebpf.EventTypeRetrans:
		if st, ok := c.connections[flowKey]; ok {
			st.RetransCount = event.RetransCount
			st.RetransBytes = event.RetransBytes
		}
		c.metrics.RetransPackets.Add(float64(1))

	case ebpf.EventTypeRST:
		c.metrics.ServerReset.Add(float64(1))
	}
}

func (c *TCPCollector) handleConnect(event *ebpf.TCPEvent, flowKey, srcIP, dstIP, processName string) {
	flow := &ebpf.FlowInfo{
		SrcIP:       srcIP,
		DstIP:       dstIP,
		SrcPort:     event.SPort,
		DstPort:     event.DPort,
		Protocol:    "TCP",
		Direction:   ebpf.GetDirectionName(event.Direction),
		StartTime:   time.Unix(0, int64(event.TimestampNs)),
		ProcessName: processName,
		PID:         event.PID,
	}

	c.connections[flowKey] = flow
	c.metrics.ActiveFlows.Inc()
	c.metrics.NewFlows.Inc()

	log.WithFields(log.Fields{
		"src":        srcIP,
		"dst":        dstIP,
		"sport":      event.SPort,
		"dport":      event.DPort,
		"process":    processName,
		"pid":        event.PID,
		"syn_rtt_us": event.SynRTT,
	}).Info("TCP flow started")
}

func (c *TCPCollector) handleClose(event *ebpf.TCPEvent, flowKey, srcIP, dstIP string) {
	flow, exists := c.connections[flowKey]
	if !exists {
		// FLOW_END 可能在 FLOW_START 之前到达（连接建立和关闭在同一个 tcp_set_state 调用序列里）
		// 直接从事件中更新指标，不需要依赖 connections map
		log.WithFields(log.Fields{
			"src":   srcIP,
			"dst":   dstIP,
			"sport": event.SPort,
			"dport": event.DPort,
		}).Debug("TCP FLOW_END without prior FLOW_START, updating metrics directly")
		c.updateMetricsFromEvent(event)
		c.metrics.ClosedFlows.Inc()
		return
	}

	// 更新流信息
	flow.EndTime = time.Unix(0, int64(event.TimestampNs))
	flow.Duration = flow.EndTime.Sub(flow.StartTime)
	flow.BytesSent = event.BytesSent
	flow.BytesReceived = event.BytesReceived
	flow.PacketsSent = event.PacketsSent
	flow.PacketsReceived = event.PacketsReceived

	// 时延指标
	flow.SynRTT = time.Duration(event.SynRTT) * time.Microsecond
	flow.SynRTTClient = time.Duration(event.SynRTTClient) * time.Microsecond
	flow.SynRTTServer = time.Duration(event.SynRTTServer) * time.Microsecond
	flow.RTTMean = time.Duration(event.RTTMean) * time.Microsecond
	flow.RTTMax = time.Duration(event.RTTMax) * time.Microsecond
	flow.RTTMin = time.Duration(event.RTTMin) * time.Microsecond
	flow.SRTMean = time.Duration(event.SRTMean) * time.Microsecond
	flow.SRTMax = time.Duration(event.SRTMax) * time.Microsecond

	// 性能指标
	flow.RetransCount = event.RetransCount
	flow.RetransBytes = event.RetransBytes
	flow.ZeroWndCount = event.ZeroWndCount
	flow.ZeroWndDuration = time.Duration(event.ZeroWndDuration) * time.Microsecond

	// 异常标志
	flow.SynRetransCount = event.SynRetrans
	flow.RSTCount = event.RSTCount
	flow.TimeoutOccurred = event.TimeoutFlag > 0

	// TCP 状态
	flow.TCPState = ebpf.GetTCPStateName(event.TCPState)

	// 计算重传比例
	if flow.PacketsSent > 0 {
		flow.RetransRatio = float64(flow.RetransCount) / float64(flow.PacketsSent)
	}

	// 更新 Prometheus 指标
	c.updateMetrics(flow, event)

	log.WithFields(log.Fields{
		"src":            srcIP,
		"dst":            dstIP,
		"bytes_sent":     flow.BytesSent,
		"bytes_received": flow.BytesReceived,
		"duration":       flow.Duration,
		"rtt_mean":       flow.RTTMean,
		"retrans_count":  flow.RetransCount,
	}).Info("TCP connection closed")

	delete(c.connections, flowKey)
	c.metrics.ActiveFlows.Dec()
	c.metrics.ClosedFlows.Inc()
}

func (c *TCPCollector) updateMetrics(flow *ebpf.FlowInfo, event *ebpf.TCPEvent) {
	// 吞吐指标
	c.metrics.BytesSent.Add(float64(event.BytesSent))
	c.metrics.BytesReceived.Add(float64(event.BytesReceived))
	c.metrics.PacketsSent.Add(float64(event.PacketsSent))
	c.metrics.PacketsReceived.Add(float64(event.PacketsReceived))

	// 时延指标
	if event.SynRTT > 0 {
		c.metrics.SynRTT.Observe(float64(event.SynRTT))
		c.metrics.SynRTTClient.Observe(float64(event.SynRTTClient))
		c.metrics.SynRTTServer.Observe(float64(event.SynRTTServer))
	}

	if event.RTTMean > 0 {
		c.metrics.RTT.Observe(float64(event.RTTMean))
		c.metrics.RTTMax.Set(float64(event.RTTMax))
		c.metrics.RTTMin.Set(float64(event.RTTMin))
	}

	if event.SRTMean > 0 {
		c.metrics.SRT.Observe(float64(event.SRTMean))
		c.metrics.SRTMax.Set(float64(event.SRTMax))
	}

	// 重传指标
	if event.RetransCount > 0 {
		c.metrics.RetransPackets.Add(float64(event.RetransCount))
		c.metrics.RetransBytes.Add(float64(event.RetransBytes))
		c.metrics.RetransRatio.Set(flow.RetransRatio)
	}

	// 零窗口指标
	if event.ZeroWndCount > 0 {
		c.metrics.ZeroWindowEvents.Add(float64(event.ZeroWndCount))
		c.metrics.ZeroWindowDuration.Add(float64(event.ZeroWndDuration))
	}

	// 异常指标
	if event.SynRetrans > 0 {
		if event.Direction == ebpf.FlowDirectionEgress {
			c.metrics.ClientSynRepeat.Add(float64(event.SynRetrans))
		} else {
			c.metrics.ServerSynRepeat.Add(float64(event.SynRetrans))
		}
	}

	if event.RSTCount > 0 {
		c.metrics.ServerReset.Add(float64(event.RSTCount))
	}

	// TCP 状态
	stateName := ebpf.GetTCPStateName(event.TCPState)
	c.metrics.TCPStateGauge.WithLabelValues(stateName).Inc()
}

// updateMetricsFromEvent 在没有 flow 对象时直接从 event 更新指标（FLOW_END 先到时用）
func (c *TCPCollector) updateMetricsFromEvent(event *ebpf.TCPEvent) {
	c.metrics.BytesSent.Add(float64(event.BytesSent))
	c.metrics.BytesReceived.Add(float64(event.BytesReceived))
	c.metrics.PacketsSent.Add(float64(event.PacketsSent))
	c.metrics.PacketsReceived.Add(float64(event.PacketsReceived))

	if event.SynRTT > 0 {
		c.metrics.SynRTT.Observe(float64(event.SynRTT))
		c.metrics.SynRTTClient.Observe(float64(event.SynRTTClient))
		c.metrics.SynRTTServer.Observe(float64(event.SynRTTServer))
	}
	if event.RTTMean > 0 {
		c.metrics.RTT.Observe(float64(event.RTTMean))
		c.metrics.RTTMax.Set(float64(event.RTTMax))
		c.metrics.RTTMin.Set(float64(event.RTTMin))
	}
	if event.RetransCount > 0 {
		c.metrics.RetransPackets.Add(float64(event.RetransCount))
		c.metrics.RetransBytes.Add(float64(event.RetransBytes))
	}
	if event.ZeroWndCount > 0 {
		c.metrics.ZeroWindowEvents.Add(float64(event.ZeroWndCount))
	}
	stateName := ebpf.GetTCPStateName(event.TCPState)
	c.metrics.TCPStateGauge.WithLabelValues(stateName).Inc()

	log.WithFields(log.Fields{
		"src":            ebpf.Uint32ToIP(event.SAddr),
		"dst":            ebpf.Uint32ToIP(event.DAddr),
		"sport":          event.SPort,
		"dport":          event.DPort,
		"bytes_sent":     event.BytesSent,
		"bytes_received": event.BytesReceived,
		"syn_rtt_us":     event.SynRTT,
		"rtt_mean_us":    event.RTTMean,
		"retrans":        event.RetransCount,
		"duration_us":    event.DurationNs,
		"process":        ebpf.ParseCommField(event.Comm),
	}).Info("TCP flow closed")
}
func (c *TCPCollector) CalculateRates() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(c.lastStatsTime).Seconds()

	if elapsed == 0 {
		return
	}

	// 获取当前总量（从 Prometheus Counter 读取）
	// 注意：这里简化处理，实际应该从 eBPF Map 中读取
	var totalBytesSent, totalBytesRecv uint64
	var totalPacketsSent, totalPacketsRecv uint64

	for _, flow := range c.connections {
		totalBytesSent += flow.BytesSent
		totalBytesRecv += flow.BytesReceived
		totalPacketsSent += flow.PacketsSent
		totalPacketsRecv += flow.PacketsReceived
	}

	// 计算速率
	bytesDelta := totalBytesSent + totalBytesRecv - c.lastBytesSent - c.lastBytesRecv
	packetsDelta := totalPacketsSent + totalPacketsRecv - c.lastPacketsSent - c.lastPacketsRecv

	bps := float64(bytesDelta) / elapsed
	pps := float64(packetsDelta) / elapsed

	c.metrics.BytesPerSecond.Set(bps)
	c.metrics.PacketsPerSecond.Set(pps)

	// 更新缓存
	c.lastBytesSent = totalBytesSent
	c.lastBytesRecv = totalBytesRecv
	c.lastPacketsSent = totalPacketsSent
	c.lastPacketsRecv = totalPacketsRecv
	c.lastStatsTime = now
}

// GetActiveConnections 获取活跃连接列表
func (c *TCPCollector) GetActiveConnections() []*ebpf.FlowInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	flows := make([]*ebpf.FlowInfo, 0, len(c.connections))
	for _, flow := range c.connections {
		flowCopy := *flow
		flows = append(flows, &flowCopy)
	}
	return flows
}

// GetMetrics 获取指标对象
func (c *TCPCollector) GetMetrics() *Metrics {
	return c.metrics
}

// GetConnectionCount 获取连接数
func (c *TCPCollector) GetConnectionCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.connections)
}

// Close 清理资源
func (c *TCPCollector) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.connections = nil
	log.Info("TCP collector closed")
	return nil
}

// GCStaleConnections 清理超过 maxAge 未更新的过期连接
func (c *TCPCollector) GCStaleConnections(maxAge time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	var removed int
	for key, flow := range c.connections {
		if now.Sub(flow.StartTime) > maxAge {
			delete(c.connections, key)
			c.metrics.ActiveFlows.Dec()
			removed++
		}
	}
	if removed > 0 {
		log.WithField("removed", removed).Debug("GC stale TCP connections")
	}
}
