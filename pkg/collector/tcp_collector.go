package collector

import (
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"observer/pkg/ebpf"
)

type TCPCollector struct {
	mu          sync.RWMutex
	connections map[string]*ebpf.FlowInfo
	metrics     *Metrics
}

func NewTCPCollector() *TCPCollector {
	return &TCPCollector{
		connections: make(map[string]*ebpf.FlowInfo),
		metrics:     NewMetrics("tcp"),
	}
}

func (c *TCPCollector) HandleTCPEvent(event *ebpf.TCPEvent) {
	srcIP := ebpf.Uint32ToIP(event.SAddr)
	dstIP := ebpf.Uint32ToIP(event.DAddr)
	processName := ebpf.BytesToString(event.Comm[:])

	flowKey := fmt.Sprintf("%s:%d->%s:%d", srcIP, event.SPort, dstIP, event.DPort)

	c.mu.Lock()
	defer c.mu.Unlock()

	switch event.EventType {
	case ebpf.EventTypeConnect:
		flow := &ebpf.FlowInfo{
			SrcIP:       srcIP,
			DstIP:       dstIP,
			SrcPort:     event.SPort,
			DstPort:     event.DPort,
			Protocol:    "TCP",
			Direction:   "EGRESS",
			StartTime:   time.Unix(0, int64(event.TimestampNs)),
			ProcessName: processName,
			PID:         event.PID,
		}
		c.connections[flowKey] = flow
		c.metrics.ConnectionsActive.Inc()
		c.metrics.ConnectionsTotal.Inc()

		log.WithFields(log.Fields{
			"src":     srcIP,
			"dst":     dstIP,
			"sport":   event.SPort,
			"dport":   event.DPort,
			"process": processName,
			"pid":     event.PID,
		}).Debug("TCP connection initiated")

	case ebpf.EventTypeClose:
		flow, exists := c.connections[flowKey]
		if exists {
			flow.BytesSent = event.BytesSent
			flow.BytesReceived = event.BytesReceived
			flow.Duration = time.Duration(event.DurationNs)

			c.metrics.ConnectionsActive.Dec()
			c.metrics.BytesSent.Add(float64(event.BytesSent))
			c.metrics.BytesReceived.Add(float64(event.BytesReceived))

			log.WithFields(log.Fields{
				"src":            srcIP,
				"dst":            dstIP,
				"sport":          event.SPort,
				"dport":          event.DPort,
				"bytes_sent":     event.BytesSent,
				"bytes_received": event.BytesReceived,
				"duration":       flow.Duration,
			}).Info("TCP connection closed")

			delete(c.connections, flowKey)
		}
	}
}

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

func (c *TCPCollector) GetMetrics() *Metrics {
	return c.metrics
}
