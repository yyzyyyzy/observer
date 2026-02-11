package collector

import (
	"sync"
	"sync/atomic"

	log "github.com/sirupsen/logrus"
	"observer/pkg/ebpf"
)

type UDPCollector struct {
	mu          sync.RWMutex
	packetCount atomic.Int64
	bytesSent   atomic.Int64
	bytesRecv   atomic.Int64
	metrics     *Metrics
}

func NewUDPCollector() *UDPCollector {
	return &UDPCollector{
		metrics: NewMetrics("udp"),
	}
}

func (c *UDPCollector) HandleUDPEvent(event *ebpf.UDPEvent) {
	processName := ebpf.BytesToString(event.Comm[:])

	c.packetCount.Add(1)

	if event.Direction == ebpf.FlowDirectionEgress {
		c.bytesSent.Add(int64(event.PacketSize))
		c.metrics.BytesSent.Add(float64(event.PacketSize))
		c.metrics.PacketsSent.Inc()
	} else {
		c.bytesRecv.Add(int64(event.PacketSize))
		c.metrics.BytesReceived.Add(float64(event.PacketSize))
		c.metrics.PacketsReceived.Inc()
	}

	if c.packetCount.Load()%1000 == 0 {
		direction := "EGRESS"
		if event.Direction == ebpf.FlowDirectionIngress {
			direction = "INGRESS"
		}

		log.WithFields(log.Fields{
			"direction": direction,
			"size":      event.PacketSize,
			"process":   processName,
			"pid":       event.PID,
		}).Debug("UDP packet")
	}
}

func (c *UDPCollector) GetActiveFlows() []*ebpf.FlowInfo {
	return []*ebpf.FlowInfo{}
}

func (c *UDPCollector) GetMetrics() *Metrics {
	return c.metrics
}

func (c *UDPCollector) GetStats() map[string]int64 {
	return map[string]int64{
		"total_packets": c.packetCount.Load(),
		"bytes_sent":    c.bytesSent.Load(),
		"bytes_recv":    c.bytesRecv.Load(),
	}
}
