package collector

import (
	"sync"
	"sync/atomic"

	"observer/pkg/ebpf"

	log "github.com/sirupsen/logrus"
)

type TCCollector struct {
	mu             sync.RWMutex
	packetCount    atomic.Int64
	ingressBytes   atomic.Int64
	egressBytes    atomic.Int64
	ingressPackets atomic.Int64
	egressPackets  atomic.Int64
	metrics        *Metrics
}

func NewTCCollector() *TCCollector {
	return &TCCollector{
		metrics: NewMetrics("tc"),
	}
}

func (c *TCCollector) HandleTCPacket(packet *ebpf.TCPacket) {
	srcIP := ebpf.Uint32ToIP(packet.SAddr)
	dstIP := ebpf.Uint32ToIP(packet.DAddr)

	protocol := "UNKNOWN"
	switch packet.Protocol {
	case ebpf.ProtocolTCP:
		protocol = "TCP"
	case ebpf.ProtocolUDP:
		protocol = "UDP"
	}

	direction := "INGRESS"
	if packet.Direction == ebpf.FlowDirectionEgress {
		direction = "EGRESS"
		c.egressBytes.Add(int64(packet.PacketLen))
		c.egressPackets.Add(1)
		c.metrics.BytesSent.Add(float64(packet.PacketLen))
		c.metrics.PacketsSent.Inc()
	} else {
		c.ingressBytes.Add(int64(packet.PacketLen))
		c.ingressPackets.Add(1)
		c.metrics.BytesReceived.Add(float64(packet.PacketLen))
		c.metrics.PacketsReceived.Inc()
	}

	c.packetCount.Add(1)

	if c.packetCount.Load()%1000 == 0 {
		log.WithFields(log.Fields{
			"src":       srcIP,
			"dst":       dstIP,
			"sport":     packet.SPort,
			"dport":     packet.DPort,
			"protocol":  protocol,
			"direction": direction,
			"len":       packet.PacketLen,
			"ifindex":   packet.IfIndex,
		}).Debug("TC packet captured")
	}
}

func (c *TCCollector) GetStats() map[string]int64 {
	return map[string]int64{
		"total_packets":   c.packetCount.Load(),
		"ingress_bytes":   c.ingressBytes.Load(),
		"egress_bytes":    c.egressBytes.Load(),
		"ingress_packets": c.ingressPackets.Load(),
		"egress_packets":  c.egressPackets.Load(),
	}
}

func (c *TCCollector) GetMetrics() *Metrics {
	return c.metrics
}
