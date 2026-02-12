// pkg/collector/tc_collector.go
package collector

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	log "github.com/sirupsen/logrus"
	"observer/pkg/ebpf"
)

// TCMetrics TC 层专属指标（按协议、方向、接口维度）
type TCMetrics struct {
	PacketsTotal *prometheus.CounterVec
	BytesTotal   *prometheus.CounterVec
	TCPFlagsTotal *prometheus.CounterVec // SYN/ACK/FIN/RST 分布
}

func newTCMetrics() *TCMetrics {
	return &TCMetrics{
		PacketsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "network_tc_packets_total",
			Help: "Total packets observed at TC hook",
		}, []string{"protocol", "direction", "ifindex"}),

		BytesTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "network_tc_bytes_total",
			Help: "Total bytes observed at TC hook",
		}, []string{"protocol", "direction", "ifindex"}),

		TCPFlagsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "network_tc_tcp_flags_total",
			Help: "TCP flags distribution observed at TC hook",
		}, []string{"flag", "direction"}),
	}
}

// TCCollector TC 层数据采集器
type TCCollector struct {
	mu      sync.RWMutex
	metrics *TCMetrics

	lastStatsTime time.Time
}

// NewTCCollector 创建 TC 采集器
func NewTCCollector() *TCCollector {
	return &TCCollector{
		metrics:       newTCMetrics(),
		lastStatsTime: time.Now(),
	}
}

// HandleTCPacket 实现 ebpf.TCPacketHandler 接口
func (c *TCCollector) HandleTCPacket(pkt *ebpf.TCPacket) {
	proto := ebpf.GetProtocolName(pkt.Protocol)
	dir   := ebpf.GetDirectionName(pkt.Direction)
	iface := ebpf.IfIndexToName(pkt.IfIndex)

	c.metrics.PacketsTotal.WithLabelValues(proto, dir, iface).Inc()
	c.metrics.BytesTotal.WithLabelValues(proto, dir, iface).Add(float64(pkt.PacketLen))

	// 解析并统计 TCP flags
	if pkt.Protocol == 6 && pkt.TCPFlags != 0 {
		flags := pkt.TCPFlags
		flagNames := []struct {
			mask uint8
			name string
		}{
			{0x01, "FIN"},
			{0x02, "SYN"},
			{0x04, "RST"},
			{0x08, "PSH"},
			{0x10, "ACK"},
			{0x20, "URG"},
		}
		for _, f := range flagNames {
			if flags&f.mask != 0 {
				c.metrics.TCPFlagsTotal.WithLabelValues(f.name, dir).Inc()
			}
		}
	}

	log.WithFields(log.Fields{
		"src":      ebpf.Uint32ToIP(pkt.SAddr),
		"dst":      ebpf.Uint32ToIP(pkt.DAddr),
		"sport":    pkt.SPort,
		"dport":    pkt.DPort,
		"proto":    proto,
		"dir":      dir,
		"len":      pkt.PacketLen,
		"tcpflags": pkt.TCPFlags,
	}).Debug("TC packet")
}

// GetMetrics 返回 TC 指标对象
func (c *TCCollector) GetMetrics() *TCMetrics {
	return c.metrics
}

// Close 释放资源
func (c *TCCollector) Close() error {
	log.Info("TC collector closed")
	return nil
}
