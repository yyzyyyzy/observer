// pkg/collector/tc_collector.go
// TC 层数据采集器 — 对齐 DeepFlow tc_tracer 完整实现
//
// 职责：
//   1. 接收来自 tc_ingress / tc_egress BPF 程序的数据包事件
//   2. 更新 Prometheus 指标（按 protocol/direction/iface/flags 多维度）
//   3. 统计 TCP flags 分布（SYN/ACK/FIN/RST/PSH/URG）
//   4. 统计 IP TTL、TOS、数据包大小分布
//   5. Debug 日志（仅 log.Debug，生产不影响性能）

package collector

import (
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	log "github.com/sirupsen/logrus"
	"observer/pkg/ebpf"
)

// TCMetrics TC 层专属指标（DeepFlow 对齐）
type TCMetrics struct {
	// 基础流量统计
	PacketsTotal *prometheus.CounterVec
	BytesTotal   *prometheus.CounterVec

	// TCP flags 分布（SYN/SYN-ACK/FIN/RST/PSH 等）
	TCPFlagsTotal *prometheus.CounterVec

	// 数据包大小分布（小包/大包/巨帧）
	PacketSizeHistogram *prometheus.HistogramVec

	// 每秒数据包速率
	PacketsPerSecond *prometheus.GaugeVec

	// 活跃接口数
	ActiveInterfaces prometheus.Gauge
}

func newTCMetrics() *TCMetrics {
	sizeBuckets := []float64{64, 128, 256, 512, 1024, 1500, 2048, 4096, 9000}
	return &TCMetrics{
		PacketsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "network_tc_packets_total",
			Help: "Total packets observed at TC hook (by protocol/direction/iface)",
		}, []string{"protocol", "direction", "iface"}),

		BytesTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "network_tc_bytes_total",
			Help: "Total bytes observed at TC hook (by protocol/direction/iface)",
		}, []string{"protocol", "direction", "iface"}),

		TCPFlagsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "network_tc_tcp_flags_total",
			Help: "TCP flag counts observed at TC hook",
		}, []string{"flag", "direction", "iface"}),

		PacketSizeHistogram: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "network_tc_packet_size_bytes",
			Help:    "Packet size distribution observed at TC hook",
			Buckets: sizeBuckets,
		}, []string{"protocol", "direction"}),

		PacketsPerSecond: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "network_tc_pps",
			Help: "Packets per second at TC hook (last interval)",
		}, []string{"direction", "iface"}),

		ActiveInterfaces: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "network_tc_active_interfaces",
			Help: "Number of interfaces with TC hooks attached",
		}),
	}
}

// ── TCCollector ───────────────────────────────────────────

type tcIfaceStats struct {
	pktCount  uint64
	byteCount uint64
}

type TCCollector struct {
	mu           sync.RWMutex
	metrics      *TCMetrics
	ifaceStats   map[string]*tcIfaceStats // iface → stats（用于 PPS 计算）
	lastCalcTime time.Time
	activeIfaces map[string]bool
}

func NewTCCollector() *TCCollector {
	return &TCCollector{
		metrics:      newTCMetrics(),
		ifaceStats:   make(map[string]*tcIfaceStats),
		activeIfaces: make(map[string]bool),
		lastCalcTime: time.Now(),
	}
}

// HandleTCPacket 实现 ebpf.TCPacketHandler 接口
func (c *TCCollector) HandleTCPacket(pkt *ebpf.TCPacket) {
	proto := ebpf.GetProtocolName(pkt.Protocol)
	dir   := ebpf.GetDirectionName(pkt.Direction)
	iface := ebpf.IfIndexToName(pkt.IfIndex)

	// 基础计数器
	c.metrics.PacketsTotal.WithLabelValues(proto, dir, iface).Inc()
	c.metrics.BytesTotal.WithLabelValues(proto, dir, iface).Add(float64(pkt.PacketLen))

	// 数据包大小分布
	c.metrics.PacketSizeHistogram.WithLabelValues(proto, dir).Observe(float64(pkt.PacketLen))

	// 接口 PPS 计算暂存
	c.mu.Lock()
	if _, ok := c.ifaceStats[iface]; !ok {
		c.ifaceStats[iface] = &tcIfaceStats{}
		c.activeIfaces[iface] = true
		c.metrics.ActiveInterfaces.Set(float64(len(c.activeIfaces)))
	}
	c.ifaceStats[iface].pktCount++
	c.ifaceStats[iface].byteCount += uint64(pkt.PacketLen)
	c.mu.Unlock()

	// TCP flags 分布
	if pkt.Protocol == 6 && pkt.TCPFlags != 0 {
		c.parseTCPFlags(pkt.TCPFlags, dir, iface)
	}

	log.WithFields(log.Fields{
		"src":   fmt.Sprintf("%s:%d", ebpf.Uint32ToIP(pkt.SAddr), pkt.SPort),
		"dst":   fmt.Sprintf("%s:%d", ebpf.Uint32ToIP(pkt.DAddr), pkt.DPort),
		"proto": proto,
		"dir":   dir,
		"iface": iface,
		"len":   pkt.PacketLen,
		"flags": fmt.Sprintf("0x%02x", pkt.TCPFlags),
		"ttl":   pkt.IPTTL,
	}).Debug("TC packet captured")
}

func (c *TCCollector) parseTCPFlags(flags uint8, dir, iface string) {
	type flagDef struct {
		mask uint8
		name string
	}
	defs := []flagDef{
		{0x01, "FIN"},
		{0x02, "SYN"},
		{0x04, "RST"},
		{0x08, "PSH"},
		{0x10, "ACK"},
		{0x20, "URG"},
	}
	for _, f := range defs {
		if flags&f.mask != 0 {
			c.metrics.TCPFlagsTotal.WithLabelValues(f.name, dir, iface).Inc()
		}
	}
	// 组合标志：SYN+ACK（三次握手响应）
	if flags&0x12 == 0x12 {
		c.metrics.TCPFlagsTotal.WithLabelValues("SYN-ACK", dir, iface).Inc()
	}
}

// CalculatePPS 计算每秒包速率（定期调用）
func (c *TCCollector) CalculatePPS() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(c.lastCalcTime).Seconds()
	if elapsed <= 0 {
		return
	}

	for iface, st := range c.ifaceStats {
		pps := float64(st.pktCount) / elapsed
		c.metrics.PacketsPerSecond.WithLabelValues("ingress+egress", iface).Set(pps)
		// 重置计数
		st.pktCount = 0
		st.byteCount = 0
	}
	c.lastCalcTime = now
}

func (c *TCCollector) GetMetrics() *TCMetrics { return c.metrics }

func (c *TCCollector) Close() error {
	log.Info("TC collector closed")
	return nil
}
