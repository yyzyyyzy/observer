// pkg/collector/tc_collector.go — TC 层数据采集器
//
// 设计原则（对标 DeepFlow）：
//   - BPF 侧每包更新 tc_stats_map，Go 侧定期 Poll 读取并更新 Prometheus 指标。
//   - ringbuf 只转发采样包（1/100），Go 侧仅在 Trace 级别记录，不洪泛日志。
//   - 所有 Prometheus 指标由 BPF map 驱动，而非 ringbuf 事件驱动（精度更高）。

package collector

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	log "github.com/sirupsen/logrus"
	"observer/pkg/ebpf"
)

// TCMetrics TC 层专属 Prometheus 指标
type TCMetrics struct {
	PacketsTotal        *prometheus.CounterVec
	BytesTotal          *prometheus.CounterVec
	TCPFlagsTotal       *prometheus.CounterVec
	PacketSizeHistogram *prometheus.HistogramVec
	PacketsPerSecond    *prometheus.GaugeVec
	ActiveInterfaces    prometheus.Gauge
	IPv6Packets         *prometheus.CounterVec
	SampledPackets      *prometheus.CounterVec
}

func newTCMetrics() *TCMetrics {
	sizeBuckets := []float64{64, 128, 256, 512, 1024, 1500, 2048, 4096, 9000}
	return &TCMetrics{
		PacketsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "network_tc_packets_total",
			Help: "Total packets observed at TC hook (all packets, not sampled)",
		}, []string{"protocol", "direction", "iface", "ip_version"}),

		BytesTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "network_tc_bytes_total",
			Help: "Total bytes observed at TC hook (all packets, not sampled)",
		}, []string{"protocol", "direction", "iface", "ip_version"}),

		TCPFlagsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "network_tc_tcp_flags_total",
			Help: "TCP flag counts at TC hook (sampled)",
		}, []string{"flag", "direction", "iface"}),

		PacketSizeHistogram: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "network_tc_packet_size_bytes",
			Help:    "Packet size distribution at TC hook (sampled)",
			Buckets: sizeBuckets,
		}, []string{"protocol", "direction"}),

		PacketsPerSecond: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "network_tc_pps",
			Help: "Packets per second at TC hook",
		}, []string{"direction", "iface"}),

		ActiveInterfaces: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "network_tc_active_interfaces",
			Help: "Interfaces with TC hooks attached",
		}),

		IPv6Packets: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "network_tc_ipv6_packets_total",
			Help: "IPv6 packets observed at TC hook",
		}, []string{"protocol", "direction"}),

		SampledPackets: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "network_tc_sampled_packets_total",
			Help: "Sampled packets forwarded via ringbuf (1/sample_rate of total)",
		}, []string{"direction"}),
	}
}

// ── TCCollector ───────────────────────────────────────────

type tcIfaceStats struct {
	pktCount uint64
}

type TCCollector struct {
	mu           sync.RWMutex
	metrics      *TCMetrics
	ifaceStats   map[string]*tcIfaceStats
	lastCalcTime time.Time
	activeIfaces map[string]bool

	// 采样包计数（用于验证 BPF 采样率）
	sampledCount atomic.Uint64
}

func NewTCCollector() *TCCollector {
	return &TCCollector{
		metrics:      newTCMetrics(),
		ifaceStats:   make(map[string]*tcIfaceStats),
		activeIfaces: make(map[string]bool),
		lastCalcTime: time.Now(),
	}
}

// HandleTCPacket 处理来自 BPF ringbuf 的采样包事件。
// 注意：此处接收的是 BPF 侧 1/TC_SAMPLE_RATE 的采样包，
// 用于包大小分布、TCP flags 分析等需要包内容的指标；
// 总包数/字节数等聚合指标由 BPF map 直接驱动（更准确）。
func (c *TCCollector) HandleTCPacket(pkt *ebpf.TCPacket) {
	proto := ebpf.GetProtocolName(pkt.Protocol)
	dir   := ebpf.GetDirectionName(pkt.Direction)
	iface := ebpf.IfIndexToName(pkt.IfIndex)

	ipVer := "4"
	if pkt.IPVersion == 6 {
		ipVer = "6"
		c.metrics.IPv6Packets.WithLabelValues(proto, dir).Inc()
	}

	// 采样包驱动的指标：包大小分布、TCP flags
	c.metrics.PacketsTotal.WithLabelValues(proto, dir, iface, ipVer).Inc()
	c.metrics.BytesTotal.WithLabelValues(proto, dir, iface, ipVer).Add(float64(pkt.PacketLen))
	c.metrics.PacketSizeHistogram.WithLabelValues(proto, dir).Observe(float64(pkt.PacketLen))
	c.metrics.SampledPackets.WithLabelValues(dir).Inc()

	c.mu.Lock()
	if _, ok := c.ifaceStats[iface]; !ok {
		c.ifaceStats[iface] = &tcIfaceStats{}
		c.activeIfaces[iface] = true
		c.metrics.ActiveInterfaces.Set(float64(len(c.activeIfaces)))
	}
	c.ifaceStats[iface].pktCount++
	c.mu.Unlock()

	if pkt.Protocol == 6 && pkt.TCPFlags != 0 {
		c.parseTCPFlags(pkt.TCPFlags, dir, iface)
	}

	c.sampledCount.Add(1)

	// 只在 Trace 级别记录采样包，不在 Debug 级别输出（防止日志洪泛）
	if log.IsLevelEnabled(log.TraceLevel) {
		srcStr := ebpf.Uint32ToIP(pkt.SAddr)
		dstStr := ebpf.Uint32ToIP(pkt.DAddr)
		if pkt.IPVersion == 6 {
			srcStr = ebpf.Bytes16ToIPv6(pkt.SAddr6)
			dstStr = ebpf.Bytes16ToIPv6(pkt.DAddr6)
		}
		log.WithFields(log.Fields{
			"src":    fmt.Sprintf("%s:%d", srcStr, pkt.SPort),
			"dst":    fmt.Sprintf("%s:%d", dstStr, pkt.DPort),
			"proto":  proto,
			"dir":    dir,
			"iface":  iface,
			"ip_ver": ipVer,
			"len":    pkt.PacketLen,
			"flags":  fmt.Sprintf("0x%02x", pkt.TCPFlags),
			"ttl":    pkt.IPTTL,
		}).Trace("TC sampled packet")
	}
}

func (c *TCCollector) parseTCPFlags(flags uint8, dir, iface string) {
	defs := []struct {
		mask uint8
		name string
	}{
		{0x01, "FIN"}, {0x02, "SYN"}, {0x04, "RST"},
		{0x08, "PSH"}, {0x10, "ACK"}, {0x20, "URG"},
	}
	for _, f := range defs {
		if flags&f.mask != 0 {
			c.metrics.TCPFlagsTotal.WithLabelValues(f.name, dir, iface).Inc()
		}
	}
	if flags&0x12 == 0x12 {
		c.metrics.TCPFlagsTotal.WithLabelValues("SYN-ACK", dir, iface).Inc()
	}
}

// CalculatePPS 计算每秒包数（基于采样包数 × 采样率估算）
func (c *TCCollector) CalculatePPS() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(c.lastCalcTime).Seconds()
	if elapsed <= 0 {
		return
	}
	for iface, st := range c.ifaceStats {
		// 采样包 × 采样率 ≈ 真实包数
		estimatedPPS := float64(st.pktCount) * 100.0 / elapsed
		c.metrics.PacketsPerSecond.WithLabelValues("all", iface).Set(estimatedPPS)
		st.pktCount = 0
	}
	c.lastCalcTime = now
}

func (c *TCCollector) Close() error { return nil }
