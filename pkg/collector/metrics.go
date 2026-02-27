// pkg/collector/metrics.go — Prometheus 指标定义

package collector

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics 采集器 Prometheus 指标
type Metrics struct {
	// 吞吐
	BytesSent       prometheus.Counter
	BytesReceived   prometheus.Counter
	PacketsSent     prometheus.Counter
	PacketsReceived prometheus.Counter
	NewFlows        prometheus.Counter
	ClosedFlows     prometheus.Counter
	ActiveFlows     prometheus.Gauge
	BytesPerSecond  prometheus.Gauge
	PktsPerSecond   prometheus.Gauge

	// TCP 时延（μs）
	SynRTT       prometheus.Histogram
	SynRTTClient prometheus.Histogram
	SynRTTServer prometheus.Histogram
	RTT          prometheus.Histogram
	RTTMax       prometheus.Gauge
	RTTMin       prometheus.Gauge
	SRT          prometheus.Histogram
	SRTMax       prometheus.Gauge

	// TCP 重传 & 零窗口
	RetransPackets     prometheus.Counter
	RetransBytes       prometheus.Counter
	RetransRatio       prometheus.Gauge
	ZeroWindowEvents   prometheus.Counter
	ZeroWindowDuration prometheus.Counter

	// TCP 异常
	ClientSynRepeat     prometheus.Counter
	ClientEstablishFail prometheus.Counter
	ServerSynRepeat     prometheus.Counter
	ServerEstablishFail prometheus.Counter
	ServerQueueOverflow prometheus.Counter
	ServerReset         prometheus.Counter
	TCPTimeout          prometheus.Counter

	// TCP 状态分布
	TCPStateGauge *prometheus.GaugeVec

	// 负载
	NewFlowsPerSecond   prometheus.Gauge
	CloseFlowsPerSecond prometheus.Gauge
}

// NewMetrics 创建协议级指标（protocol = "tcp" | "udp"）
// 使用独立 Registry 避免不同 protocol 的 promauto 名称冲突。
func NewMetrics(protocol string) *Metrics {
	latencyBuckets := []float64{
		100, 200, 500,
		1000, 2000, 5000,
		10000, 20000, 50000,
		100000, 200000, 500000,
		1000000, 5000000, 10000000,
	}
	p := protocol + "_"

	return &Metrics{
		BytesSent: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + p + "bytes_sent_total",
			Help: "Total bytes sent",
		}),
		BytesReceived: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + p + "bytes_received_total",
			Help: "Total bytes received",
		}),
		PacketsSent: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + p + "packets_sent_total",
			Help: "Total packets sent",
		}),
		PacketsReceived: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + p + "packets_received_total",
			Help: "Total packets received",
		}),
		NewFlows: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + p + "new_flows_total",
			Help: "Total new flows",
		}),
		ClosedFlows: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + p + "closed_flows_total",
			Help: "Total closed flows",
		}),
		ActiveFlows: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "network_" + p + "active_flows",
			Help: "Current active flows",
		}),
		BytesPerSecond: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "network_" + p + "bytes_per_second",
			Help: "Current throughput in bytes/s",
		}),
		PktsPerSecond: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "network_" + p + "packets_per_second",
			Help: "Current throughput in packets/s",
		}),

		SynRTT: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "network_" + p + "syn_rtt_microseconds",
			Help:    "TCP SYN RTT (client SYN to final ACK) in μs",
			Buckets: latencyBuckets,
		}),
		SynRTTClient: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "network_" + p + "syn_rtt_client_microseconds",
			Help:    "TCP client-side SYN RTT (SYN+ACK → ACK) in μs",
			Buckets: latencyBuckets,
		}),
		SynRTTServer: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "network_" + p + "syn_rtt_server_microseconds",
			Help:    "TCP server-side SYN RTT (SYN → SYN+ACK) in μs",
			Buckets: latencyBuckets,
		}),
		RTT: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "network_" + p + "rtt_microseconds",
			Help:    "TCP data RTT in μs",
			Buckets: latencyBuckets,
		}),
		RTTMax: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "network_" + p + "rtt_max_microseconds",
			Help: "Maximum TCP RTT in μs",
		}),
		RTTMin: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "network_" + p + "rtt_min_microseconds",
			Help: "Minimum TCP RTT in μs",
		}),
		SRT: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "network_" + p + "srt_microseconds",
			Help:    "Server response time in μs",
			Buckets: latencyBuckets,
		}),
		SRTMax: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "network_" + p + "srt_max_microseconds",
			Help: "Maximum server response time in μs",
		}),

		RetransPackets: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + p + "retrans_packets_total",
			Help: "Total retransmitted packets",
		}),
		RetransBytes: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + p + "retrans_bytes_total",
			Help: "Total retransmitted bytes",
		}),
		RetransRatio: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "network_" + p + "retrans_ratio",
			Help: "Retransmission ratio",
		}),
		ZeroWindowEvents: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + p + "zero_window_events_total",
			Help: "Total zero window events",
		}),
		ZeroWindowDuration: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + p + "zero_window_duration_us_total",
			Help: "Total zero window duration in μs",
		}),

		ClientSynRepeat: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + p + "client_syn_repeat_total",
			Help: "Client SYN retransmissions",
		}),
		ClientEstablishFail: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + p + "client_establish_fail_total",
			Help: "Client connection establishment failures",
		}),
		ServerSynRepeat: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + p + "server_syn_repeat_total",
			Help: "Server SYN retransmissions",
		}),
		ServerEstablishFail: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + p + "server_establish_fail_total",
			Help: "Server connection establishment failures",
		}),
		ServerQueueOverflow: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + p + "server_queue_overflow_total",
			Help: "Server TCP queue overflows",
		}),
		ServerReset: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + p + "server_reset_total",
			Help: "Server RST packets",
		}),
		TCPTimeout: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + p + "timeout_total",
			Help: "TCP timeout events",
		}),

		TCPStateGauge: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "network_" + p + "connections_by_state",
				Help: "TCP connections by state",
			},
			[]string{"state"},
		),

		NewFlowsPerSecond: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "network_" + p + "new_flows_per_second",
			Help: "New flows per second",
		}),
		CloseFlowsPerSecond: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "network_" + p + "closed_flows_per_second",
			Help: "Closed flows per second",
		}),
	}
}
