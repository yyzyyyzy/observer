// pkg/collector/metrics_enhanced.go
package collector

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics 增强的指标结构，对标 DeepFlow
type Metrics struct {
	// ==================== 吞吐指标 ====================
	// L3 Throughput
	BytesSent       prometheus.Counter // 发送字节总数
	BytesReceived   prometheus.Counter // 接收字节总数
	PacketsSent     prometheus.Counter // 发送包总数
	PacketsReceived prometheus.Counter // 接收包总数

	// L4 Throughput
	NewFlows    prometheus.Counter // 新建连接数
	ClosedFlows prometheus.Counter // 关闭连接数
	ActiveFlows prometheus.Gauge   // 活跃连接数

	// 速率指标
	BytesPerSecond   prometheus.Gauge // 字节速率 (Bps)
	PacketsPerSecond prometheus.Gauge // 包速率 (pps)

	// ==================== 时延指标 ====================
	// TCP 建连时延（微秒）
	SynRTT       prometheus.Histogram // 完整建连时延
	SynRTTClient prometheus.Histogram // 客户端建连时延
	SynRTTServer prometheus.Histogram // 服务端建连时延

	// 数据传输时延（微秒）
	RTT    prometheus.Histogram // 平均 RTT
	RTTMax prometheus.Gauge     // 最大 RTT
	RTTMin prometheus.Gauge     // 最小 RTT

	// 系统时延（微秒）
	SRT    prometheus.Histogram // 平均系统时延
	SRTMax prometheus.Gauge     // 最大系统时延

	// 客户端/服务端等待时延
	ClientWaitDelay prometheus.Histogram // 客户端等待时延
	ServerWaitDelay prometheus.Histogram // 服务端等待时延

	// ==================== TCP 性能指标 ====================
	// 重传指标
	RetransPackets prometheus.Counter // 重传包数
	RetransBytes   prometheus.Counter // 重传字节数
	RetransRatio   prometheus.Gauge   // 重传比例

	// 零窗口指标
	ZeroWindowEvents   prometheus.Counter // 零窗口次数
	ZeroWindowDuration prometheus.Counter // 零窗口总时长（微秒）

	// ==================== TCP 异常指标 ====================
	// 建连异常 - 客户端
	ClientSynRepeat      prometheus.Counter // 客户端 SYN 重传
	ClientEstablishFail  prometheus.Counter // 客户端建连失败（收到 RST）
	ClientEstablishOther prometheus.Counter // 客户端其他建连异常

	// 建连异常 - 服务端
	ServerSynMiss        prometheus.Counter // 服务端 SYN 缺失
	ServerSynRepeat      prometheus.Counter // 服务端 SYN 重传
	ServerEstablishFail  prometheus.Counter // 服务端建连失败
	ServerEstablishOther prometheus.Counter // 服务端其他建连异常
	ServerQueueOverflow  prometheus.Counter // 服务端队列溢出

	// TCP 传输异常
	ClientPortReuse prometheus.Counter // 客户端端口复用
	ServerReset     prometheus.Counter // 服务端 RST
	TCPTimeout      prometheus.Counter // TCP 超时

	// TCP 断连异常
	ClientHalfCloseLack prometheus.Counter // 客户端半关闭缺失
	ServerHalfCloseLack prometheus.Counter // 服务端半关闭缺失

	// ==================== TCP 状态分布 ====================
	TCPStateGauge *prometheus.GaugeVec // TCP 状态分布

	// ==================== 负载指标 ====================
	RequestsPerSecond   prometheus.Gauge // 每秒请求数 (RPS)
	ResponsesPerSecond  prometheus.Gauge // 每秒响应数
	NewFlowsPerSecond   prometheus.Gauge // 每秒新建连接
	CloseFlowsPerSecond prometheus.Gauge // 每秒关闭连接
}

// NewMetrics 创建增强的指标实例
func NewMetrics(protocol string) *Metrics {
	// 时延的 bucket 设置（微秒）
	// 覆盖范围：100us ~ 10s
	latencyBuckets := []float64{
		100, 200, 500, // 亚毫秒级
		1000, 2000, 5000, // 毫秒级
		10000, 20000, 50000, // 十毫秒级
		100000, 200000, 500000, // 百毫秒级
		1000000, 5000000, 10000000, // 秒级
	}

	return &Metrics{
		// ==================== 吞吐指标 ====================
		BytesSent: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + protocol + "_bytes_sent_total",
			Help: "Total bytes sent",
		}),
		BytesReceived: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + protocol + "_bytes_received_total",
			Help: "Total bytes received",
		}),
		PacketsSent: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + protocol + "_packets_sent_total",
			Help: "Total packets sent",
		}),
		PacketsReceived: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + protocol + "_packets_received_total",
			Help: "Total packets received",
		}),
		NewFlows: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + protocol + "_new_flows_total",
			Help: "Total number of new flows",
		}),
		ClosedFlows: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + protocol + "_closed_flows_total",
			Help: "Total number of closed flows",
		}),
		ActiveFlows: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "network_" + protocol + "_active_flows",
			Help: "Current number of active flows",
		}),
		BytesPerSecond: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "network_" + protocol + "_bytes_per_second",
			Help: "Bytes per second (Bps)",
		}),
		PacketsPerSecond: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "network_" + protocol + "_packets_per_second",
			Help: "Packets per second (pps)",
		}),

		// ==================== 时延指标 ====================
		SynRTT: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "network_" + protocol + "_syn_rtt_microseconds",
			Help:    "TCP SYN round-trip time in microseconds (client SYN to final ACK)",
			Buckets: latencyBuckets,
		}),
		SynRTTClient: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "network_" + protocol + "_syn_rtt_client_microseconds",
			Help:    "TCP client-side SYN RTT in microseconds (SYN+ACK to ACK)",
			Buckets: latencyBuckets,
		}),
		SynRTTServer: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "network_" + protocol + "_syn_rtt_server_microseconds",
			Help:    "TCP server-side SYN RTT in microseconds (SYN to SYN+ACK)",
			Buckets: latencyBuckets,
		}),
		RTT: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "network_" + protocol + "_rtt_microseconds",
			Help:    "TCP round-trip time in microseconds",
			Buckets: latencyBuckets,
		}),
		RTTMax: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "network_" + protocol + "_rtt_max_microseconds",
			Help: "Maximum TCP RTT in microseconds",
		}),
		RTTMin: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "network_" + protocol + "_rtt_min_microseconds",
			Help: "Minimum TCP RTT in microseconds",
		}),
		SRT: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "network_" + protocol + "_srt_microseconds",
			Help:    "System response time (ACK delay) in microseconds",
			Buckets: latencyBuckets,
		}),
		SRTMax: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "network_" + protocol + "_srt_max_microseconds",
			Help: "Maximum system response time in microseconds",
		}),
		ClientWaitDelay: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "network_" + protocol + "_client_wait_microseconds",
			Help:    "Client wait delay in microseconds",
			Buckets: latencyBuckets,
		}),
		ServerWaitDelay: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "network_" + protocol + "_server_wait_microseconds",
			Help:    "Server wait delay in microseconds",
			Buckets: latencyBuckets,
		}),

		// ==================== TCP 性能指标 ====================
		RetransPackets: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + protocol + "_retrans_packets_total",
			Help: "Total number of retransmitted packets",
		}),
		RetransBytes: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + protocol + "_retrans_bytes_total",
			Help: "Total bytes retransmitted",
		}),
		RetransRatio: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "network_" + protocol + "_retrans_ratio",
			Help: "Ratio of retransmitted packets to total packets",
		}),
		ZeroWindowEvents: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + protocol + "_zero_window_events_total",
			Help: "Total number of zero window events",
		}),
		ZeroWindowDuration: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + protocol + "_zero_window_duration_microseconds_total",
			Help: "Total duration of zero window in microseconds",
		}),

		// ==================== TCP 异常指标 ====================
		ClientSynRepeat: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + protocol + "_client_syn_repeat_total",
			Help: "Client SYN retransmissions",
		}),
		ClientEstablishFail: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + protocol + "_client_establish_fail_total",
			Help: "Client connection establishment failures (RST received)",
		}),
		ClientEstablishOther: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + protocol + "_client_establish_other_total",
			Help: "Other client connection establishment errors",
		}),
		ServerSynMiss: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + protocol + "_server_syn_miss_total",
			Help: "Server SYN missing (direct SYN+ACK)",
		}),
		ServerSynRepeat: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + protocol + "_server_syn_repeat_total",
			Help: "Server SYN retransmissions",
		}),
		ServerEstablishFail: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + protocol + "_server_establish_fail_total",
			Help: "Server connection establishment failures",
		}),
		ServerEstablishOther: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + protocol + "_server_establish_other_total",
			Help: "Other server connection establishment errors",
		}),
		ServerQueueOverflow: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + protocol + "_server_queue_overflow_total",
			Help: "Server TCP queue overflows",
		}),
		ClientPortReuse: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + protocol + "_client_port_reuse_total",
			Help: "Client port reuse events",
		}),
		ServerReset: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + protocol + "_server_reset_total",
			Help: "Server RST packets sent",
		}),
		TCPTimeout: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + protocol + "_timeout_total",
			Help: "TCP timeout events",
		}),
		ClientHalfCloseLack: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + protocol + "_client_half_close_lack_total",
			Help: "Client half-close missing events",
		}),
		ServerHalfCloseLack: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_" + protocol + "_server_half_close_lack_total",
			Help: "Server half-close missing events",
		}),

		// ==================== TCP 状态分布 ====================
		TCPStateGauge: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "network_" + protocol + "_connections_by_state",
				Help: "Number of TCP connections by state",
			},
			[]string{"state"}, // ESTABLISHED, SYN_SENT, SYN_RECV, FIN_WAIT1, etc.
		),

		// ==================== 负载指标 ====================
		RequestsPerSecond: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "network_" + protocol + "_requests_per_second",
			Help: "Requests per second (RPS)",
		}),
		ResponsesPerSecond: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "network_" + protocol + "_responses_per_second",
			Help: "Responses per second",
		}),
		NewFlowsPerSecond: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "network_" + protocol + "_new_flows_per_second",
			Help: "New flows per second",
		}),
		CloseFlowsPerSecond: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "network_" + protocol + "_closed_flows_per_second",
			Help: "Closed flows per second",
		}),
	}
}
