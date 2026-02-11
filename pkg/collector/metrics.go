package collector

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Metrics struct {
	BytesSent          prometheus.Counter
	BytesReceived      prometheus.Counter
	PacketsSent        prometheus.Counter
	PacketsReceived    prometheus.Counter
	ConnectionsActive  prometheus.Gauge
	ConnectionsTotal   prometheus.Counter
}

func NewMetrics(protocol string) *Metrics {
	return &Metrics{
		BytesSent: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_observer_" + protocol + "_bytes_sent_total",
			Help: "Total bytes sent over " + protocol,
		}),
		BytesReceived: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_observer_" + protocol + "_bytes_received_total",
			Help: "Total bytes received over " + protocol,
		}),
		PacketsSent: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_observer_" + protocol + "_packets_sent_total",
			Help: "Total packets sent over " + protocol,
		}),
		PacketsReceived: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_observer_" + protocol + "_packets_received_total",
			Help: "Total packets received over " + protocol,
		}),
		ConnectionsActive: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "network_observer_" + protocol + "_connections_active",
			Help: "Number of active " + protocol + " connections",
		}),
		ConnectionsTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name: "network_observer_" + protocol + "_connections_total",
			Help: "Total number of " + protocol + " connections",
		}),
	}
}
