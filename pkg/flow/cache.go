// pkg/flow/cache.go
// TCP Flow Cache — 管理 TCP 流生命周期，流结束时将完整 L4FlowLog 写入 ClickHouse。

package flow

import (
	"fmt"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	log "github.com/sirupsen/logrus"

	"observer/pkg/cloudmeta"
	"observer/pkg/ebpf"
	"observer/pkg/storage"
)

// ── 配置 ──────────────────────────────────────────────────────────────────────

type CacheConfig struct {
	MaxFlows      int
	FlowTTL       time.Duration
	FlushInterval time.Duration
	SampleBytes   uint64
}

var DefaultCacheConfig = CacheConfig{
	MaxFlows:      65536,
	FlowTTL:       5 * time.Minute,
	FlushInterval: 10 * time.Second,
}

type entry struct {
	flow     *ebpf.Flow
	lastSeen time.Time
}

// ── Prometheus 指标 ───────────────────────────────────────────────────────────

type CacheMetrics struct {
	FlowCacheSize    prometheus.Gauge
	FlowCacheEvicted prometheus.Counter
	FlowCacheTimeout prometheus.Counter
	FlowCreated      prometheus.Counter
	FlowUpdated      prometheus.Counter
	FlowDestroyed    prometheus.Counter
	SynRTT           *prometheus.HistogramVec
	RTTMean          *prometheus.HistogramVec
	ArtRTT           *prometheus.HistogramVec
	BytesTx          *prometheus.CounterVec
	BytesRx          *prometheus.CounterVec
	RetransTx        *prometheus.CounterVec
	DestroyReason    *prometheus.CounterVec
	Duration         *prometheus.HistogramVec
}

func newCacheMetrics() *CacheMetrics {
	latB := []float64{50, 100, 200, 500, 1000, 2000, 5000, 10000, 50000, 100000, 500000}
	durB := []float64{1e6, 5e6, 10e6, 30e6, 60e6, 300e6, 600e6, 1800e6, 3600e6}
	return &CacheMetrics{
		FlowCacheSize:    promauto.NewGauge(prometheus.GaugeOpts{Name: "flow_cache_size", Help: "Active flows in user-space cache"}),
		FlowCacheEvicted: promauto.NewCounter(prometheus.CounterOpts{Name: "flow_cache_evicted_total", Help: "Flows evicted by LRU"}),
		FlowCacheTimeout: promauto.NewCounter(prometheus.CounterOpts{Name: "flow_cache_timeout_total", Help: "Flows expired by TTL"}),
		FlowCreated:      promauto.NewCounter(prometheus.CounterOpts{Name: "flow_created_total"}),
		FlowUpdated:      promauto.NewCounter(prometheus.CounterOpts{Name: "flow_updated_total"}),
		FlowDestroyed:    promauto.NewCounter(prometheus.CounterOpts{Name: "flow_destroyed_total"}),
		SynRTT:           promauto.NewHistogramVec(prometheus.HistogramOpts{Name: "flow_syn_rtt_us", Help: "SYN RTT (μs)", Buckets: latB}, []string{"role"}),
		RTTMean:          promauto.NewHistogramVec(prometheus.HistogramOpts{Name: "flow_rtt_mean_us", Help: "Data RTT (μs)", Buckets: latB}, []string{"role"}),
		ArtRTT:           promauto.NewHistogramVec(prometheus.HistogramOpts{Name: "flow_art_rtt_us", Help: "Server response time (μs)", Buckets: latB}, []string{"role"}),
		BytesTx:          promauto.NewCounterVec(prometheus.CounterOpts{Name: "flow_bytes_tx_total"}, []string{"role"}),
		BytesRx:          promauto.NewCounterVec(prometheus.CounterOpts{Name: "flow_bytes_rx_total"}, []string{"role"}),
		RetransTx:        promauto.NewCounterVec(prometheus.CounterOpts{Name: "flow_retrans_tx_total"}, []string{"role"}),
		DestroyReason:    promauto.NewCounterVec(prometheus.CounterOpts{Name: "flow_destroy_reason_total"}, []string{"reason"}),
		Duration:         promauto.NewHistogramVec(prometheus.HistogramOpts{Name: "flow_duration_us", Buckets: durB}, []string{"role"}),
	}
}

// ── Cache ─────────────────────────────────────────────────────────────────────

type Cache struct {
	cfg          CacheConfig
	metrics      *CacheMetrics
	lrc          *lru.Cache[ebpf.FlowKey, *entry]
	store        *storage.ClickHouseClient
	metaProvider cloudmeta.MetaProvider
}

func NewCache(cfg CacheConfig) *Cache {
	return NewCacheWithDeps(cfg, nil, nil)
}

func NewCacheWithDeps(cfg CacheConfig, store *storage.ClickHouseClient, meta cloudmeta.MetaProvider) *Cache {
	if cfg.MaxFlows <= 0 {
		cfg.MaxFlows = DefaultCacheConfig.MaxFlows
	}
	if cfg.FlowTTL <= 0 {
		cfg.FlowTTL = DefaultCacheConfig.FlowTTL
	}
	if meta == nil {
		meta = &cloudmeta.NoopMetaProvider{}
	}

	c := &Cache{cfg: cfg, metrics: newCacheMetrics(), store: store, metaProvider: meta}
	c.lrc, _ = lru.NewWithEvict[ebpf.FlowKey, *entry](cfg.MaxFlows, func(_ ebpf.FlowKey, e *entry) {
		e.flow.DestroyReason = ebpf.DestroyTimeout
		e.flow.EndTime = time.Now()
		if e.flow.StartTime.IsZero() {
			e.flow.StartTime = e.flow.EndTime
		}
		e.flow.Duration = e.flow.EndTime.Sub(e.flow.StartTime)
		c.persistL4(e.flow)
		c.recordDestroyMetrics(e.flow)
		c.metrics.FlowCacheEvicted.Inc()
		c.metrics.DestroyReason.WithLabelValues("EVICTED").Inc()
	})
	return c
}

func (c *Cache) HandleTCPEvent(ev *ebpf.TCPEvent) {
	role := ebpf.FlowRole(ev.Role)
	key := ebpf.NewFlowKey(ev.SAddr, ev.DAddr, ev.SPort, ev.DPort, ev.Protocol, role)
	switch ebpf.FlowLifecycle(ev.Lifecycle) {
	case ebpf.FlowCreate:
		c.onCreate(key, ev, role)
	case ebpf.FlowUpdate:
		c.onUpdate(key, ev)
	case ebpf.FlowDestroy:
		c.onDestroy(key, ev)
	}
}

func (c *Cache) onCreate(key ebpf.FlowKey, ev *ebpf.TCPEvent, role ebpf.FlowRole) {
	if e, ok := c.lrc.Get(key); ok {
		c.applyEvent(e.flow, ev)
		return
	}
	now := time.Now()
	srcIP := ebpf.Uint32ToIP(ev.SAddr)
	dstIP := ebpf.Uint32ToIP(ev.DAddr)

	f := &ebpf.Flow{
		Key:          key,
		SrcIP:        srcIP,
		DstIP:        dstIP,
		SrcPort:      key.SrcPort,
		DstPort:      key.DstPort,
		Protocol:     "TCP",
		Role:         role,
		ProcessName:  ebpf.ParseCommField(ev.Comm),
		PID:          ev.PID,
		Lifecycle:    ebpf.FlowCreate,
		StartTime:    now,
		LastSeen:     now,
		SynRTT:       time.Duration(ev.SynRTT) * time.Microsecond,
		SynRTTServer: time.Duration(ev.SynRTTServer) * time.Microsecond,
		SynRTTClient: time.Duration(ev.SynRTTClient) * time.Microsecond,
	}
	if tag := c.metaProvider.GetTag(srcIP); tag != nil {
		f.CloudTag = tag
	} else if tag := c.metaProvider.GetTag(dstIP); tag != nil {
		f.CloudTag = tag
	}
	c.lrc.Add(key, &entry{flow: f, lastSeen: now})
	c.metrics.FlowCreated.Inc()
	c.metrics.FlowCacheSize.Set(float64(c.lrc.Len()))
}

func (c *Cache) onUpdate(key ebpf.FlowKey, ev *ebpf.TCPEvent) {
	e, ok := c.lrc.Get(key)
	if !ok {
		return
	}
	c.applyEvent(e.flow, ev)
	e.lastSeen = time.Now()
	c.metrics.FlowUpdated.Inc()
}

func (c *Cache) onDestroy(key ebpf.FlowKey, ev *ebpf.TCPEvent) {
	e, ok := c.lrc.Get(key)
	if !ok {
		return
	}
	c.applyEvent(e.flow, ev)
	f := e.flow
	f.Lifecycle = ebpf.FlowDestroy
	f.DestroyReason = ebpf.DestroyReason(ev.DestroyReason)
	if f.DestroyReason == 0 {
		f.DestroyReason = ebpf.DestroyFIN
	}
	now := time.Now()
	f.EndTime = now
	if ev.DurationUs > 0 {
		f.Duration = time.Duration(ev.DurationUs) * time.Microsecond
	} else {
		f.Duration = now.Sub(f.StartTime)
	}
	c.persistL4(f)
	c.recordDestroyMetrics(f)
	c.metrics.FlowDestroyed.Inc()
	c.metrics.DestroyReason.WithLabelValues(f.DestroyReason.String()).Inc()
	log.WithFields(log.Fields{
		"src":    fmt.Sprintf("%s:%d", f.SrcIP, f.SrcPort),
		"dst":    fmt.Sprintf("%s:%d", f.DstIP, f.DstPort),
		"dur":    f.Duration,
		"reason": f.DestroyReason,
	}).Debug("Flow destroyed")
	c.lrc.Remove(key)
	c.metrics.FlowCacheSize.Set(float64(c.lrc.Len()))
}

func (c *Cache) applyEvent(f *ebpf.Flow, ev *ebpf.TCPEvent) {
	f.BytesSent = ev.BytesSent
	f.BytesReceived = ev.BytesReceived
	f.PacketsSent = ev.PacketsSent
	f.PacketsReceived = ev.PacketsReceived
	f.RetransCount = ev.RetransCount
	f.RetransBytes = ev.RetransBytes
	f.ZeroWndCount = ev.ZeroWndCount
	f.ZeroWndDuration = time.Duration(ev.ZeroWndDuration) * time.Microsecond
	f.SynRetransCount = ev.SynRetrans
	f.RSTCount = ev.RSTCount
	f.TimeoutOccurred = ev.TimeoutFlag > 0
	if ev.SynRTT > 0 {
		f.SynRTT = time.Duration(ev.SynRTT) * time.Microsecond
		f.SynRTTServer = time.Duration(ev.SynRTTServer) * time.Microsecond
		f.SynRTTClient = time.Duration(ev.SynRTTClient) * time.Microsecond
	}
	if ev.RTTMean > 0 {
		f.RTTMean = time.Duration(ev.RTTMean) * time.Microsecond
		f.RTTMax = time.Duration(ev.RTTMax) * time.Microsecond
		f.RTTMin = time.Duration(ev.RTTMin) * time.Microsecond
	}
	if ev.SRTMean > 0 {
		f.SRTMean = time.Duration(ev.SRTMean) * time.Microsecond
		f.SRTMax = time.Duration(ev.SRTMax) * time.Microsecond
	}
	f.LastSeen = time.Now()
}

// persistL4 将流写入 ClickHouse l4_flow_log，对齐 DeepFlow 字段规范。
// 无 K8s 环境时 PodIP 为空字符串，safeIPv4 将其转为 0.0.0.0，不报格式错误。
func (c *Cache) persistL4(f *ebpf.Flow) {
	if c.store == nil {
		return
	}
	now := f.EndTime
	if now.IsZero() {
		now = time.Now()
	}
	start := f.StartTime
	if start.IsZero() {
		start = now
	}

	var retransRatio float32
	totalPkts := f.PacketsSent + f.PacketsReceived
	if totalPkts > 0 {
		retransRatio = float32(f.RetransCount) / float32(totalPkts)
	}

	row := storage.L4FlowLog{
		StartTime:  start,
		EndTime:    now,
		DurationUs: uint64(f.Duration.Microseconds()),

		SrcIP:    storage.SafeIPv4(f.SrcIP),
		DstIP:    storage.SafeIPv4(f.DstIP),
		SrcPort:  f.SrcPort,
		DstPort:  f.DstPort,
		Protocol: 6, // TCP

		PID:         f.PID,
		ProcessName: f.ProcessName,

		Role:      uint8(f.Role),
		CloseType: uint8(f.DestroyReason),

		BytesSent:       f.BytesSent,
		BytesReceived:   f.BytesReceived,
		PacketsSent:     f.PacketsSent,
		PacketsReceived: f.PacketsReceived,

		SynRttUs:       uint32(f.SynRTT.Microseconds()),
		SynRttClientUs: uint32(f.SynRTTClient.Microseconds()),
		SynRttServerUs: uint32(f.SynRTTServer.Microseconds()),
		RTTMinUs:       uint32(f.RTTMin.Microseconds()),
		RTTMeanUs:      uint32(f.RTTMean.Microseconds()),
		RTTMaxUs:       uint32(f.RTTMax.Microseconds()),
		SRTMeanUs:      uint32(f.SRTMean.Microseconds()),
		SRTMaxUs:       uint32(f.SRTMax.Microseconds()),

		RetransCnt:    f.RetransCount,
		RetransBytes:  f.RetransBytes,
		RetransRatio:  retransRatio,
		ZeroWndCnt:    f.ZeroWndCount,
		ZeroWndUs:     uint64(f.ZeroWndDuration.Microseconds()),
		RSTCnt:        f.RSTCount,
		SynRetransCnt: f.SynRetransCount,

		// 无 K8s 环境时默认 0.0.0.0
		PodIP: storage.SafeIPv4(""),
	}

	// 注入 K8s 云标签（无 K8s 环境时 tag 为 nil，字段保持空字符串默认值）
	if tag, ok := f.CloudTag.(*cloudmeta.CloudTag); ok && tag != nil {
		row.PodName = tag.PodName
		row.PodNamespace = tag.PodNamespace
		row.ServiceName = tag.ServiceName
		row.NodeName = tag.NodeName
		row.PodIP = storage.SafeIPv4(tag.PodIP)
		row.Region = tag.Region
		row.AZ = tag.AZ
		row.AppLabels = tag.AppLabelsJSON()
	}

	c.store.WriteL4FlowLog(row)
}

func (c *Cache) recordDestroyMetrics(f *ebpf.Flow) {
	role := f.Role.String()
	if f.SynRTT > 0 {
		c.metrics.SynRTT.WithLabelValues(role).Observe(float64(f.SynRTT.Microseconds()))
	}
	if f.RTTMean > 0 {
		c.metrics.RTTMean.WithLabelValues(role).Observe(float64(f.RTTMean.Microseconds()))
	}
	if f.SRTMean > 0 {
		c.metrics.ArtRTT.WithLabelValues(role).Observe(float64(f.SRTMean.Microseconds()))
	}
	c.metrics.BytesTx.WithLabelValues(role).Add(float64(f.BytesSent))
	c.metrics.BytesRx.WithLabelValues(role).Add(float64(f.BytesReceived))
	if f.RetransCount > 0 {
		c.metrics.RetransTx.WithLabelValues(role).Add(float64(f.RetransCount))
	}
	if f.Duration > 0 {
		c.metrics.Duration.WithLabelValues(role).Observe(float64(f.Duration.Microseconds()))
	}
	c.metrics.FlowDestroyed.Inc()
}

func (c *Cache) RunGC() int {
	now := time.Now()
	var expired []ebpf.FlowKey
	for _, key := range c.lrc.Keys() {
		if e, ok := c.lrc.Peek(key); ok && now.Sub(e.lastSeen) > c.cfg.FlowTTL {
			expired = append(expired, key)
		}
	}
	for _, key := range expired {
		if e, ok := c.lrc.Peek(key); ok {
			e.flow.DestroyReason = ebpf.DestroyTimeout
			e.flow.EndTime = now
			e.flow.Duration = now.Sub(e.flow.StartTime)
			c.persistL4(e.flow)
			c.recordDestroyMetrics(e.flow)
			c.metrics.FlowCacheTimeout.Inc()
			c.metrics.DestroyReason.WithLabelValues("TIMEOUT").Inc()
		}
		c.lrc.Remove(key)
	}
	if len(expired) > 0 {
		c.metrics.FlowCacheSize.Set(float64(c.lrc.Len()))
	}
	return len(expired)
}

func (c *Cache) ActiveFlows() []*ebpf.Flow {
	keys := c.lrc.Keys()
	out := make([]*ebpf.Flow, 0, len(keys))
	for _, key := range keys {
		if e, ok := c.lrc.Peek(key); ok {
			cp := *e.flow
			out = append(out, &cp)
		}
	}
	return out
}

// Flush 将当前所有活跃流做一次 Prometheus 指标快照。
// 活跃流不会从 cache 中删除，只是采样当前状态。
// 对齐 DeepFlow 的周期性 flush 设计。
func (c *Cache) Flush() {
	for _, key := range c.lrc.Keys() {
		e, ok := c.lrc.Peek(key)
		if !ok {
			continue
		}
		f := e.flow
		role := f.Role.String()
		if f.SynRTT > 0 {
			c.metrics.SynRTT.WithLabelValues(role).Observe(float64(f.SynRTT.Microseconds()))
		}
		if f.RTTMean > 0 {
			c.metrics.RTTMean.WithLabelValues(role).Observe(float64(f.RTTMean.Microseconds()))
		}
		if f.SRTMean > 0 {
			c.metrics.ArtRTT.WithLabelValues(role).Observe(float64(f.SRTMean.Microseconds()))
		}
		c.metrics.BytesTx.WithLabelValues(role).Add(float64(f.BytesSent))
		c.metrics.BytesRx.WithLabelValues(role).Add(float64(f.BytesReceived))
		if f.RetransCount > 0 {
			c.metrics.RetransTx.WithLabelValues(role).Add(float64(f.RetransCount))
		}
	}
	c.metrics.FlowCacheSize.Set(float64(c.lrc.Len()))
	log.WithField("active_flows", c.lrc.Len()).Debug("TCP flow cache flushed (metrics snapshot)")
}

func (c *Cache) Size() int              { return c.lrc.Len() }
func (c *Cache) Metrics() *CacheMetrics { return c.metrics }

// Flush 将所有活跃流的当前快照写入 ClickHouse（FLOW_UPDATE 快照）。
// 对齐 DeepFlow interval flush：每个 stats_window 周期将存活流的当前累积指标
// 写入 l4_flow_log，方便 Grafana/ClickHouse 实时查看尚未结束的长连接指标。
// close_type 设为 0（FLUSH，表示这是中间快照而非真实结束）。
// 本实现同时更新 Prometheus 指标快照（无副作用）。
func (c *Cache) FlushSnapshot() {
	if c.store == nil {
		return
	}
	now := time.Now()
	keys := c.lrc.Keys()
	if len(keys) == 0 {
		return
	}

	flushed := 0
	for _, key := range keys {
		e, ok := c.lrc.Peek(key)
		if !ok {
			continue
		}
		f := e.flow
		// 跳过刚创建（<1s）的流，避免无意义快照
		if now.Sub(f.StartTime) < time.Second {
			continue
		}

		dur := now.Sub(f.StartTime)
		row := storage.L4FlowLog{
			StartTime:  f.StartTime,
			EndTime:    now,
			DurationUs: uint64(dur.Microseconds()),

			SrcIP:    storage.SafeIPv4(f.SrcIP),
			DstIP:    storage.SafeIPv4(f.DstIP),
			SrcPort:  f.SrcPort,
			DstPort:  f.DstPort,
			Protocol: 6, // TCP

			PID:         f.PID,
			ProcessName: f.ProcessName,

			// close_type = 0 表示 FLUSH 快照（非真实关闭）
			Role:      uint8(f.Role),
			CloseType: 0,

			BytesSent:       f.BytesSent,
			BytesReceived:   f.BytesReceived,
			PacketsSent:     f.PacketsSent,
			PacketsReceived: f.PacketsReceived,

			SynRttUs:       uint32(f.SynRTT.Microseconds()),
			SynRttClientUs: uint32(f.SynRTTClient.Microseconds()),
			SynRttServerUs: uint32(f.SynRTTServer.Microseconds()),
			RTTMinUs:       uint32(f.RTTMin.Microseconds()),
			RTTMeanUs:      uint32(f.RTTMean.Microseconds()),
			RTTMaxUs:       uint32(f.RTTMax.Microseconds()),
			SRTMeanUs:      uint32(f.SRTMean.Microseconds()),
			SRTMaxUs:       uint32(f.SRTMax.Microseconds()),

			RetransCnt:    f.RetransCount,
			RetransBytes:  f.RetransBytes,
			ZeroWndCnt:    f.ZeroWndCount,
			ZeroWndUs:     uint64(f.ZeroWndDuration.Microseconds()),
			RSTCnt:        f.RSTCount,
			SynRetransCnt: f.SynRetransCount,

			PodIP: storage.SafeIPv4(""),
		}

		// 重传率
		totalPkts := f.PacketsSent + f.PacketsReceived
		if totalPkts > 0 {
			row.RetransRatio = float32(f.RetransCount) / float32(totalPkts)
		}

		// 注入云标签
		if tag, ok := f.CloudTag.(*cloudmeta.CloudTag); ok && tag != nil {
			row.PodName      = tag.PodName
			row.PodNamespace = tag.PodNamespace
			row.ServiceName  = tag.ServiceName
			row.NodeName     = tag.NodeName
			row.PodIP        = storage.SafeIPv4(tag.PodIP)
			row.Region       = tag.Region
			row.AZ           = tag.AZ
			row.AppLabels    = tag.AppLabelsJSON()
		}

		c.store.WriteL4FlowLog(row)
		flushed++
	}

	if flushed > 0 {
		log.WithFields(log.Fields{
			"flushed":    flushed,
			"cache_size": c.lrc.Len(),
		}).Debug("TCP flow cache flush snapshot → l4_flow_log")
	}
}
