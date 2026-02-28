// pkg/config/config.go
// 全局配置，对齐 DeepFlow：ClickHouse 存储、L7 解析、WASM 插件、云标签注入
package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

// Config 全局配置结构
type Config struct {
	HTTP        HTTPConfig        `mapstructure:"http"`
	EBPF        EBPFConfig        `mapstructure:"ebpf"`
	Collector   CollectorConfig   `mapstructure:"collector"`
	ClickHouse  ClickHouseConfig  `mapstructure:"clickhouse"`
	L7          L7Config          `mapstructure:"l7"`
	WASM        WASMConfig        `mapstructure:"wasm"`
	CloudMeta   CloudMetaConfig   `mapstructure:"cloud_meta"`
	Metrics     MetricsConfig     `mapstructure:"metrics"`
	Log         LogConfig         `mapstructure:"log"`
	Performance PerformanceConfig `mapstructure:"performance"`
	Advanced    AdvancedConfig    `mapstructure:"advanced"`
}

// HTTPConfig HTTP 服务配置
type HTTPConfig struct {
	Listen      string `mapstructure:"listen"`
	MetricsPath string `mapstructure:"metrics_path"`
	HealthPath  string `mapstructure:"health_path"`
}

// EBPFConfig eBPF 程序配置
type EBPFConfig struct {
	RingBufSize  int    `mapstructure:"ring_buf_size"`
	MaxFlows     int    `mapstructure:"max_flows"`
	SamplingRate int    `mapstructure:"sampling_rate"`
	EnableBTF    bool   `mapstructure:"enable_btf"`
	BPFObjDir    string `mapstructure:"bpf_obj_dir"`
}

// CollectorConfig 采集器开关配置
type CollectorConfig struct {
	TCP TCPCollectorConfig `mapstructure:"tcp"`
	UDP UDPCollectorConfig `mapstructure:"udp"`
	TC  TCCollectorConfig  `mapstructure:"tc"`
}

type TCPCollectorConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

type UDPCollectorConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

type TCCollectorConfig struct {
	Enabled    bool     `mapstructure:"enabled"`
	Interfaces []string `mapstructure:"interfaces"`
}

// ClickHouseConfig ClickHouse 存储配置（对齐 DeepFlow）
type ClickHouseConfig struct {
	Enabled          bool          `mapstructure:"enabled"`
	Addresses        []string      `mapstructure:"addresses"`
	Database         string        `mapstructure:"database"`
	Username         string        `mapstructure:"username"`
	Password         string        `mapstructure:"password"`
	// L4 流日志批写入配置
	L4BatchSize      int           `mapstructure:"l4_batch_size"`
	L4FlushInterval  time.Duration `mapstructure:"l4_flush_interval"`
	// L7 流日志批写入配置
	L7BatchSize      int           `mapstructure:"l7_batch_size"`
	L7FlushInterval  time.Duration `mapstructure:"l7_flush_interval"`
	// 数据保留策略（天）
	L4RetentionDays  int           `mapstructure:"l4_retention_days"`
	L7RetentionDays  int           `mapstructure:"l7_retention_days"`
	// 连接池
	MaxOpenConns     int           `mapstructure:"max_open_conns"`
	MaxIdleConns     int           `mapstructure:"max_idle_conns"`
	DialTimeout      time.Duration `mapstructure:"dial_timeout"`
}

// L7Config L7 协议解析配置
type L7Config struct {
	Enabled        bool            `mapstructure:"enabled"`
	MaxPayloadSize int             `mapstructure:"max_payload_size"` // 抓取的载荷最大字节数
	Protocols      L7Protocols     `mapstructure:"protocols"`
	// SkipPorts 端口黑名单（BPF层 + Go层双重过滤）。
	// 这些端口上的流量不会进入 L7 解析流程，直接丢弃。
	// 用于规避：SSH(22)、Agent自身HTTP(8080)、ClickHouse(9000)、
	// Prometheus(9090)、VNC(5900-5999)等已知无法识别或自身服务流量。
	// 配置格式：端口号列表，例如 [22, 8080, 9000, 9090]
	// 留空时使用内置默认黑名单（参见 DefaultSkipPorts）。
	SkipPorts      []uint16        `mapstructure:"skip_ports"`
}

type L7Protocols struct {
	HTTP    L7ProtocolConfig `mapstructure:"http"`
	MySQL   L7ProtocolConfig `mapstructure:"mysql"`
	Redis   L7ProtocolConfig `mapstructure:"redis"`
	DNS     L7ProtocolConfig `mapstructure:"dns"`
	Kafka   L7ProtocolConfig `mapstructure:"kafka"`
	GRPC    L7ProtocolConfig `mapstructure:"grpc"`
}

type L7ProtocolConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

// WASMConfig WASM 插件配置
type WASMConfig struct {
	Enabled    bool         `mapstructure:"enabled"`
	PluginDir  string       `mapstructure:"plugin_dir"`
	Plugins    []WASMPlugin `mapstructure:"plugins"`
}

type WASMPlugin struct {
	Name     string            `mapstructure:"name"`
	Path     string            `mapstructure:"path"`
	Protocol string            `mapstructure:"protocol"` // 该插件解析的协议名
	Config   map[string]string `mapstructure:"config"`
}

// CloudMetaConfig 云标签注入配置（K8s / 云厂商）
type CloudMetaConfig struct {
	Enabled         bool              `mapstructure:"enabled"`
	Provider        string            `mapstructure:"provider"` // kubernetes, aws, aliyun
	SyncInterval    time.Duration     `mapstructure:"sync_interval"`
	Kubernetes      K8sConfig         `mapstructure:"kubernetes"`
	ExtraLabels     map[string]string `mapstructure:"extra_labels"`
}

type K8sConfig struct {
	InCluster       bool   `mapstructure:"in_cluster"`
	KubeConfigPath  string `mapstructure:"kubeconfig_path"`
	// 注入哪些 K8s 标签到流记录
	InjectPodLabels bool   `mapstructure:"inject_pod_labels"`
	InjectNamespace bool   `mapstructure:"inject_namespace"`
	InjectNodeName  bool   `mapstructure:"inject_node_name"`
}

// MetricsConfig 指标配置
type MetricsConfig struct {
	EnableHistograms bool      `mapstructure:"enable_histograms"`
	LatencyBuckets   []float64 `mapstructure:"latency_buckets"`
	StatsWindow      int       `mapstructure:"stats_window"` // 秒
}

// LogConfig 日志配置
type LogConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
	Output string `mapstructure:"output"`
}

// PerformanceConfig 性能调优配置
type PerformanceConfig struct {
	WorkerThreads  int `mapstructure:"worker_threads"`
	EventQueueSize int `mapstructure:"event_queue_size"`
	BatchSize      int `mapstructure:"batch_size"`
}

// AdvancedConfig 高级配置
type AdvancedConfig struct {
	Debug                bool `mapstructure:"debug"`
	PprofPort            int  `mapstructure:"pprof_port"`
	ConnectionGCInterval int  `mapstructure:"connection_gc_interval"`
	StatsInterval        int  `mapstructure:"stats_interval"`
}

func defaults() {
	viper.SetDefault("http.listen", ":8080")
	viper.SetDefault("http.metrics_path", "/metrics")
	viper.SetDefault("http.health_path", "/health")

	viper.SetDefault("ebpf.ring_buf_size", 262144)
	viper.SetDefault("ebpf.max_flows", 65536)
	viper.SetDefault("ebpf.sampling_rate", 100)
	viper.SetDefault("ebpf.enable_btf", true)
	viper.SetDefault("ebpf.bpf_obj_dir", "./bpf")

	viper.SetDefault("collector.tcp.enabled", true)
	viper.SetDefault("collector.udp.enabled", true)
	viper.SetDefault("collector.tc.enabled", false)

	// ClickHouse 默认配置
	viper.SetDefault("clickhouse.enabled", false)
	viper.SetDefault("clickhouse.addresses", []string{"127.0.0.1:9000"})
	viper.SetDefault("clickhouse.database", "flow_metrics")
	viper.SetDefault("clickhouse.username", "default")
	viper.SetDefault("clickhouse.password", "")
	viper.SetDefault("clickhouse.l4_batch_size", 1000)
	viper.SetDefault("clickhouse.l4_flush_interval", 5*time.Second)
	viper.SetDefault("clickhouse.l7_batch_size", 1000)
	viper.SetDefault("clickhouse.l7_flush_interval", 5*time.Second)
	viper.SetDefault("clickhouse.l4_retention_days", 7)
	viper.SetDefault("clickhouse.l7_retention_days", 3)
	viper.SetDefault("clickhouse.max_open_conns", 10)
	viper.SetDefault("clickhouse.max_idle_conns", 5)
	viper.SetDefault("clickhouse.dial_timeout", 10*time.Second)

	// L7 默认配置
	viper.SetDefault("l7.enabled", true)
	viper.SetDefault("l7.max_payload_size", 4096)
	viper.SetDefault("l7.protocols.http.enabled", true)
	viper.SetDefault("l7.protocols.mysql.enabled", true)
	viper.SetDefault("l7.protocols.redis.enabled", true)
	viper.SetDefault("l7.protocols.dns.enabled", true)
	viper.SetDefault("l7.protocols.kafka.enabled", false)
	viper.SetDefault("l7.protocols.grpc.enabled", false)

	// WASM 默认配置
	viper.SetDefault("wasm.enabled", false)
	viper.SetDefault("wasm.plugin_dir", "./plugins")

	// 云标签默认配置
	viper.SetDefault("cloud_meta.enabled", false)
	viper.SetDefault("cloud_meta.provider", "kubernetes")
	viper.SetDefault("cloud_meta.sync_interval", 30*time.Second)
	viper.SetDefault("cloud_meta.kubernetes.in_cluster", true)
	viper.SetDefault("cloud_meta.kubernetes.inject_pod_labels", true)
	viper.SetDefault("cloud_meta.kubernetes.inject_namespace", true)
	viper.SetDefault("cloud_meta.kubernetes.inject_node_name", true)

	viper.SetDefault("metrics.enable_histograms", true)
	viper.SetDefault("metrics.stats_window", 60)
	viper.SetDefault("metrics.latency_buckets", []float64{
		100, 200, 500, 1000, 2000, 5000,
		10000, 20000, 50000, 100000, 500000, 1000000,
	})

	viper.SetDefault("log.level", "info")
	viper.SetDefault("log.format", "json")
	viper.SetDefault("log.output", "stdout")

	viper.SetDefault("performance.event_queue_size", 10000)
	viper.SetDefault("performance.batch_size", 100)

	viper.SetDefault("advanced.connection_gc_interval", 300)
	viper.SetDefault("advanced.stats_interval", 60)
}

func Load() (*Config, error) {
	defaults()
	cfg := &Config{}
	if err := viper.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return cfg, nil
}

func validate(cfg *Config) error {
	if cfg.EBPF.SamplingRate < 1 || cfg.EBPF.SamplingRate > 100 {
		return fmt.Errorf("ebpf.sampling_rate must be 1-100, got %d", cfg.EBPF.SamplingRate)
	}
	if cfg.EBPF.RingBufSize < 4096 {
		return fmt.Errorf("ebpf.ring_buf_size must be >= 4096")
	}
	return nil
}

func (c *Config) StatsWindowDuration() time.Duration {
	return time.Duration(c.Metrics.StatsWindow) * time.Second
}

func (c *Config) ConnectionGCDuration() time.Duration {
	return time.Duration(c.Advanced.ConnectionGCInterval) * time.Second
}

// DefaultSkipPorts 内置端口黑名单（对齐 DeepFlow 同名概念）。
//
// 这些端口的流量通常属于以下类别，无需 L7 解析：
//   - 加密协议（SSH:22）：payload 已加密，任何 parser 均无法识别
//   - 基础设施自身通信（ClickHouse:9000, Prometheus:9090）：已知内部流量
//   - Agent HTTP 服务（:8080）：metrics/health 端点，无需追踪
//   - VNC（5900-5999）：图形协议，非 HTTP/DB 类
//   - RDP（3389）：Windows 远程桌面
//
// 若用户在 config.yaml 的 l7.skip_ports 中提供了非空列表，
// 则以用户配置为准，不追加默认列表。
var DefaultSkipPorts = []uint16{
	22,   // SSH（加密，任何明文 parser 均无法匹配）
	23,   // Telnet（虽然明文，但通常是交互流量，噪声大）
	2222, // 备用 SSH
	3389, // RDP
	5900, 5901, 5902, 5903, 5904, 5990, // VNC
	8080, // Observer agent HTTP（metrics/health 自身端口）
	9000, // ClickHouse native protocol
	9090, // Prometheus（或其他内部监控）
	9100, // node_exporter
}

// EffectiveSkipPorts 返回最终生效的端口黑名单。
// 若用户配置了 l7.skip_ports 则直接使用，否则返回默认列表。
// 并自动追加 Agent 自身 HTTP 监听端口（从 http.listen 解析）。
func (c *Config) EffectiveSkipPorts() []uint16 {
	base := c.L7.SkipPorts
	if len(base) == 0 {
		base = DefaultSkipPorts
	}

	// 自动追加 agent 自身监听端口，避免 metrics/health 请求被解析
	if c.HTTP.Listen != "" {
		_, portStr, err := splitHostPort(c.HTTP.Listen)
		if err == nil && portStr != "" {
			var p uint16
			if _, err2 := fmt.Sscanf(portStr, "%d", &p); err2 == nil && p > 0 {
				base = appendIfMissing(base, p)
			}
		}
	}

	// 自动追加 pprof 端口（debug 模式）
	if c.Advanced.PprofPort > 0 {
		base = appendIfMissing(base, uint16(c.Advanced.PprofPort))
	}

	return base
}

// splitHostPort 简单分割 host:port，支持 ":8080" 和 "0.0.0.0:8080" 两种格式。
func splitHostPort(addr string) (host, port string, err error) {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i], addr[i+1:], nil
		}
	}
	return "", "", fmt.Errorf("no port in %q", addr)
}

func appendIfMissing(ports []uint16, p uint16) []uint16 {
	for _, existing := range ports {
		if existing == p {
			return ports
		}
	}
	return append(ports, p)
}
