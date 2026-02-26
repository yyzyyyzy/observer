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
