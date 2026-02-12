// pkg/config/config.go
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
	BPFObjDir      string `mapstructure:"bpf_obj_dir"`
}

// CollectorConfig 采集器开关配置
type CollectorConfig struct {
	TCP TCPCollectorConfig `mapstructure:"tcp"`
	UDP UDPCollectorConfig `mapstructure:"udp"`
	TC  TCCollectorConfig  `mapstructure:"tc"`
}

// TCPCollectorConfig TCP 采集器配置
type TCPCollectorConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

// UDPCollectorConfig UDP 采集器配置
type UDPCollectorConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

// TCCollectorConfig TC 采集器配置
type TCCollectorConfig struct {
	Enabled    bool     `mapstructure:"enabled"`
	Interfaces []string `mapstructure:"interfaces"`
}

// MetricsConfig 指标配置
type MetricsConfig struct {
	EnableHistograms bool      `mapstructure:"enable_histograms"`
	LatencyBuckets   []float64 `mapstructure:"latency_buckets"`
	StatsWindow      int       `mapstructure:"stats_window"` // 秒
}

// LogConfig 日志配置
type LogConfig struct {
	Level      string `mapstructure:"level"`
	Format     string `mapstructure:"format"`
	Output     string `mapstructure:"output"`
	FilePath   string `mapstructure:"file_path"`
	MaxSize    int    `mapstructure:"max_size"`
	MaxAge     int    `mapstructure:"max_age"`
	MaxBackups int    `mapstructure:"max_backups"`
}

// PerformanceConfig 性能调优配置
type PerformanceConfig struct {
	WorkerThreads      int  `mapstructure:"worker_threads"`
	EventQueueSize     int  `mapstructure:"event_queue_size"`
	BatchSize          int  `mapstructure:"batch_size"`
	EnableCPUAffinity  bool `mapstructure:"enable_cpu_affinity"`
}

// AdvancedConfig 高级配置
type AdvancedConfig struct {
	Debug                  bool `mapstructure:"debug"`
	PprofPort              int  `mapstructure:"pprof_port"`
	ConnectionGCInterval   int  `mapstructure:"connection_gc_interval"`
	StatsInterval          int  `mapstructure:"stats_interval"`
}

// defaults 设置 Viper 默认值
func defaults() {
	viper.SetDefault("http.listen",       ":8080")
	viper.SetDefault("http.metrics_path", "/metrics")
	viper.SetDefault("http.health_path",  "/health")

	viper.SetDefault("ebpf.ring_buf_size",   262144)
	viper.SetDefault("ebpf.max_flows",         10240)
	viper.SetDefault("ebpf.sampling_rate",     100)
	viper.SetDefault("ebpf.enable_btf",        true)
	viper.SetDefault("ebpf.bpf_obj_dir",       "./bpf")

	viper.SetDefault("collector.tcp.enabled", true)
	viper.SetDefault("collector.udp.enabled", true)
	viper.SetDefault("collector.tc.enabled",  false)

	viper.SetDefault("metrics.enable_histograms", true)
	viper.SetDefault("metrics.stats_window",       60)
	viper.SetDefault("metrics.latency_buckets", []float64{
		100, 200, 500,
		1000, 2000, 5000,
		10000, 20000, 50000,
		100000, 200000, 500000,
		1000000, 5000000, 10000000,
	})

	viper.SetDefault("log.level",  "info")
	viper.SetDefault("log.format", "json")
	viper.SetDefault("log.output", "stdout")

	viper.SetDefault("performance.event_queue_size", 10000)
	viper.SetDefault("performance.batch_size",        100)

	viper.SetDefault("advanced.connection_gc_interval", 300)
	viper.SetDefault("advanced.stats_interval",          60)
}

// Load 加载并验证配置
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

// validate 校验配置合法性
func validate(cfg *Config) error {
	if cfg.EBPF.SamplingRate < 1 || cfg.EBPF.SamplingRate > 100 {
		return fmt.Errorf("ebpf.sampling_rate must be 1-100, got %d", cfg.EBPF.SamplingRate)
	}
	if cfg.EBPF.RingBufSize < 4096 {
		return fmt.Errorf("ebpf.ring_buf_size must be >= 4096")
	}
	if cfg.Metrics.StatsWindow < 1 {
		return fmt.Errorf("metrics.stats_window must be >= 1")
	}
	return nil
}

// StatsWindowDuration 返回统计窗口的 time.Duration
func (c *Config) StatsWindowDuration() time.Duration {
	return time.Duration(c.Metrics.StatsWindow) * time.Second
}

// ConnectionGCDuration 返回连接 GC 间隔的 time.Duration
func (c *Config) ConnectionGCDuration() time.Duration {
	return time.Duration(c.Advanced.ConnectionGCInterval) * time.Second
}
