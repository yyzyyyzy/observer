// cmd/agent/main.go
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"observer/pkg/collector"
	"observer/pkg/config"
	"observer/pkg/ebpf"
)

var (
	cfgFile string
	version = "2.0.0"
)

var rootCmd = &cobra.Command{
	Use:   "observer-agent",
	Short: "Network Observer - eBPF-based network observability platform",
	Long: `Network Observer is a high-performance network observability platform
based on eBPF technology, providing deep insights into TCP/UDP network traffic.`,
	Run: runAgent,
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./config.yaml)")
	rootCmd.PersistentFlags().String("log-level", "info", "log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().String("log-format", "json", "log format (json, text)")
	rootCmd.PersistentFlags().String("listen", ":8080", "HTTP listen address")

	viper.BindPFlag("log.level", rootCmd.PersistentFlags().Lookup("log-level"))
	viper.BindPFlag("log.format", rootCmd.PersistentFlags().Lookup("log-format"))
	viper.BindPFlag("http.listen", rootCmd.PersistentFlags().Lookup("listen"))
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath(".")
		viper.AddConfigPath("/etc/observer/")
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}
	viper.AutomaticEnv()
	if err := viper.ReadInConfig(); err == nil {
		log.WithField("config", viper.ConfigFileUsed()).Info("Using config file")
	}
}

func setupLogging(cfg *config.Config) {
	logLevel, err := log.ParseLevel(cfg.Log.Level)
	if err != nil {
		log.WithError(err).Warn("Invalid log level, using info")
		logLevel = log.InfoLevel
	}
	log.SetLevel(logLevel)

	if cfg.Log.Format == "json" {
		log.SetFormatter(&log.JSONFormatter{TimestampFormat: time.RFC3339Nano})
	} else {
		log.SetFormatter(&log.TextFormatter{FullTimestamp: true, TimestampFormat: time.RFC3339})
	}

	log.WithFields(log.Fields{
		"version":    version,
		"log_level":  cfg.Log.Level,
		"log_format": cfg.Log.Format,
	}).Info("Observer agent starting")
}

func runAgent(cmd *cobra.Command, args []string) {
	// 加载配置
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	setupLogging(cfg)

	if os.Geteuid() != 0 {
		log.Fatal("This program must be run as root (eBPF requires CAP_SYS_ADMIN)")
	}

	// ==================== 初始化 Collector ====================
	tcpCollector := collector.NewTCPCollector()
	defer tcpCollector.Close()

	udpCollector := collector.NewUDPCollector()
	defer udpCollector.Close()

	tcCollector := collector.NewTCCollector()
	defer tcCollector.Close()

	// ==================== 初始化 eBPF Manager ====================
	mgr := ebpf.NewManager(ebpf.ManagerOptions{
		RingBufSize: cfg.EBPF.RingBufSize,
		MaxFlows:    cfg.EBPF.MaxFlows,
		BPFObjDir:   cfg.EBPF.BPFObjDir,
	})

	// 注册事件分发器
	dispatcher := collector.NewDispatcher(tcpCollector, udpCollector, tcCollector)
	mgr.RegisterTCPHandler(dispatcher)
	mgr.RegisterUDPHandler(dispatcher)
	mgr.RegisterTCPacketHandler(dispatcher)

	// 启动 eBPF 程序
	if err := mgr.Start(); err != nil {
		log.WithError(err).Fatal("Failed to start eBPF manager")
	}
	defer mgr.Stop()
	log.Info("eBPF manager started")

	// ==================== 速率计算定时器 ====================
	ratesTicker := time.NewTicker(cfg.StatsWindowDuration())
	defer ratesTicker.Stop()
	go func() {
		for range ratesTicker.C {
			tcpCollector.CalculateRates()
			udpCollector.CalculateRates()
		}
	}()

	// ==================== 连接 GC 定时器 ====================
	gcTicker := time.NewTicker(cfg.ConnectionGCDuration())
	defer gcTicker.Stop()
	go func() {
		for range gcTicker.C {
			tcpCollector.GCStaleConnections(cfg.ConnectionGCDuration())
		}
	}()

	// ==================== pprof（调试模式）====================
	if cfg.Advanced.Debug && cfg.Advanced.PprofPort > 0 {
		pprofAddr := fmt.Sprintf(":%d", cfg.Advanced.PprofPort)
		go func() {
			log.WithField("addr", pprofAddr).Info("pprof server starting")
			if err := http.ListenAndServe(pprofAddr, nil); err != nil {
				log.WithError(err).Warn("pprof server stopped")
			}
		}()
	}

	// ==================== HTTP 服务 ====================
	metricsPath := cfg.HTTP.MetricsPath
	if metricsPath == "" {
		metricsPath = "/metrics"
	}
	healthPath := cfg.HTTP.HealthPath
	if healthPath == "" {
		healthPath = "/health"
	}

	mux := http.NewServeMux()
	mux.Handle(metricsPath, promhttp.Handler())
	mux.HandleFunc(healthPath, healthHandler)
	mux.HandleFunc("/", indexHandler(metricsPath))

	server := &http.Server{
		Addr:         cfg.HTTP.Listen,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		log.WithFields(log.Fields{
			"address":      cfg.HTTP.Listen,
			"metrics_path": metricsPath,
		}).Info("HTTP server starting")
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.WithError(err).Fatal("HTTP server failed")
		}
	}()

	// ==================== 等待信号优雅退出 ====================
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.WithField("signal", sig).Info("Received shutdown signal")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.WithError(err).Error("HTTP server shutdown error")
	}

	log.Info("Observer agent stopped")
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"ok","version":"%s"}`, version)
}

func indexHandler(metricsPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>Network Observer</title>
<style>body{font-family:Arial,sans-serif;margin:40px}h1{color:#333}
.info{background:#f0f0f0;padding:20px;border-radius:5px}
a{color:#0066cc;text-decoration:none}a:hover{text-decoration:underline}</style>
</head><body>
<h1>Network Observer v%s</h1>
<div class="info">
  <h2>Endpoints</h2>
  <ul>
    <li><a href="%s">Prometheus Metrics</a></li>
    <li><a href="/health">Health Check</a></li>
  </ul>
  <h2>Features</h2>
  <ul>
    <li>eBPF-based zero-overhead network monitoring</li>
    <li>TCP latency: SYN RTT, data RTT, system RTT</li>
    <li>TCP performance: retransmission, zero-window</li>
    <li>TCP anomaly detection (12+ types)</li>
    <li>UDP flow tracking</li>
    <li>TC-layer packet inspection</li>
  </ul>
</div></body></html>`, version, metricsPath)
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
