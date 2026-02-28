// cmd/agent/main.go — Observer Agent 入口

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

	"observer/pkg/cloudmeta"
	"observer/pkg/collector"
	"observer/pkg/config"
	"observer/pkg/ebpf"
	"observer/pkg/flow"
	"observer/pkg/l7"
	"observer/pkg/storage"
	"observer/pkg/wasm"
)

var (
	cfgFile string
	version = "10.0.0"
)

var rootCmd = &cobra.Command{
	Use:   "observer-agent",
	Short: "Observer — eBPF Network Observability Agent",
	RunE:  runAgent,
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file path")
	rootCmd.PersistentFlags().String("log-level", "info", "log level (debug/info/warn/error)")
	rootCmd.PersistentFlags().String("log-format", "json", "log format (json/text)")
	rootCmd.PersistentFlags().String("listen", ":8080", "HTTP listen address")
	_ = viper.BindPFlag("log.level", rootCmd.PersistentFlags().Lookup("log-level"))
	_ = viper.BindPFlag("log.format", rootCmd.PersistentFlags().Lookup("log-format"))
	_ = viper.BindPFlag("http.listen", rootCmd.PersistentFlags().Lookup("listen"))
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
		log.WithField("file", viper.ConfigFileUsed()).Info("Config loaded")
	}
}

func setupLogging(cfg *config.Config) {
	lvl, err := log.ParseLevel(cfg.Log.Level)
	if err != nil {
		lvl = log.InfoLevel
	}
	log.SetLevel(lvl)
	if cfg.Log.Format == "json" {
		log.SetFormatter(&log.JSONFormatter{TimestampFormat: time.RFC3339Nano})
	} else {
		log.SetFormatter(&log.TextFormatter{FullTimestamp: true})
	}
	log.WithFields(log.Fields{
		"version": version,
		"pid":     os.Getpid(),
	}).Info("Observer agent starting")
}

func runAgent(_ *cobra.Command, _ []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	setupLogging(cfg)

	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root (eBPF requires CAP_SYS_ADMIN/CAP_BPF)")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ── ① ClickHouse 存储 ─────────────────────────────────
	var chClient *storage.ClickHouseClient
	if cfg.ClickHouse.Enabled {
		chClient, err = storage.NewClickHouseClient(cfg.ClickHouse)
		if err != nil {
			return fmt.Errorf("clickhouse connect: %w", err)
		}
		defer chClient.Close()
		log.Info("ClickHouse: l4_flow_log + l7_flow_log enabled")
	}

	// ── ② K8s Informer 云标签 ──────────────────────────────
	var metaProvider cloudmeta.MetaProvider = &cloudmeta.NoopMetaProvider{}
	if cfg.CloudMeta.Enabled {
		k8sMeta, k8sErr := cloudmeta.NewK8sMetaProvider(cfg.CloudMeta)
		if k8sErr != nil {
			log.WithError(k8sErr).Warn("K8s meta provider init failed, using noop")
		} else {
			if syncErr := k8sMeta.Start(ctx); syncErr != nil {
				log.WithError(syncErr).Warn("K8s informer cache sync warn")
			}
			metaProvider = k8sMeta
			defer k8sMeta.Stop()
			log.WithField("stats", k8sMeta.Stats()).Info("K8s Informer cloud meta ready")
		}
	}

	// ── ③ wazero WASM 插件运行时 ──────────────────────────
	wasmRuntime, wasmErr := wasm.NewRuntime(cfg.WASM)
	if wasmErr != nil {
		log.WithError(wasmErr).Warn("WASM runtime init failed")
	}
	if wasmRuntime != nil {
		defer wasmRuntime.Close()
	}

	// ── ④ L7 协议解析注册表 ───────────────────────────────
	var l7Registry *l7.Registry
	if cfg.L7.Enabled {
		// 构建端口过滤器（Go 层），对齐 DeepFlow l7_skip_port_set
		skipPorts := cfg.EffectiveSkipPorts()
		portFilter := l7.NewPortFilter(skipPorts)
		l7Registry = l7.NewRegistryWithFilter(chClient, portFilter)
		if wasmRuntime != nil {
			for _, p := range wasmRuntime.Parsers() {
				l7Registry.Register(p)
			}
		}
		log.WithField("skip_ports", skipPorts).Info("L7 registry: HTTP/HTTP2/gRPC/MySQL/Redis/DNS/Kafka/Ping/TLS + wazero WASM plugins")
	}

	// ── ⑤ TCP Flow Cache ──────────────────────────────────
	tcpCache := flow.NewCacheWithDeps(
		flow.CacheConfig{
			MaxFlows:      cfg.EBPF.MaxFlows,
			FlowTTL:       cfg.ConnectionGCDuration(),
			FlushInterval: cfg.StatsWindowDuration(),
		},
		chClient,
		metaProvider,
	)

	// ── ⑥ UDP Flow Cache ──────────────────────────────────
	udpCache := flow.NewUDPCache(
		flow.CacheConfig{
			MaxFlows: cfg.EBPF.MaxFlows,
			FlowTTL:  2 * time.Minute,
		},
		chClient,
		metaProvider,
	)

	// ── ⑦ Collectors ──────────────────────────────────────
	tcpCollector := collector.NewTCPCollector(tcpCache)
	defer tcpCollector.Close()

	udpCollector := collector.NewUDPCollectorWithDeps(udpCache)
	defer udpCollector.Close()

	tcCollector := collector.NewTCCollector()
	defer tcCollector.Close()

	// ── ⑧ eBPF Manager ────────────────────────────────────
	mgr := ebpf.NewManager(ebpf.ManagerOptions{
		RingBufSize:  cfg.EBPF.RingBufSize,
		MaxFlows:     cfg.EBPF.MaxFlows,
		BPFObjDir:    cfg.EBPF.BPFObjDir,
		TCInterfaces: cfg.Collector.TC.Interfaces,
		// SkipPorts 写入 BPF l7_skip_ports map，在内核态过滤端口噪声
		SkipPorts:    cfg.EffectiveSkipPorts(),
	})

	disp := collector.NewDispatcher(tcpCollector, udpCollector, tcCollector)
	mgr.RegisterTCPHandler(disp)
	mgr.RegisterUDPHandler(disp)
	mgr.RegisterTCPacketHandler(disp)
	if l7Registry != nil {
		mgr.RegisterL7Handler(l7Registry)
	}

	if err := mgr.Start(); err != nil {
		return fmt.Errorf("eBPF manager start: %w", err)
	}
	defer mgr.Stop()

	log.Info("eBPF manager started: TCP(10 hooks) + UDP(3 hooks) + L7(4 hooks) + TC(ingress+egress)")

	// ── ⑨ 定时任务 ────────────────────────────────────────

	// BPS/PPS 速率计算
	rateTick := time.NewTicker(cfg.StatsWindowDuration())
	defer rateTick.Stop()
	go func() {
		for range rateTick.C {
			tcpCollector.CalculateRates()
			udpCollector.CalculateRates()
			tcCollector.CalculatePPS()
		}
	}()

	// TCP Flow Prometheus 指标快照
	flushTick := time.NewTicker(cfg.StatsWindowDuration())
	defer flushTick.Stop()
	go func() {
		for range flushTick.C {
			tcpCache.Flush()
			tcpCache.FlushSnapshot()
		}
	}()

	// TCP Flow TTL GC
	tcpGCTick := time.NewTicker(cfg.ConnectionGCDuration())
	defer tcpGCTick.Stop()
	go func() {
		for range tcpGCTick.C {
			if n := tcpCache.RunGC(); n > 0 {
				log.WithField("evicted", n).Debug("TCP flow GC")
			}
		}
	}()

	// UDP Flow GC（idle > 2min）
	udpGCTick := time.NewTicker(30 * time.Second)
	defer udpGCTick.Stop()
	go func() {
		for range udpGCTick.C {
			if n := udpCache.RunGC(); n > 0 {
				log.WithField("evicted", n).Debug("UDP flow GC → l4_flow_log")
			}
		}
	}()

	// pprof（调试模式）
	if cfg.Advanced.Debug && cfg.Advanced.PprofPort > 0 {
		go func() {
			addr := fmt.Sprintf(":%d", cfg.Advanced.PprofPort)
			log.WithField("addr", addr).Info("pprof server started")
			_ = http.ListenAndServe(addr, nil)
		}()
	}

	// ── ⑩ HTTP 服务 ───────────────────────────────────────
	mux := http.NewServeMux()
	mux.Handle(cfg.HTTP.MetricsPath, promhttp.Handler())
	mux.HandleFunc(cfg.HTTP.HealthPath, healthHandler)
	mux.HandleFunc("/debug/cloud_tags", debugCloudTagsHandler(metaProvider))
	mux.HandleFunc("/", indexHandler(cfg, version))

	srv := &http.Server{
		Addr:         cfg.HTTP.Listen,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	go func() {
		log.WithFields(log.Fields{
			"addr":    cfg.HTTP.Listen,
			"metrics": cfg.HTTP.MetricsPath,
		}).Info("HTTP server started")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.WithError(err).Fatal("HTTP server error")
		}
	}()

	// ── 优雅退出 ───────────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.WithField("signal", sig).Info("Shutdown signal received")

	cancel()
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutCancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		log.WithError(err).Error("HTTP server shutdown error")
	}
	log.WithField("version", version).Info("Observer agent stopped")
	return nil
}

// ── HTTP Handlers ──────────────────────────────────────────

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok","version":"%s","ts":%d}`, version, time.Now().Unix())
}

func debugCloudTagsHandler(meta cloudmeta.MetaProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.URL.Query().Get("ip")
		if ip == "" {
			if k8s, ok := meta.(*cloudmeta.K8sMetaProvider); ok {
				tags := k8s.DumpTags()
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"count":%d}`, len(tags))
			} else {
				http.Error(w, `{"error":"noop provider"}`, http.StatusServiceUnavailable)
			}
			return
		}
		tag := meta.GetTag(ip)
		if tag == nil {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"pod":%q,"ns":%q,"svc":%q,"node":%q,"region":%q,"az":%q}`,
			tag.PodName, tag.PodNamespace, tag.ServiceName,
			tag.NodeName, tag.Region, tag.AZ)
	}
}

func indexHandler(cfg *config.Config, ver string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, indexHTML,
			ver, ver,
			cfg.HTTP.MetricsPath, cfg.HTTP.MetricsPath,
			cfg.HTTP.HealthPath, cfg.HTTP.HealthPath,
			cfg.ClickHouse.Enabled, cfg.L7.Enabled, cfg.WASM.Enabled, cfg.CloudMeta.Enabled)
	}
}

const indexHTML = `<!DOCTYPE html>
<html><head><title>Observer v%s</title><meta charset="utf-8">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0a0f1e;color:#e2e8f0;min-height:100vh}
.container{max-width:960px;margin:0 auto;padding:40px 20px}
h1{font-size:2rem;color:#38bdf8;margin-bottom:4px}
.sub{color:#64748b;font-size:.9rem;margin-bottom:28px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px}
.card{background:#111827;border:1px solid #1f2d44;border-radius:12px;padding:20px}
.card h3{font-size:.75rem;color:#6b7280;text-transform:uppercase;letter-spacing:.08em;margin-bottom:12px}
.row{display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid #1f2d44;font-size:.85rem}
.row:last-child{border:none}
.val{color:#38bdf8;font-weight:600}
.tag{display:inline-block;padding:2px 9px;border-radius:99px;font-size:.75rem;margin:2px}
.green{background:#052e16;color:#4ade80;border:1px solid #14532d}
.blue{background:#0c1a3e;color:#60a5fa;border:1px solid #1e3a8a}
.violet{background:#1e1040;color:#a78bfa;border:1px solid #3730a3}
.amber{background:#1c1000;color:#fbbf24;border:1px solid #78350f}
a{color:#38bdf8;text-decoration:none}
</style>
</head><body><div class="container">
<h1>🔭 Observer v%s</h1>
<p class="sub">eBPF Network Observability · IPv4/IPv6 · TCP/UDP/L7 · wazero · K8s AutoTagging</p>
<div class="grid">
<div class="card"><h3>Endpoints</h3>
<div class="row"><span>Prometheus</span><a class="val" href="%s">%s</a></div>
<div class="row"><span>Health</span><a class="val" href="%s">%s</a></div>
<div class="row"><span>Cloud Tags</span><a class="val" href="/debug/cloud_tags">/debug/cloud_tags</a></div>
<div class="row"><span>pprof</span><span class="val">/debug/pprof</span></div>
</div>
<div class="card"><h3>Components</h3>
<div class="row"><span>ClickHouse</span><span class="val">%v</span></div>
<div class="row"><span>L7 Parsing</span><span class="val">%v</span></div>
<div class="row"><span>WASM (wazero)</span><span class="val">%v</span></div>
<div class="row"><span>K8s CloudMeta</span><span class="val">%v</span></div>
</div>
</div>
<div class="card"><h3>L4 Capabilities</h3>
<span class="tag green">TCP FLOW_CREATE/UPDATE/DESTROY</span>
<span class="tag green">UDP Flow Aggregation</span>
<span class="tag green">SYN RTT (3-segment)</span>
<span class="tag green">RTT min/avg/max</span>
<span class="tag green">SRT (Server Response Time)</span>
<span class="tag green">Retrans + Zero-Window</span>
<span class="tag green">Role: CLIENT/SERVER (100%% accurate)</span>
<span class="tag green">LRU Cache + TTL GC</span>
<span class="tag green">FlowKey Normalization</span>
<span class="tag green">l4_flow_log → ClickHouse</span>
<span class="tag green">PID/Port Filter Maps</span>
</div>
<div class="card" style="margin-top:16px"><h3>L7 + TC + Cloud</h3>
<span class="tag blue">HTTP/1.1 + HTTP/2</span>
<span class="tag blue">gRPC</span>
<span class="tag blue">MySQL</span>
<span class="tag blue">Redis RESP</span>
<span class="tag blue">DNS RFC1035</span>
<span class="tag blue">Kafka</span>
<span class="tag blue">ICMP Ping</span>
<span class="tag green">TC IPv4 + IPv6</span>
<span class="tag green">VLAN 802.1Q</span>
<span class="tag violet">wazero WASM Extension</span>
<span class="tag amber">K8s Pod/Svc/Node Informer</span>
<span class="tag amber">l7_flow_log → ClickHouse</span>
</div>
</div></body></html>`

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
