// cmd/agent/main.go
// Observer Agent v6
//
// 三项核心升级：
//   1. WASM:      wasmtime-go → wazero（纯 Go，零 CGo，静态链接）
//   2. CloudMeta: Watch/List  → SharedInformerFactory（K8s 标准模式）
//   3. TCP/UDP:   全面对齐 DeepFlow 流设计（inet_csk_accept + SRT + 规范化 FlowKey）

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
	version = "8.0.0"
)

var rootCmd = &cobra.Command{
	Use:   "observer-agent",
	Short: "Observer v6 — eBPF + wazero WASM + K8s Informer + DeepFlow TCP/UDP",
	RunE:  runAgent,
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file path")
	rootCmd.PersistentFlags().String("log-level", "info", "log level (debug/info/warn/error)")
	rootCmd.PersistentFlags().String("log-format", "json", "log format (json/text)")
	rootCmd.PersistentFlags().String("listen", ":8080", "HTTP metrics listen address")
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

func runAgent(cmd *cobra.Command, _ []string) error {
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

	// ── ① ClickHouse 存储 ──────────────────────────────────
	var chClient *storage.ClickHouseClient
	if cfg.ClickHouse.Enabled {
		chClient, err = storage.NewClickHouseClient(cfg.ClickHouse)
		if err != nil {
			return fmt.Errorf("clickhouse connect: %w", err)
		}
		defer chClient.Close()
		log.Info("ClickHouse: l4_flow_log + l7_flow_log enabled")
	}

	// ── ② K8s Informer 云标签提供者 ────────────────────────
	// v6 改进：SharedInformerFactory 替代手动 Watch/List
	//   - 内置断线重连 + 本地缓存 + WaitForCacheSync
	//   - EventHandler 增量维护 IP→Tag，零 API Server 压力
	//   - 正确处理 DeletedFinalStateUnknown
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

	// ── ③ wazero WASM 插件运行时 ───────────────────────────
	// v6 改进：wazero（纯 Go，零 CGo）替代 wasmtime-go（需 CGo + Rust 工具链）
	//   - 无需安装 libwasmtime.a，Docker 镜像无额外依赖
	//   - 任意平台直接 go build，交叉编译友好
	//   - 完整 WASI preview1 支持
	wasmRuntime, wasmErr := wasm.NewRuntime(cfg.WASM)
	if wasmErr != nil {
		log.WithError(wasmErr).Warn("WASM runtime init failed")
	}
	if wasmRuntime != nil {
		defer wasmRuntime.Close()
	}

	// ── ④ L7 协议解析注册表 ────────────────────────────────
	var l7Registry *l7.Registry
	if cfg.L7.Enabled {
		l7Registry = l7.NewRegistry(chClient)
		if wasmRuntime != nil {
			for _, p := range wasmRuntime.Parsers() {
				l7Registry.Register(p)
			}
		}
		log.Info("L7 registry: HTTP/MySQL/Redis/DNS + wazero WASM plugins")
	}

	// ── ⑤ TCP Flow Cache ───────────────────────────────────
	tcpCache := flow.NewCacheWithDeps(
		flow.CacheConfig{
			MaxFlows:      cfg.EBPF.MaxFlows,
			FlowTTL:       cfg.ConnectionGCDuration(),
			FlushInterval: cfg.StatsWindowDuration(),
		},
		chClient,
		metaProvider,
	)

	// ── ⑥ UDP Flow Cache ───────────────────────────────────
	// v6 改进：完整流聚合 + l4_flow_log 写入（对齐 DeepFlow UDP 流设计）
	udpCache := flow.NewUDPCache(
		flow.CacheConfig{
			MaxFlows: cfg.EBPF.MaxFlows,
			FlowTTL:  2 * time.Minute, // UDP idle timeout（DeepFlow 默认 2min）
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
	// v6 改进：新增 inet_csk_accept kprobe/kretprobe
	//   精确判断 TCP 服务端角色（返回值 = new_sk，100% 准确）
	mgr := ebpf.NewManager(ebpf.ManagerOptions{
		RingBufSize:  cfg.EBPF.RingBufSize,
		MaxFlows:     cfg.EBPF.MaxFlows,
		BPFObjDir:    cfg.EBPF.BPFObjDir,
		TCInterfaces: cfg.Collector.TC.Interfaces, // TC 监听接口（需要 enabled=true 且配置 interfaces）
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

	log.Info("eBPF manager started: TCP(10 hooks) + UDP(3 hooks) + L7(2 hooks)")

	// ── ⑨ 定时任务 ────────────────────────────────────────

	// BPS/PPS 速率计算
	rateTick := time.NewTicker(cfg.StatsWindowDuration())
	defer rateTick.Stop()
	go func() {
		for range rateTick.C {
			tcpCollector.CalculateRates()
			udpCollector.CalculateRates()
		}
	}()

	// TCP Flow 周期 Prometheus flush + ClickHouse 中间快照
	// Flush():         更新 Prometheus 指标快照（活跃流状态）
	// FlushSnapshot(): 将活跃流当前状态写入 l4_flow_log（对齐 DeepFlow interval flush）
	flushTick := time.NewTicker(cfg.StatsWindowDuration())
	defer flushTick.Stop()
	go func() {
		for range flushTick.C {
			tcpCache.Flush()
			tcpCache.FlushSnapshot()
		}
	}()

	// TCP Flow GC（TTL 超时清理 → l4_flow_log）
	tcpGCTick := time.NewTicker(cfg.ConnectionGCDuration())
	defer tcpGCTick.Stop()
	go func() {
		for range tcpGCTick.C {
			if n := tcpCache.RunGC(); n > 0 {
				log.WithField("evicted", n).Debug("TCP flow GC")
			}
		}
	}()

	// UDP Flow GC（idle > 2min → l4_flow_log，每 30s 扫描）
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
			log.WithField("addr", addr).Info("pprof server")
			_ = http.ListenAndServe(addr, nil)
		}()
	}

	// ── ⑩ HTTP 服务 ───────────────────────────────────────
	mux := http.NewServeMux()
	mux.Handle(cfg.HTTP.MetricsPath, promhttp.Handler())
	mux.HandleFunc(cfg.HTTP.HealthPath, healthHandler)
	mux.HandleFunc("/debug/cloud_tags", debugCloudTagsHandler(metaProvider))
	mux.HandleFunc("/", indexHandler(cfg))

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

	// ── 优雅退出 ──────────────────────────────────────────
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

// ── HTTP Handlers ─────────────────────────────────────────

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok","version":"%s","ts":%d}`, version, time.Now().Unix())
}

func debugCloudTagsHandler(meta cloudmeta.MetaProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ip := r.URL.Query().Get("ip"); ip != "" {
			tag := meta.GetTag(ip)
			if tag == nil {
				http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"pod":"%s","ns":"%s","svc":"%s","node":"%s","region":"%s","az":"%s"}`,
				tag.PodName, tag.PodNamespace, tag.ServiceName,
				tag.NodeName, tag.Region, tag.AZ)
			return
		}
		// dump all (K8s only)
		if k8s, ok := meta.(*cloudmeta.K8sMetaProvider); ok {
			tags := k8s.DumpTags()
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"count":%d}`, len(tags))
		} else {
			http.Error(w, `{"error":"noop provider"}`, http.StatusServiceUnavailable)
		}
	}
}

func indexHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>Observer v%s</title>
<meta charset="utf-8">
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',system-ui,sans-serif;background:#0a0f1e;color:#e2e8f0;min-height:100vh}
  .container{max-width:1000px;margin:0 auto;padding:40px 20px}
  h1{font-size:2rem;color:#38bdf8;margin-bottom:4px;letter-spacing:-.02em}
  .sub{color:#64748b;font-size:.9rem;margin-bottom:32px}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px}
  .card{background:#111827;border:1px solid #1f2d44;border-radius:12px;padding:20px}
  .card h3{font-size:.75rem;color:#6b7280;text-transform:uppercase;letter-spacing:.08em;margin-bottom:14px}
  .row{display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid #1f2d44;font-size:.85rem}
  .row:last-child{border:none}
  .val{color:#38bdf8;font-weight:600;font-variant-numeric:tabular-nums}
  .tag{display:inline-block;padding:2px 9px;border-radius:99px;font-size:.75rem;margin:2px}
  .green{background:#052e16;color:#4ade80;border:1px solid #14532d}
  .blue{background:#0c1a3e;color:#60a5fa;border:1px solid #1e3a8a}
  .violet{background:#1e1040;color:#a78bfa;border:1px solid #3730a3}
  .amber{background:#1c1000;color:#fbbf24;border:1px solid #78350f}
  a{color:#38bdf8;text-decoration:none}
  a:hover{text-decoration:underline}
  .section{margin-bottom:20px}
  .section h2{font-size:.85rem;color:#94a3b8;margin-bottom:10px;display:flex;align-items:center;gap:8px}
</style>
</head><body>
<div class="container">
  <h1>🔭 Observer v%s</h1>
  <p class="sub">eBPF Network Observability · DeepFlow Architecture · wazero + K8s Informer</p>

  <div class="grid">
    <div class="card">
      <h3>Endpoints</h3>
      <div class="row"><span>Prometheus Metrics</span><a class="val" href="%s">%s</a></div>
      <div class="row"><span>Health Check</span><a class="val" href="%s">%s</a></div>
      <div class="row"><span>Cloud Tags Debug</span><a class="val" href="/debug/cloud_tags">/debug/cloud_tags</a></div>
      <div class="row"><span>pprof</span><span class="val">/debug/pprof</span></div>
    </div>
    <div class="card">
      <h3>Components Status</h3>
      <div class="row"><span>ClickHouse Storage</span><span class="val">%v</span></div>
      <div class="row"><span>L7 Protocol Parsing</span><span class="val">%v</span></div>
      <div class="row"><span>WASM Plugins (wazero)</span><span class="val">%v</span></div>
      <div class="row"><span>K8s Cloud Meta (Informer)</span><span class="val">%v</span></div>
    </div>
  </div>

  <div class="card section">
    <h3>v6 Improvements</h3>
    <div class="row">
      <span>WASM Runtime</span>
      <span><del style="color:#6b7280">wasmtime-go (CGo+Rust)</del> → <span class="val">wazero (pure-Go, zero-CGo)</span></span>
    </div>
    <div class="row">
      <span>K8s Cloud Tags</span>
      <span><del style="color:#6b7280">Watch/List (manual)</del> → <span class="val">SharedInformerFactory + EventHandler</span></span>
    </div>
    <div class="row">
      <span>TCP Server Role</span>
      <span><del style="color:#6b7280">port heuristic</del> → <span class="val">inet_csk_accept kretprobe (100%% accurate)</span></span>
    </div>
    <div class="row">
      <span>TCP SRT Metric</span>
      <span><del style="color:#6b7280">not tracked</del> → <span class="val">request_rcv_ts → sendmsg delta (μs)</span></span>
    </div>
    <div class="row">
      <span>UDP Flow Model</span>
      <span><del style="color:#6b7280">per-packet</del> → <span class="val">full flow agg + FlowKey normalization + l4_flow_log</span></span>
    </div>
    <div class="row">
      <span>UDP Recv Size</span>
      <span><del style="color:#6b7280">buffer size (wrong)</del> → <span class="val">kretprobe actual bytes</span></span>
    </div>
  </div>

  <div class="card section">
    <h3>L4 Features (DeepFlow Aligned)</h3>
    <span class="tag green">TCP FLOW_CREATE/UPDATE/DESTROY</span>
    <span class="tag green">UDP Flow Aggregation</span>
    <span class="tag green">SYN RTT (3-segment)</span>
    <span class="tag green">RTT min/avg/max</span>
    <span class="tag green">SRT (Server Response Time)</span>
    <span class="tag green">Retrans + Zero-Window</span>
    <span class="tag green">Role: CLIENT/SERVER (accurate)</span>
    <span class="tag green">LRU Cache + TTL GC</span>
    <span class="tag green">FlowKey Normalization</span>
    <span class="tag green">l4_flow_log → ClickHouse</span>
  </div>

  <div class="card section">
    <h3>L7 + Cloud Features</h3>
    <span class="tag blue">HTTP/1.1</span>
    <span class="tag blue">MySQL Protocol</span>
    <span class="tag blue">Redis RESP</span>
    <span class="tag blue">DNS RFC1035</span>
    <span class="tag violet">wazero WASM Extension</span>
    <span class="tag violet">Zero-CGo Build</span>
    <span class="tag amber">K8s Pod/Svc/Node Informer</span>
    <span class="tag amber">Pod IP → CloudTag O(1)</span>
    <span class="tag amber">Region/AZ Topology</span>
    <span class="tag amber">l7_flow_log → ClickHouse</span>
  </div>
</div>
</body></html>`,
			version, version,
			cfg.HTTP.MetricsPath, cfg.HTTP.MetricsPath,
			cfg.HTTP.HealthPath, cfg.HTTP.HealthPath,
			cfg.ClickHouse.Enabled, cfg.L7.Enabled, cfg.WASM.Enabled, cfg.CloudMeta.Enabled)
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
