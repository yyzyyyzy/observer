package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"

	"observer/pkg/collector"
	"observer/pkg/ebpf"
)

var (
	tcpEnabled    = flag.Bool("tcp", true, "Enable TCP tracing")
	udpEnabled    = flag.Bool("udp", true, "Enable UDP tracing")
	tcInterface   = flag.String("tc-interface", "", "Network interface for TC hooks (e.g., eth0)")
	metricsPort   = flag.Int("metrics-port", 9090, "Port for Prometheus metrics")
	logLevel      = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	showStats     = flag.Bool("stats", false, "Show statistics periodically")
	statsInterval = flag.Duration("stats-interval", 10*time.Second, "Statistics display interval")
)

func main() {
	flag.Parse()

	level, err := log.ParseLevel(*logLevel)
	if err != nil {
		log.Fatalf("Invalid log level: %v", err)
	}
	log.SetLevel(level)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})

	if os.Geteuid() != 0 {
		log.Fatal("This program must be run as root")
	}

	log.Info("Starting Network Observer Agent...")
	log.Infof("TCP tracing: %v", *tcpEnabled)
	log.Infof("UDP tracing: %v", *udpEnabled)
	if *tcInterface != "" {
		log.Infof("TC interface: %s", *tcInterface)
	}

	dispatcher := collector.NewEventDispatcher()

	manager, err := ebpf.NewManager(dispatcher)
	if err != nil {
		log.Fatalf("Failed to create eBPF manager: %v", err)
	}

	if err := manager.Start(*tcpEnabled, *udpEnabled, *tcInterface); err != nil {
		log.Fatalf("Failed to start eBPF manager: %v", err)
	}

	go startMetricsServer(*metricsPort)

	if *showStats {
		go displayStats(dispatcher, *statsInterval)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	log.Info("Network Observer Agent started successfully. Press Ctrl+C to exit.")

	select {
	case <-sigCh:
		log.Info("Received shutdown signal")
	case <-ctx.Done():
		log.Info("Context cancelled")
	}

	log.Info("Shutting down...")
	if err := manager.Stop(); err != nil {
		log.Errorf("Error during shutdown: %v", err)
	}

	log.Info("Network Observer Agent stopped")
}

func startMetricsServer(port int) {
	http.Handle("/metrics", promhttp.Handler())

	addr := fmt.Sprintf(":%d", port)
	log.Infof("Starting metrics server on %s", addr)

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Failed to start metrics server: %v", err)
	}
}

func displayStats(dispatcher *collector.EventDispatcher, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		log.Info("=== Network Observer Statistics ===")

		tcpConnections := dispatcher.GetTCPCollector().GetActiveConnections()
		log.Infof("Active TCP connections: %d", len(tcpConnections))

		if len(tcpConnections) > 0 {
			log.Info("Recent TCP connections:")
			count := 0
			for _, conn := range tcpConnections {
				if count >= 5 {
					break
				}
				log.Infof("  %s:%d -> %s:%d (%s) [%s, PID: %d]",
					conn.SrcIP, conn.SrcPort, conn.DstIP, conn.DstPort,
					conn.Direction, conn.ProcessName, conn.PID)
				count++
			}
		}

		udpStats := dispatcher.GetUDPCollector().GetStats()
		log.Infof("UDP packets: %d (Sent: %d bytes, Recv: %d bytes)",
			udpStats["total_packets"],
			udpStats["bytes_sent"],
			udpStats["bytes_recv"])

		tcStats := dispatcher.GetTCCollector().GetStats()
		log.Infof("TC packets: %d (Ingress: %d, Egress: %d)",
			tcStats["total_packets"],
			tcStats["ingress_packets"],
			tcStats["egress_packets"])
		log.Infof("TC bytes: Ingress: %d, Egress: %d",
			tcStats["ingress_bytes"],
			tcStats["egress_bytes"])

		log.Info("===================================")
	}
}
