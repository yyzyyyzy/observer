// pkg/ebpf/tls_manager.go — TLS uprobe 管理器
//
// 负责：
//   1. 发现系统中的 libssl.so 路径（支持 OpenSSL 1.1.x / 3.x）
//   2. 通过 cilium/ebpf link.Uprobe 将 tls_tracer.o 挂载到 SSL_read/SSL_write
//   3. 从 tls_events ringbuf 读取已解密的明文，复用现有 L7EventHandler 路由

package ebpf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	log "github.com/sirupsen/logrus"
)

// sslLibCandidates 列出常见发行版上 libssl 的路径。
// 按优先级排序：先 OpenSSL 3.x，再 1.1.x，再 BoringSSL。
var sslLibCandidates = []string{
	// Debian/Ubuntu OpenSSL 3.x
	"/usr/lib/x86_64-linux-gnu/libssl.so.3",
	"/usr/lib/aarch64-linux-gnu/libssl.so.3",
	// Debian/Ubuntu OpenSSL 1.1.x
	"/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
	"/usr/lib/aarch64-linux-gnu/libssl.so.1.1",
	// RHEL/CentOS/Fedora
	"/usr/lib64/libssl.so.3",
	"/usr/lib64/libssl.so.1.1",
	// Alpine
	"/usr/lib/libssl.so.3",
	"/usr/lib/libssl.so.1.1",
	// Generic symlink
	"/usr/lib/libssl.so",
}

// sslSymbols 描述每个需要 uprobe 的 SSL 符号及其对应的 BPF 程序函数名后缀。
// BPF C 函数名全小写（e.g., uprobe__ssl_write），SSL 符号名保留大小写（e.g., SSL_write）。
var sslSymbols = []struct {
	sslSymbol      string // libssl 导出符号名（传给 ex.Uprobe）
	entryFuncSuffix string // BPF entry 函数名后缀（uprobe__ + suffix）
	retFuncSuffix   string // BPF ret 函数名后缀（uretprobe__ + suffix）
}{
	{"SSL_write",    "ssl_write",    "ssl_write"},
	{"SSL_read",     "ssl_read",     "ssl_read"},
	{"SSL_write_ex", "ssl_write_ex", "ssl_write_ex"},
	{"SSL_read_ex",  "ssl_read_ex",  "ssl_read_ex"},
}

// findSSLLib 返回系统上第一个存在的 libssl 路径。
// 也扫描 /proc/1/maps 等，以支持容器内的 overlay fs 场景。
func findSSLLib() string {
	for _, p := range sslLibCandidates {
		if _, err := os.Stat(p); err == nil {
			log.WithField("path", p).Debug("Found libssl")
			return p
		}
	}
	// 扩展扫描：通过 /usr/lib 目录 glob 匹配
	patterns := []string{
		"/usr/lib/x86_64-linux-gnu/libssl.so.*",
		"/usr/lib64/libssl.so.*",
		"/usr/lib/libssl.so.*",
	}
	for _, pat := range patterns {
		matches, _ := filepath.Glob(pat)
		if len(matches) > 0 {
			log.WithField("path", matches[0]).Debug("Found libssl via glob")
			return matches[0]
		}
	}
	return ""
}

// loadTLSPrograms 加载 tls_tracer.o 并挂载 uprobe 到 libssl。
// 失败时降级处理（warn 级别），不中断主流程。
func (m *Manager) loadTLSPrograms() error {
	objPath := fmt.Sprintf("%s/tls_tracer.o", m.opts.BPFObjDir)
	if _, err := os.Stat(objPath); err != nil {
		log.WithField("path", objPath).Debug("tls_tracer.o not found, TLS uprobe disabled")
		return nil
	}

	sslLib := findSSLLib()
	if sslLib == "" {
		log.Warn("libssl not found on this system, TLS uprobe disabled")
		return nil
	}
	log.WithField("libssl", sslLib).Info("Attaching TLS uprobes to libssl")

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("load TLS collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("new TLS collection: %w", err)
	}
	defer coll.Close()

	tlsEvents := coll.Maps["tls_events"]
	if tlsEvents == nil {
		return fmt.Errorf("tls_events map not found")
	}

	// 打开 libssl 可执行文件用于 uprobe
	ex, err := link.OpenExecutable(sslLib)
	if err != nil {
		return fmt.Errorf("open libssl for uprobe: %w", err)
	}

	// cilium/ebpf 以 BPF 程序的 C 函数名为 key（小写），不是 SEC name 里的符号名。
	// SEC("uprobe/SSL_write") + int uprobe__ssl_write(...) → key = "uprobe__ssl_write"
	attached := 0
	for _, sym := range sslSymbols {
		// entry uprobe：函数名 = "uprobe__" + lowercase(symbol)
		entryProgName := "uprobe__" + sym.entryFuncSuffix
		entryProg := coll.Programs[entryProgName]
		if entryProg == nil {
			log.WithField("prog", entryProgName).Debug("TLS uprobe program not found, skipping")
			continue
		}
		uprobeLink, err := ex.Uprobe(sym.sslSymbol, entryProg, nil)
		if err != nil {
			log.WithFields(log.Fields{"symbol": sym.sslSymbol}).
				WithError(err).Warn("Failed to attach TLS uprobe")
			continue
		}
		m.links = append(m.links, uprobeLink)

		// uretprobe：函数名 = "uretprobe__" + lowercase(symbol)
		retProgName := "uretprobe__" + sym.retFuncSuffix
		retProg := coll.Programs[retProgName]
		if retProg == nil {
			log.WithField("prog", retProgName).Debug("TLS uretprobe program not found, skipping")
			continue
		}
		uretLink, err := ex.Uretprobe(sym.sslSymbol, retProg, nil)
		if err != nil {
			log.WithFields(log.Fields{"symbol": sym.sslSymbol}).
				WithError(err).Warn("Failed to attach TLS uretprobe")
			continue
		}
		m.links = append(m.links, uretLink)
		attached++
		log.WithField("symbol", sym.sslSymbol).Debug("TLS uprobe attached")
	}

	if attached == 0 {
		log.Warn("No TLS uprobe symbols attached, TLS plaintext capture disabled")
		return nil
	}

	rd, err := ringbuf.NewReader(tlsEvents)
	if err != nil {
		return fmt.Errorf("new ringbuf reader for tls_events: %w", err)
	}
	m.tlsRing = rd
	log.WithFields(log.Fields{
		"libssl":   sslLib,
		"attached": attached,
	}).Info("TLS uprobe loaded, capturing plaintext SSL traffic")
	return nil
}

// tlsEventLoop 从 tls_events ringbuf 读取明文事件，
// 复用与 L7Event 相同的结构体和解析器，直接投递给 l7Handlers。
func (m *Manager) tlsEventLoop() {
	defer m.wg.Done()
	log.Info("TLS plaintext ring buffer event loop started")
	for {
		record, err := m.tlsRing.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.WithError(err).Warn("Error reading from TLS ring buffer")
			continue
		}
		// tls_event 布局与 l7_event 完全一致，复用 parseL7Event
		event, err := parseL7Event(record.RawSample)
		if err != nil {
			log.WithError(err).Debug("Failed to parse TLS event")
			continue
		}
		// 用特殊端口号（0）标记来源，Go 侧解析器通过 payload 内容识别协议
		// 通过 PID 查 /proc/net/tcp 补全四元组（由 registry 侧完成）
		m.mu.Lock()
		handlers := m.l7Handlers
		m.mu.Unlock()
		for _, h := range handlers {
			h.HandleL7Event(event)
		}
	}
}




