// pkg/ebpf/fd_sock_manager.go — FD→Socket 映射管理与 Go TLS uprobe 加载
//
// 职责：
//   1. 加载 fd_sock_tracer.o，维护 pid+fd → 四元组的内核态 Map
//   2. 加载 go_tls_tracer.o，对系统中所有 Go 二进制动态挂载 crypto/tls uprobe
//   3. 提供 LookupSockTuple(pid, sport) 供 TLS 事件循环补全四元组
//
// 四元组补全优先级：
//   L1 (最快): BPF pid_fd_sock_map（内核态，O(1)，此文件维护）
//   L2 (慢):   /proc/net/tcp 扫描（原有兜底，已在 utils.go 实现）

package ebpf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	log "github.com/sirupsen/logrus"
)

// SockTuple 四元组（从 pid_fd_sock_map 读出）
type SockTuple struct {
	SAddr uint32
	DAddr uint32
	SPort uint16
	DPort uint16
	Proto uint8
}

// fdSockObjects 持有 fd_sock_tracer 的关键 Map
type fdSockObjects struct {
	PidFdSockMap *ebpf.Map // pid+fd → SockTuple
}

// goTLSObjects 持有 go_tls_tracer 的 ringbuf
type goTLSObjects struct {
	GoTLSEvents *ebpf.Map
}

// loadFdSockPrograms 加载 fd_sock_tracer.o 并挂载 tracepoint/kprobe
func (m *Manager) loadFdSockPrograms() error {
	objPath := fmt.Sprintf("%s/fd_sock_tracer.o", m.opts.BPFObjDir)
	if _, err := os.Stat(objPath); err != nil {
		log.WithField("path", objPath).Debug("fd_sock_tracer.o not found, FD→Socket map disabled")
		return nil
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("load fd_sock collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("new fd_sock collection: %w", err)
	}
	defer coll.Close()

	pidFdMap := coll.Maps["pid_fd_sock_map"]
	if pidFdMap == nil {
		return fmt.Errorf("pid_fd_sock_map not found")
	}

	m.fdSockObjs = &fdSockObjects{PidFdSockMap: pidFdMap}

	// tracepoint hooks
	tpHooks := []struct{ prog, category, name string }{
		{"tp__sys_enter_connect", "syscalls", "sys_enter_connect"},
		{"tp__sys_exit_accept4", "syscalls", "sys_exit_accept4"},
		{"tp__sys_enter_accept4", "syscalls", "sys_enter_accept4"},
		{"tp__sys_enter_close", "syscalls", "sys_enter_close"},
	}
	for _, h := range tpHooks {
		prog := coll.Programs[h.prog]
		if prog == nil {
			log.WithField("prog", h.prog).Debug("fd_sock tracepoint program not found")
			continue
		}
		tp, err := link.Tracepoint(h.category, h.name, prog, nil)
		if err != nil {
			log.WithFields(log.Fields{"prog": h.prog, "tp": h.name}).
				WithError(err).Warn("Failed to attach fd_sock tracepoint")
			continue
		}
		m.links = append(m.links, tp)
		log.WithField("tp", h.name).Debug("fd_sock tracepoint attached")
	}

	// kretprobe/tcp_set_state (fd 四元组写入)
	if prog := coll.Programs["kprobe__tcp_set_state_fd"]; prog != nil {
		kp, err := link.Kprobe("tcp_set_state", prog, nil)
		if err != nil {
			log.WithError(err).Warn("Failed to attach kprobe/tcp_set_state for fd_sock")
		} else {
			m.links = append(m.links, kp)
		}
	}

	log.Info("FD→Socket BPF map loaded, kernel-side tuple lookup enabled")
	return nil
}

// LookupSockTuple 通过 pid+sport 在内核态 Map 中查询四元组（L1 快路径）
// 若未找到返回 nil，调用方应降级到 /proc/net/tcp。
func (m *Manager) LookupSockTuple(pid uint32, sport uint16) *SockTuple {
	if m.fdSockObjs == nil || m.fdSockObjs.PidFdSockMap == nil {
		return nil
	}

	type pidFdKey struct {
		PID uint32
		FD  uint32
	}
	key := pidFdKey{PID: pid, FD: uint32(sport)} // 以 sport 作为索引键

	type sockTupleRaw struct {
		SAddr uint32
		DAddr uint32
		SPort uint16
		DPort uint16
		Proto uint8
		_     [3]byte
	}
	var val sockTupleRaw
	if err := m.fdSockObjs.PidFdSockMap.Lookup(key, &val); err != nil {
		return nil
	}
	if val.SAddr == 0 && val.DAddr == 0 {
		return nil
	}
	return &SockTuple{
		SAddr: val.SAddr,
		DAddr: val.DAddr,
		SPort: val.SPort,
		DPort: val.DPort,
		Proto: val.Proto,
	}
}

// ── Go TLS uprobe ─────────────────────────────────────────

// goSymbols 需要 uprobe 的 Go 运行时符号
var goTLSSymbols = []struct {
	symbol    string
	entryProg string
	retProg   string
}{
	{
		"crypto/tls.(*Conn).Write",
		"uprobe__go_tls_write",
		"uretprobe__go_tls_write",
	},
	{
		"crypto/tls.(*Conn).Read",
		"uprobe__go_tls_read",
		"uretprobe__go_tls_read",
	},
}

// findGoBinaries 返回系统中所有 Go 编译的二进制路径。
// 策略：扫描 /proc/*/exe 并通过读取 ELF Note 段或特征字符串判断是否为 Go 二进制。
// 限制最多 64 个二进制，避免在服务器上过度挂载。
func findGoBinaries() []string {
	var bins []string
	seen := make(map[string]bool)

	procDirs, _ := filepath.Glob("/proc/[0-9]*/exe")
	for _, exeLink := range procDirs {
		target, err := os.Readlink(exeLink)
		if err != nil || seen[target] {
			continue
		}
		if isGoBinary(target) {
			bins = append(bins, target)
			seen[target] = true
		}
		if len(bins) >= 64 {
			break
		}
	}
	return bins
}

// isGoBinary 通过检查文件头中的 Go build ID 段判断是否为 Go 二进制
func isGoBinary(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	// 读取前 4KB，查找 Go build ID 特征字符串
	buf := make([]byte, 4096)
	n, _ := f.Read(buf)
	if n < 4 {
		return false
	}

	// ELF magic check
	if buf[0] != 0x7f || buf[1] != 'E' || buf[2] != 'L' || buf[3] != 'F' {
		return false
	}

	// Go 二进制通常包含 "Go build ID:" 字符串或 "go1." 版本标记
	content := string(buf[:n])
	return strings.Contains(content, "go1.") ||
		strings.Contains(content, "Go build ID")
}

// loadGoTLSPrograms 加载 go_tls_tracer.o 并对所有已知 Go 二进制挂载 uprobe
func (m *Manager) loadGoTLSPrograms() error {
	objPath := fmt.Sprintf("%s/go_tls_tracer.o", m.opts.BPFObjDir)
	if _, err := os.Stat(objPath); err != nil {
		log.WithField("path", objPath).Debug("go_tls_tracer.o not found, Go TLS uprobe disabled")
		return nil
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("load Go TLS collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("new Go TLS collection: %w", err)
	}
	defer coll.Close()

	goTLSEvents := coll.Maps["go_tls_events"]
	if goTLSEvents == nil {
		return fmt.Errorf("go_tls_events map not found")
	}
	m.goTLSObjs = &goTLSObjects{GoTLSEvents: goTLSEvents}

	// 发现 Go 二进制并挂载 uprobe
	goBins := findGoBinaries()
	if len(goBins) == 0 {
		log.Debug("No Go binaries found, Go TLS uprobe skipped")
		return nil
	}

	attachedBins := 0
	attachedSymbols := 0

	for _, binPath := range goBins {
		ex, err := link.OpenExecutable(binPath)
		if err != nil {
			log.WithField("bin", binPath).WithError(err).Debug("Cannot open Go binary for uprobe")
			continue
		}

		binAttached := 0
		for _, sym := range goTLSSymbols {
			entryProg := coll.Programs[sym.entryProg]
			retProg := coll.Programs[sym.retProg]
			if entryProg == nil || retProg == nil {
				continue
			}

			entryLink, err := ex.Uprobe(sym.symbol, entryProg, nil)
			if err != nil {
				// Go binary 可能未使用 crypto/tls（纯 grpc 或自定义 TLS），静默跳过
				continue
			}
			m.links = append(m.links, entryLink)

			retLink, err := ex.Uretprobe(sym.symbol, retProg, nil)
			if err != nil {
				log.WithFields(log.Fields{"bin": binPath, "sym": sym.symbol}).
					WithError(err).Debug("Go TLS uretprobe failed")
			} else {
				m.links = append(m.links, retLink)
			}
			binAttached++
			attachedSymbols++
		}

		if binAttached > 0 {
			attachedBins++
			log.WithFields(log.Fields{
				"bin":     binPath,
				"symbols": binAttached,
			}).Debug("Go TLS uprobe attached")
		}
	}

	if attachedBins == 0 {
		log.Debug("Go TLS uprobe: no symbols attached (Go binaries may not use crypto/tls)")
		return nil
	}

	rd, err := ringbuf.NewReader(goTLSEvents)
	if err != nil {
		return fmt.Errorf("new ringbuf reader for go_tls_events: %w", err)
	}
	m.goTLSRing = rd

	// 启动 Go TLS 的增量发现协程（每 60s 扫描新进程）
	go m.goTLSDiscoveryLoop(coll, objPath)

	log.WithFields(log.Fields{
		"binaries": attachedBins,
		"symbols":  attachedSymbols,
	}).Info("Go TLS uprobes loaded")
	return nil
}

// goTLSDiscoveryLoop 定期扫描新启动的 Go 进程并附加 uprobe
// Go 进程的短生命周期要求持续发现（类似 DeepFlow 的进程监听机制）
func (m *Manager) goTLSDiscoveryLoop(coll *ebpf.Collection, objPath string) {
	seen := make(map[string]bool)
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		m.mu.Lock()
		running := m.running
		m.mu.Unlock()
		if !running {
			return
		}

		goBins := findGoBinaries()
		for _, binPath := range goBins {
			if seen[binPath] {
				continue
			}
			seen[binPath] = true

			ex, err := link.OpenExecutable(binPath)
			if err != nil {
				continue
			}
			for _, sym := range goTLSSymbols {
				entryProg := coll.Programs[sym.entryProg]
				retProg := coll.Programs[sym.retProg]
				if entryProg == nil || retProg == nil {
					continue
				}
				if el, err := ex.Uprobe(sym.symbol, entryProg, nil); err == nil {
					m.mu.Lock()
					m.links = append(m.links, el)
					m.mu.Unlock()
				}
				if rl, err := ex.Uretprobe(sym.symbol, retProg, nil); err == nil {
					m.mu.Lock()
					m.links = append(m.links, rl)
					m.mu.Unlock()
				}
			}
			log.WithField("bin", binPath).Debug("Go TLS uprobe attached to new binary")
		}
	}
}
