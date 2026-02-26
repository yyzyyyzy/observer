// pkg/ebpf/manager.go
// eBPF 程序加载、kprobe 挂载、TC 分类器挂载、ring buffer 事件循环
package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// ── Handler interfaces ────────────────────────────────────

type TCPEventHandler interface {
	HandleTCPEvent(event *TCPEvent)
}

type UDPEventHandler interface {
	HandleUDPEvent(event *UDPFlowEvent)
}

type TCPacketHandler interface {
	HandleTCPacket(packet *TCPacket)
}

// L7EventHandler 处理 L7 载荷事件
type L7EventHandler interface {
	HandleL7Event(event *L7Event)
}

// ── ManagerOptions ────────────────────────────────────────

type ManagerOptions struct {
	RingBufSize  int
	MaxFlows     int
	BPFObjDir    string
	TCInterfaces []string // TC 监听网络接口列表（对齐 DeepFlow tap_interface_regex）
}

var DefaultManagerOptions = ManagerOptions{
	RingBufSize: 256 * 1024,
	MaxFlows:    10240,
	BPFObjDir:   "./bpf",
}

// ── 内部 BPF 对象持有者 ───────────────────────────────────

type tcpObjects struct {
	FlowTrackerMap *ebpf.Map
	TcpEvents      *ebpf.Map
	StatsMap       *ebpf.Map
}

type udpObjects struct {
	UdpFlowMap  *ebpf.Map
	UdpEvents   *ebpf.Map
	RecvmsgArgs *ebpf.Map
}

// tcAttach 记录已挂载的 TC classifier（用于 Close 时清理）
type tcAttach struct {
	ifIndex   int
	ifName    string
	ingressFd int // qdisc/filter fd，-1 表示未挂载
	egressFd  int
}

// ── Manager ───────────────────────────────────────────────

type Manager struct {
	opts ManagerOptions

	tcpObjs *tcpObjects
	udpObjs *udpObjects

	tcpRing *ringbuf.Reader
	udpRing *ringbuf.Reader
	l7Ring  *ringbuf.Reader
	tcRing  *ringbuf.Reader

	links     []link.Link
	tcAttachs []tcAttach // TC classifier cleanup

	tcpHandlers   []TCPEventHandler
	udpHandlers   []UDPEventHandler
	tcpktHandlers []TCPacketHandler
	l7Handlers    []L7EventHandler

	mu      sync.Mutex
	running bool
	wg      sync.WaitGroup
}

func NewManager(opts ManagerOptions) *Manager {
	if opts.RingBufSize == 0 {
		opts.RingBufSize = DefaultManagerOptions.RingBufSize
	}
	if opts.MaxFlows == 0 {
		opts.MaxFlows = DefaultManagerOptions.MaxFlows
	}
	if opts.BPFObjDir == "" {
		opts.BPFObjDir = DefaultManagerOptions.BPFObjDir
	}
	return &Manager{opts: opts}
}

func (m *Manager) RegisterTCPHandler(h TCPEventHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tcpHandlers = append(m.tcpHandlers, h)
}

func (m *Manager) RegisterUDPHandler(h UDPEventHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.udpHandlers = append(m.udpHandlers, h)
}

func (m *Manager) RegisterTCPacketHandler(h TCPacketHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tcpktHandlers = append(m.tcpktHandlers, h)
}

func (m *Manager) RegisterL7Handler(h L7EventHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.l7Handlers = append(m.l7Handlers, h)
}

// Start 加载 eBPF 程序、挂载 kprobe/TC、启动事件循环
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return errors.New("manager already running")
	}

	// 内核 < 5.11 需要解除 RLIMIT_MEMLOCK
	if err := rlimit.RemoveMemlock(); err != nil {
		log.WithError(err).Warn("Failed to remove memlock limit")
	}

	if err := m.loadTCPPrograms(); err != nil {
		return fmt.Errorf("load TCP programs: %w", err)
	}

	if err := m.loadUDPPrograms(); err != nil {
		m.cleanup()
		return fmt.Errorf("load UDP programs: %w", err)
	}

	// L7 程序（可选，BPF 文件不存在时静默跳过）
	if err := m.loadL7Programs(); err != nil {
		log.WithError(err).Warn("L7 BPF load failed, L7 capture disabled")
	}

	// TC 程序（可选，依赖配置的接口列表）
	if err := m.loadTCPrograms(); err != nil {
		log.WithError(err).Warn("TC BPF load failed, TC capture disabled")
	}

	m.running = true
	m.wg.Add(1)
	go m.tcpEventLoop()
	m.wg.Add(1)
	go m.udpEventLoop()
	if m.l7Ring != nil {
		m.wg.Add(1)
		go m.l7EventLoop()
	}
	if m.tcRing != nil {
		m.wg.Add(1)
		go m.tcEventLoop()
	}

	log.Info("eBPF manager started")
	return nil
}

// Stop 优雅关闭
func (m *Manager) Stop() {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}
	m.running = false

	if m.tcpRing != nil {
		m.tcpRing.Close()
	}
	if m.udpRing != nil {
		m.udpRing.Close()
	}
	if m.l7Ring != nil {
		m.l7Ring.Close()
	}
	if m.tcRing != nil {
		m.tcRing.Close()
	}
	m.mu.Unlock()

	m.wg.Wait()
	m.cleanup()
	log.Info("eBPF manager stopped")
}

// ── Load helpers ──────────────────────────────────────────

func (m *Manager) loadTCPPrograms() error {
	objPath := fmt.Sprintf("%s/tcp_tracer.o", m.opts.BPFObjDir)
	if _, err := os.Stat(objPath); err != nil {
		return fmt.Errorf("TCP BPF object not found at %s: %w", objPath, err)
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("load collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("new collection: %w", err)
	}

	m.tcpObjs = &tcpObjects{
		FlowTrackerMap: coll.Maps["flow_tracker_map"],
		TcpEvents:      coll.Maps["tcp_events"],
		StatsMap:       coll.Maps["stats_map"],
	}

	kprobeHooks := []struct {
		prog string
		fn   string
	}{
		{"kprobe__tcp_connect", "tcp_connect"},
		{"kprobe__inet_csk_accept", "inet_csk_accept"},
		{"kprobe__tcp_rcv_state_process", "tcp_rcv_state_process"},
		{"kprobe__tcp_sendmsg", "tcp_sendmsg"},
		{"kprobe__tcp_recvmsg", "tcp_recvmsg"},
		{"kprobe__tcp_ack", "tcp_ack"},
		{"kprobe__tcp_retransmit_skb", "tcp_retransmit_skb"},
		{"kprobe__tcp_send_active_reset", "tcp_send_active_reset"},
		{"kprobe__tcp_set_state", "tcp_set_state"},
	}
	for _, h := range kprobeHooks {
		prog := coll.Programs[h.prog]
		if prog == nil {
			log.WithField("prog", h.prog).Warn("TCP program not found in collection")
			continue
		}
		kp, err := link.Kprobe(h.fn, prog, nil)
		if err != nil {
			log.WithFields(log.Fields{"prog": h.prog, "fn": h.fn}).
				WithError(err).Warn("Failed to attach TCP kprobe")
			continue
		}
		m.links = append(m.links, kp)
		log.WithFields(log.Fields{"prog": h.prog, "fn": h.fn}).Debug("TCP kprobe attached")
	}

	kretprobeHooks := []struct {
		prog string
		fn   string
	}{
		{"kretprobe__inet_csk_accept", "inet_csk_accept"},
		{"kretprobe__tcp_recvmsg", "tcp_recvmsg"},
	}
	for _, h := range kretprobeHooks {
		prog := coll.Programs[h.prog]
		if prog == nil {
			log.WithField("prog", h.prog).Warn("TCP kretprobe program not found")
			continue
		}
		krp, err := link.Kretprobe(h.fn, prog, nil)
		if err != nil {
			log.WithFields(log.Fields{"prog": h.prog, "fn": h.fn}).
				WithError(err).Warn("Failed to attach TCP kretprobe")
			continue
		}
		m.links = append(m.links, krp)
		log.WithFields(log.Fields{"prog": h.prog, "fn": h.fn}).Debug("TCP kretprobe attached")
	}

	rd, err := ringbuf.NewReader(m.tcpObjs.TcpEvents)
	if err != nil {
		coll.Close()
		return fmt.Errorf("new ringbuf reader for tcp_events: %w", err)
	}
	m.tcpRing = rd
	coll.Close()
	return nil
}

func (m *Manager) loadUDPPrograms() error {
	objPath := fmt.Sprintf("%s/udp_tracer.o", m.opts.BPFObjDir)
	if _, err := os.Stat(objPath); err != nil {
		log.WithField("path", objPath).Warn("UDP BPF object not found, UDP monitoring disabled")
		return nil
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("load UDP collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("new UDP collection: %w", err)
	}

	m.udpObjs = &udpObjects{
		UdpFlowMap:  coll.Maps["udp_flow_map"],
		UdpEvents:   coll.Maps["udp_events"],
		RecvmsgArgs: coll.Maps["recvmsg_args"],
	}

	for _, h := range []struct {
		prog     string
		fn       string
		retprobe bool
	}{
		{"kprobe__udp_sendmsg", "udp_sendmsg", false},
		{"kprobe__udp_recvmsg", "udp_recvmsg", false},
		{"kretprobe__udp_recvmsg", "udp_recvmsg", true},
	} {
		prog := coll.Programs[h.prog]
		if prog == nil {
			continue
		}
		var kp link.Link
		var lerr error
		if h.retprobe {
			kp, lerr = link.Kretprobe(h.fn, prog, nil)
		} else {
			kp, lerr = link.Kprobe(h.fn, prog, nil)
		}
		if lerr != nil {
			log.WithField("fn", h.fn).WithError(lerr).Warn("Failed to attach UDP probe")
			continue
		}
		m.links = append(m.links, kp)
		log.WithFields(log.Fields{"prog": h.prog, "retprobe": h.retprobe}).Debug("UDP probe attached")
	}

	rd, err := ringbuf.NewReader(m.udpObjs.UdpEvents)
	if err != nil {
		coll.Close()
		return fmt.Errorf("new ringbuf reader for udp_events: %w", err)
	}
	m.udpRing = rd
	coll.Close()
	return nil
}

// loadL7Programs 加载 L7 载荷捕获程序（v8：挂 tcp_sendmsg/tcp_recvmsg）
func (m *Manager) loadL7Programs() error {
	objPath := fmt.Sprintf("%s/l7_tracer.o", m.opts.BPFObjDir)
	if _, err := os.Stat(objPath); err != nil {
		log.WithField("path", objPath).Debug("L7 BPF object not found, L7 capture disabled")
		return nil
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("load L7 collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("new L7 collection: %w", err)
	}

	l7Events := coll.Maps["l7_events"]
	if l7Events == nil {
		coll.Close()
		return fmt.Errorf("l7_events map not found")
	}

	// v8 修复：改为挂 tcp_sendmsg / tcp_recvmsg（直接从 sock* 获取五元组）
	// 之前挂 sys_write/sys_read 依赖 fd_to_sock 映射但从未填充，导致 l7_flow_log 为空
	hooks := []struct {
		prog     string
		fn       string
		retprobe bool
	}{
		{"kprobe__tcp_sendmsg_l7", "tcp_sendmsg", false},
		{"kprobe__tcp_recvmsg_l7", "tcp_recvmsg", false},
		{"kretprobe__tcp_recvmsg_l7", "tcp_recvmsg", true},
	}
	for _, h := range hooks {
		prog := coll.Programs[h.prog]
		if prog == nil {
			log.WithField("prog", h.prog).Warn("L7 program not found in collection")
			continue
		}
		var kp link.Link
		var lerr error
		if h.retprobe {
			kp, lerr = link.Kretprobe(h.fn, prog, nil)
		} else {
			kp, lerr = link.Kprobe(h.fn, prog, nil)
		}
		if lerr != nil {
			log.WithField("fn", h.fn).WithError(lerr).Warn("Failed to attach L7 probe")
			continue
		}
		m.links = append(m.links, kp)
		log.WithFields(log.Fields{"prog": h.prog, "fn": h.fn, "retprobe": h.retprobe}).Debug("L7 probe attached")
	}

	rd, err := ringbuf.NewReader(l7Events)
	if err != nil {
		coll.Close()
		return fmt.Errorf("new ringbuf reader for l7_events: %w", err)
	}
	m.l7Ring = rd
	coll.Close()
	log.Info("L7 eBPF programs loaded (tcp_sendmsg/tcp_recvmsg hooks)")
	return nil
}

// ── TC Program Loader（DeepFlow 对齐实现） ────────────────
//
// 设计对齐 DeepFlow tap_interface_regex：
//   1. 从配置列表遍历接口（ens33, eth0, docker0 等）
//   2. 为每个接口创建 clsact qdisc（无锁，仅用于 BPF 分类器）
//   3. 分别 attach ingress/egress BPF classifier
//   4. Stop 时清理所有 qdisc（自动移除 filters）
//
// 使用 golang.org/x/sys/unix 系统调用，不需要额外的 netlink 库。

const (
	// TC_H_MAJ_MASK / TC_H_MIN_MASK
	tcHandleRoot    = 0xFFFFFFFF // TC_H_ROOT
	tcHandleIngress = 0xFFFFFFF2 // TC_H_INGRESS
	tcHandleClsact  = 0xFFFFFFF4 // TC_H_CLSACT
	tcHandleMaj1    = 0x00010000
	tcHandleMin1    = 0x00000001
	tcPrioFilter    = 1
)

func (m *Manager) loadTCPrograms() error {
	objPath := fmt.Sprintf("%s/tc_tracer.o", m.opts.BPFObjDir)
	if _, err := os.Stat(objPath); err != nil {
		log.WithField("path", objPath).Debug("TC BPF object not found, TC capture disabled")
		return nil
	}

	if len(m.opts.TCInterfaces) == 0 {
		log.Debug("No TC interfaces configured, TC capture disabled")
		return nil
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("load TC collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("new TC collection: %w", err)
	}
	defer coll.Close()

	tcEvents := coll.Maps["tc_events"]
	if tcEvents == nil {
		return fmt.Errorf("tc_events map not found in tc_tracer.o")
	}

	ingressProg := coll.Programs["tc_ingress"]
	egressProg := coll.Programs["tc_egress"]

	if ingressProg == nil || egressProg == nil {
		return fmt.Errorf("tc_ingress or tc_egress program not found in tc_tracer.o")
	}

	// 为每个接口 attach TC classifier
	for _, ifName := range m.opts.TCInterfaces {
		iface, err := net.InterfaceByName(ifName)
		if err != nil {
			log.WithField("iface", ifName).WithError(err).Warn("TC: interface not found, skipping")
			continue
		}

		if err := m.attachTCClassifier(iface, ingressProg, egressProg); err != nil {
			log.WithField("iface", ifName).WithError(err).Warn("TC: attach classifier failed")
			continue
		}
		log.WithField("iface", ifName).Info("TC classifier attached (ingress+egress)")
	}

	if len(m.tcAttachs) == 0 {
		log.Warn("TC: no interfaces attached successfully, TC capture disabled")
		return nil
	}

	rd, err := ringbuf.NewReader(tcEvents)
	if err != nil {
		return fmt.Errorf("new ringbuf reader for tc_events: %w", err)
	}
	m.tcRing = rd
	log.WithField("interfaces", m.opts.TCInterfaces).Info("TC BPF programs loaded")
	return nil
}

// attachTCClassifier 在指定网口上挂载 ingress/egress BPF TC classifier。
//
// 步骤（对齐 DeepFlow tap_mode_local）：
//   1. 通过 netlink 创建 clsact qdisc（幂等：已存在则忽略）
//   2. ingress：添加 BPF filter 到 clsact ingress hook
//   3. egress：添加 BPF filter 到 clsact egress hook
//
// 使用原始 netlink socket + rtnetlink 消息，与 DeepFlow 实现相同。

func (m *Manager) attachTCClassifier(iface *net.Interface, ingress, egress *ebpf.Program) error {
	ifidx := iface.Index

	// Step 1: 创建 clsact qdisc
	if err := tcAddClsactQdisc(ifidx); err != nil {
		return fmt.Errorf("add clsact qdisc on %s: %w", iface.Name, err)
	}

	// Step 2: attach ingress BPF filter
	inFd := ingress.FD()
	if err := tcAddFilter(ifidx, inFd, true, iface.Name); err != nil {
		return fmt.Errorf("add ingress filter on %s: %w", iface.Name, err)
	}

	// Step 3: attach egress BPF filter
	outFd := egress.FD()
	if err := tcAddFilter(ifidx, outFd, false, iface.Name); err != nil {
		return fmt.Errorf("add egress filter on %s: %w", iface.Name, err)
	}

	m.tcAttachs = append(m.tcAttachs, tcAttach{
		ifIndex:   ifidx,
		ifName:    iface.Name,
		ingressFd: inFd,
		egressFd:  outFd,
	})
	return nil
}

// tcAddClsactQdisc 通过 rtnetlink 在接口上创建 clsact qdisc（幂等）。
// clsact 是专为 eBPF 设计的 qdisc，可同时 attach ingress/egress BPF 程序，
// 不影响正常流量调度（与 DeepFlow tc_local_mode 相同）。
func tcAddClsactQdisc(ifindex int) error {
	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}
	defer unix.Close(sock)

	if err := unix.Bind(sock, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink bind: %w", err)
	}

	// RTM_NEWQDISC: 添加 clsact qdisc
	// struct tcmsg
	type tcmsg struct {
		Family  uint8
		Pad1    uint8
		Pad2    uint16
		Ifindex int32
		Handle  uint32
		Parent  uint32
		Info    uint32
	}

	// "clsact" = [99,108,115,97,99,116,0,0,0,0,0] null-padded to 16 bytes
	kindBytes := make([]byte, 16)
	copy(kindBytes, "clsact\x00")

	// NLATTR: NLA_KIND = 1
	nlaKindLen := 4 + len(kindBytes) // nlattr hdr(4) + "clsact\0" padded
	nlaKind := make([]byte, nlaKindLen)
	*(*uint16)(unsafe.Pointer(&nlaKind[0])) = uint16(nlaKindLen)
	*(*uint16)(unsafe.Pointer(&nlaKind[2])) = uint16(1)
	copy(nlaKind[4:], kindBytes)

	tcMsg := tcmsg{
		Family:  unix.AF_UNSPEC,
		Ifindex: int32(ifindex),
		Handle:  uint32(tcHandleClsact),
		Parent:  tcHandleRoot,
	}

	// Build netlink message
	tcMsgBytes := (*[unsafe.Sizeof(tcMsg)]byte)(unsafe.Pointer(&tcMsg))[:]
	msgLen := unix.SizeofNlMsghdr + len(tcMsgBytes) + len(nlaKind)
	msg := make([]byte, msgLen)

	nlhdr := (*unix.NlMsghdr)(unsafe.Pointer(&msg[0]))
	nlhdr.Len = uint32(msgLen)
	nlhdr.Type = 36
	nlhdr.Flags = 1 | 0x400 | 0x200
	nlhdr.Seq = 1
	nlhdr.Pid = 0

	copy(msg[unix.SizeofNlMsghdr:], tcMsgBytes)
	copy(msg[unix.SizeofNlMsghdr+len(tcMsgBytes):], nlaKind)

	if _, err := unix.Write(sock, msg); err != nil {
		return fmt.Errorf("write netlink: %w", err)
	}

	// Read response
	resp := make([]byte, 4096)
	n, err := unix.Read(sock, resp)
	if err != nil {
		return fmt.Errorf("read netlink response: %w", err)
	}
	if n < unix.SizeofNlMsghdr {
		return fmt.Errorf("netlink response too short")
	}

	respHdr := (*unix.NlMsghdr)(unsafe.Pointer(&resp[0]))
	if respHdr.Type == 2 {
		errno := int32(binary.LittleEndian.Uint32(resp[unix.SizeofNlMsghdr:]))
		if errno != 0 && errno != -int32(unix.EEXIST) {
			return fmt.Errorf("rtnetlink error: %d", errno)
		}
		// EEXIST 意味着 clsact 已存在，属于正常情况
	}
	return nil
}

// tcAddFilter 通过 RTM_NEWTFILTER 挂载 BPF cls_bpf filter。
// 对齐 DeepFlow 的 tc filter add dev <iface> ingress bpf direct-action obj ...
func tcAddFilter(ifindex, bpfFd int, isIngress bool, ifName string) error {
	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}
	defer unix.Close(sock)

	if err := unix.Bind(sock, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink bind: %w", err)
	}

	type tcmsg struct {
		Family  uint8
		Pad1    uint8
		Pad2    uint16
		Ifindex int32
		Handle  uint32
		Parent  uint32
		Info    uint32
	}

	// parent: TC_H_CLSACT:TC_H_MIN_INGRESS or EGRESS
	maj := uint32(0xFFFFFFF4)
	parent := maj<<16 | uint32(0xFFF2) // clsact:ingress
	if !isIngress {
		parent = maj<<16 | uint32(0xFFF3) // clsact:egress
	}

	// BPF filter 使用 prio=1, protocol=ETH_P_ALL(0x0003)
	proto := uint16(0x0003) // ETH_P_ALL in big-endian (htons(0x0300)=0x0003)
	info := uint32(tcPrioFilter)<<16 | uint32(bpf_htons(proto))

	tcMsg := tcmsg{
		Family:  unix.AF_UNSPEC,
		Ifindex: int32(ifindex),
		Handle:  uint32(tcHandleMaj1 | tcHandleMin1),
		Parent:  parent,
		Info:    info,
	}

	// TCA_KIND = "bpf"
	kindStr := "bpf\x00"
	nlaKind := buildNlAttr(uint16(1), []byte(kindStr))

	// TCA_OPTIONS: 嵌套属性包含 BPF 程序 fd
	// TCA_BPF_FD    = 2
	// TCA_BPF_FLAGS = 4 (TCA_BPF_FLAG_ACT_DIRECT = 1)
	const (
		TCA_BPF_FD              = 2
		TCA_BPF_FLAGS           = 4
		TCA_BPF_FLAG_ACT_DIRECT = 1
	)

	fdBytes := uint32ToBytes(uint32(bpfFd))
	flagBytes := uint32ToBytes(uint32(TCA_BPF_FLAG_ACT_DIRECT))

	nlaFd := buildNlAttr(TCA_BPF_FD, fdBytes)
	nlaFlags := buildNlAttr(TCA_BPF_FLAGS, flagBytes)

	optData := append(nlaFd, nlaFlags...)
	// TCA_OPTIONS = 4, with NLA_F_NESTED
	nlaOpts := buildNlAttr(uint16(4)|0x8000, optData)

	tcMsgBytes := (*[unsafe.Sizeof(tcMsg)]byte)(unsafe.Pointer(&tcMsg))[:]
	payload := append(nlaKind, nlaOpts...)
	msgLen := unix.SizeofNlMsghdr + len(tcMsgBytes) + len(payload)
	msg := make([]byte, msgLen)

	nlhdr := (*unix.NlMsghdr)(unsafe.Pointer(&msg[0]))
	nlhdr.Len = uint32(msgLen)
	nlhdr.Type = 44
	nlhdr.Flags = 1 | 0x400 | 0x200
	nlhdr.Seq = 2
	nlhdr.Pid = 0

	copy(msg[unix.SizeofNlMsghdr:], tcMsgBytes)
	copy(msg[unix.SizeofNlMsghdr+len(tcMsgBytes):], payload)

	if _, err := unix.Write(sock, msg); err != nil {
		return fmt.Errorf("write netlink: %w", err)
	}

	resp := make([]byte, 4096)
	n, err := unix.Read(sock, resp)
	if err != nil {
		return fmt.Errorf("read netlink response: %w", err)
	}
	if n < unix.SizeofNlMsghdr {
		return fmt.Errorf("netlink response too short")
	}
	respHdr := (*unix.NlMsghdr)(unsafe.Pointer(&resp[0]))
	if respHdr.Type == 2 {
		errno := int32(binary.LittleEndian.Uint32(resp[unix.SizeofNlMsghdr:]))
		if errno != 0 && errno != -int32(unix.EEXIST) {
			dir := "ingress"
			if !isIngress {
				dir = "egress"
			}
			return fmt.Errorf("rtnetlink filter error on %s %s: errno=%d", ifName, dir, errno)
		}
	}
	return nil
}

// cleanupTCClassifiers 移除所有已挂载的 TC 分类器（通过删除 clsact qdisc）
func (m *Manager) cleanupTCClassifiers() {
	for _, att := range m.tcAttachs {
		if err := tcDelClsactQdisc(att.ifIndex); err != nil {
			log.WithField("iface", att.ifName).WithError(err).Warn("TC: failed to remove clsact qdisc")
		} else {
			log.WithField("iface", att.ifName).Debug("TC: clsact qdisc removed")
		}
	}
	m.tcAttachs = nil
}

func tcDelClsactQdisc(ifindex int) error {
	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(sock)
	if err := unix.Bind(sock, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}

	type tcmsg struct {
		Family  uint8
		Pad1    uint8
		Pad2    uint16
		Ifindex int32
		Handle  uint32
		Parent  uint32
		Info    uint32
	}
	tcMsg := tcmsg{
		Family:  unix.AF_UNSPEC,
		Ifindex: int32(ifindex),
		Handle:  uint32(tcHandleClsact),
		Parent:  tcHandleRoot,
	}
	tcMsgBytes := (*[unsafe.Sizeof(tcMsg)]byte)(unsafe.Pointer(&tcMsg))[:]
	msgLen := unix.SizeofNlMsghdr + len(tcMsgBytes)
	msg := make([]byte, msgLen)
	nlhdr := (*unix.NlMsghdr)(unsafe.Pointer(&msg[0]))
	nlhdr.Len = uint32(msgLen)
	nlhdr.Type = 37
	nlhdr.Flags = 1
	nlhdr.Seq = 3
	copy(msg[unix.SizeofNlMsghdr:], tcMsgBytes)
	_, err = unix.Write(sock, msg)
	return err
}

// ── rtnetlink 辅助 ────────────────────────────────────────

func buildNlAttr(typ uint16, data []byte) []byte {
	// nlattr: len(2) + type(2) + data + padding
	dataLen := 4 + len(data)
	padded := (dataLen + 3) &^ 3
	buf := make([]byte, padded)
	binary.LittleEndian.PutUint16(buf[0:], uint16(dataLen))
	binary.LittleEndian.PutUint16(buf[2:], typ)
	copy(buf[4:], data)
	return buf
}

func uint32ToBytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func bpf_htons(v uint16) uint16 {
	return (v>>8)&0xFF | (v<<8)&0xFF00
}

// ── Event loops ───────────────────────────────────────────

func (m *Manager) tcpEventLoop() {
	defer m.wg.Done()
	log.Info("TCP ring buffer event loop started")

	for {
		record, err := m.tcpRing.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Debug("TCP ring buffer closed, event loop exiting")
				return
			}
			log.WithError(err).Warn("Error reading from TCP ring buffer")
			continue
		}

		event, err := parseTCPEvent(record.RawSample)
		if err != nil {
			log.WithError(err).Debug("Failed to parse TCP event")
			continue
		}

		m.mu.Lock()
		handlers := m.tcpHandlers
		m.mu.Unlock()

		for _, h := range handlers {
			h.HandleTCPEvent(event)
		}
	}
}

func (m *Manager) udpEventLoop() {
	defer m.wg.Done()

	if m.udpRing == nil {
		log.Info("UDP monitoring disabled, event loop not started")
		return
	}
	log.Info("UDP ring buffer event loop started")

	for {
		record, err := m.udpRing.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Debug("UDP ring buffer closed, event loop exiting")
				return
			}
			log.WithError(err).Warn("Error reading from UDP ring buffer")
			continue
		}

		event, err := parseUDPEvent(record.RawSample)
		if err != nil {
			log.WithError(err).Debug("Failed to parse UDP event")
			continue
		}

		m.mu.Lock()
		handlers := m.udpHandlers
		m.mu.Unlock()

		for _, h := range handlers {
			h.HandleUDPEvent(event)
		}
	}
}

func (m *Manager) l7EventLoop() {
	defer m.wg.Done()
	log.Info("L7 ring buffer event loop started")

	for {
		record, err := m.l7Ring.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.WithError(err).Warn("Error reading from L7 ring buffer")
			continue
		}

		event, err := parseL7Event(record.RawSample)
		if err != nil {
			log.WithError(err).Debug("Failed to parse L7 event")
			continue
		}

		m.mu.Lock()
		handlers := m.l7Handlers
		m.mu.Unlock()

		for _, h := range handlers {
			h.HandleL7Event(event)
		}
	}
}

// tcEventLoop 处理 TC ring buffer 的包事件
func (m *Manager) tcEventLoop() {
	defer m.wg.Done()
	log.Info("TC ring buffer event loop started")

	for {
		record, err := m.tcRing.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.WithError(err).Warn("Error reading from TC ring buffer")
			continue
		}

		pkt, err := parseTCPacketEvent(record.RawSample)
		if err != nil {
			log.WithError(err).Debug("Failed to parse TC packet")
			continue
		}

		m.mu.Lock()
		handlers := m.tcpktHandlers
		m.mu.Unlock()

		for _, h := range handlers {
			h.HandleTCPacket(pkt)
		}
	}
}

// ── Cleanup ───────────────────────────────────────────────

func (m *Manager) cleanup() {
	// 先清理 TC classifiers（必须在关闭 ring buffer 之前）
	m.cleanupTCClassifiers()

	for _, l := range m.links {
		l.Close()
	}
	m.links = nil

	if m.tcpRing != nil {
		m.tcpRing.Close()
		m.tcpRing = nil
	}
	if m.udpRing != nil {
		m.udpRing.Close()
		m.udpRing = nil
	}
	if m.l7Ring != nil {
		m.l7Ring.Close()
		m.l7Ring = nil
	}
	if m.tcRing != nil {
		m.tcRing.Close()
		m.tcRing = nil
	}

	if m.tcpObjs != nil {
		if m.tcpObjs.FlowTrackerMap != nil {
			m.tcpObjs.FlowTrackerMap.Close()
		}
		if m.tcpObjs.TcpEvents != nil {
			m.tcpObjs.TcpEvents.Close()
		}
		if m.tcpObjs.StatsMap != nil {
			m.tcpObjs.StatsMap.Close()
		}
		m.tcpObjs = nil
	}
	if m.udpObjs != nil {
		if m.udpObjs.UdpFlowMap != nil {
			m.udpObjs.UdpFlowMap.Close()
		}
		if m.udpObjs.UdpEvents != nil {
			m.udpObjs.UdpEvents.Close()
		}
		if m.udpObjs.RecvmsgArgs != nil {
			m.udpObjs.RecvmsgArgs.Close()
		}
		m.udpObjs = nil
	}
}

// ── Deserializers ─────────────────────────────────────────

func parseTCPEvent(raw []byte) (*TCPEvent, error) {
	const size = 152
	if len(raw) < size {
		return nil, fmt.Errorf("TCP raw data too short: got %d, want %d", len(raw), size)
	}
	ev := &TCPEvent{}
	ev.TimestampNs = binary.LittleEndian.Uint64(raw[0:8])
	ev.PID = binary.LittleEndian.Uint32(raw[8:12])
	ev.TID = binary.LittleEndian.Uint32(raw[12:16])
	copy(ev.Comm[:], raw[16:32])
	ev.SAddr = binary.LittleEndian.Uint32(raw[32:36])
	ev.DAddr = binary.LittleEndian.Uint32(raw[36:40])
	ev.SPort = binary.LittleEndian.Uint16(raw[40:42])
	ev.DPort = binary.LittleEndian.Uint16(raw[42:44])
	ev.Protocol = raw[44]
	ev.Lifecycle = raw[45]
	ev.Direction = raw[46]
	ev.Role = raw[47]
	ev.SynRTT = binary.LittleEndian.Uint32(raw[48:52])
	ev.SynRTTClient = binary.LittleEndian.Uint32(raw[52:56])
	ev.SynRTTServer = binary.LittleEndian.Uint32(raw[56:60])
	ev.RTTMean = binary.LittleEndian.Uint32(raw[60:64])
	ev.RTTMax = binary.LittleEndian.Uint32(raw[64:68])
	ev.RTTMin = binary.LittleEndian.Uint32(raw[68:72])
	ev.SRTMean = binary.LittleEndian.Uint32(raw[72:76])
	ev.SRTMax = binary.LittleEndian.Uint32(raw[76:80])
	ev.RetransCount = binary.LittleEndian.Uint32(raw[80:84])
	ev.EventSubtype = raw[84]
	ev.DestroyReason = raw[85]
	ev.SynRetrans = raw[86]
	ev.RSTCount = raw[87]
	ev.RetransBytes = binary.LittleEndian.Uint64(raw[88:96])
	ev.ZeroWndCount = binary.LittleEndian.Uint32(raw[96:100])
	ev.ZeroWndDuration = binary.LittleEndian.Uint64(raw[104:112])
	ev.BytesSent = binary.LittleEndian.Uint64(raw[112:120])
	ev.BytesReceived = binary.LittleEndian.Uint64(raw[120:128])
	ev.PacketsSent = binary.LittleEndian.Uint64(raw[128:136])
	ev.PacketsReceived = binary.LittleEndian.Uint64(raw[136:144])
	ev.TimeoutFlag = raw[144]
	ev.TCPState = raw[145]
	ev.DurationUs = binary.LittleEndian.Uint32(raw[148:152])
	return ev, nil
}

func parseUDPEvent(raw []byte) (*UDPFlowEvent, error) {
	const size = 88
	if len(raw) < size {
		return nil, fmt.Errorf("UDP raw data too short: got %d, want %d", len(raw), size)
	}
	ev := &UDPFlowEvent{}
	ev.TimestampNs = binary.LittleEndian.Uint64(raw[0:8])
	ev.PID = binary.LittleEndian.Uint32(raw[8:12])
	ev.TID = binary.LittleEndian.Uint32(raw[12:16])
	copy(ev.Comm[:], raw[16:32])
	ev.SAddr = binary.LittleEndian.Uint32(raw[32:36])
	ev.DAddr = binary.LittleEndian.Uint32(raw[36:40])
	ev.SPort = binary.LittleEndian.Uint16(raw[40:42])
	ev.DPort = binary.LittleEndian.Uint16(raw[42:44])
	ev.Direction = raw[44]
	ev.Role = raw[45]
	ev.EventType = raw[46]
	ev.PacketSize = binary.LittleEndian.Uint32(raw[48:52])
	ev.TotalBytes = binary.LittleEndian.Uint64(raw[56:64])
	ev.BytesSent = binary.LittleEndian.Uint64(raw[64:72])
	ev.BytesRecv = binary.LittleEndian.Uint64(raw[72:80])
	ev.DurationNs = binary.LittleEndian.Uint64(raw[80:88])
	return ev, nil
}

// parseL7Event 解析 L7 载荷事件
// 对应 bpf/l7_tracer.c struct l7_event 内存布局
//
//	[0:8]   timestamp_ns
//	[8:12]  pid
//	[12:16] tid
//	[16:32] comm[16]
//	[32:36] saddr
//	[36:40] daddr
//	[40:42] sport
//	[42:44] dport
//	[44]    protocol
//	[45]    direction
//	[46:50] payload_size
//	[50:]   payload[4096]
func parseL7Event(raw []byte) (*L7Event, error) {
	const headerSize = 50
	if len(raw) < headerSize {
		return nil, fmt.Errorf("L7 raw data too short: %d", len(raw))
	}
	ev := &L7Event{}
	ev.TimestampNs = binary.LittleEndian.Uint64(raw[0:8])
	ev.PID = binary.LittleEndian.Uint32(raw[8:12])
	ev.TID = binary.LittleEndian.Uint32(raw[12:16])
	copy(ev.Comm[:], raw[16:32])
	ev.SAddr = binary.LittleEndian.Uint32(raw[32:36])
	ev.DAddr = binary.LittleEndian.Uint32(raw[36:40])
	ev.SPort = binary.LittleEndian.Uint16(raw[40:42])
	ev.DPort = binary.LittleEndian.Uint16(raw[42:44])
	ev.Protocol = raw[44]
	ev.Direction = raw[45]
	ev.PayloadSize = binary.LittleEndian.Uint32(raw[46:50])

	if len(raw) > headerSize && ev.PayloadSize > 0 {
		copyLen := int(ev.PayloadSize)
		if copyLen > len(ev.Payload) {
			copyLen = len(ev.Payload)
		}
		available := len(raw) - headerSize
		if copyLen > available {
			copyLen = available
		}
		copy(ev.Payload[:], raw[headerSize:headerSize+copyLen])
	}
	return ev, nil
}

// parseTCPacketEvent 解析 TC 包事件（对应 bpf/tc_tracer.c struct tc_packet）
func parseTCPacketEvent(raw []byte) (*TCPacket, error) {
	const size = 32
	if len(raw) < size {
		return nil, fmt.Errorf("TC packet raw data too short: %d", len(raw))
	}
	pkt := &TCPacket{}
	pkt.TimestampNs = binary.LittleEndian.Uint64(raw[0:8])
	pkt.IfIndex = binary.LittleEndian.Uint32(raw[8:12])
	pkt.SAddr = binary.LittleEndian.Uint32(raw[12:16])
	pkt.DAddr = binary.LittleEndian.Uint32(raw[16:20])
	pkt.SPort = binary.LittleEndian.Uint16(raw[20:22])
	pkt.DPort = binary.LittleEndian.Uint16(raw[22:24])
	pkt.Protocol = raw[24]
	pkt.Direction = raw[25]
	pkt.TCPFlags = raw[26]
	pkt.PacketLen = binary.LittleEndian.Uint32(raw[28:32])
	return pkt, nil
}
