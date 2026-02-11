package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64 tcp ../../bpf/tcp_tracer.c -- -I../../bpf/headers
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64 udp ../../bpf/udp_tracer.c -- -I../../bpf/headers
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64 tc ../../bpf/tc_tracer.c -- -I../../bpf/headers

import (
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"
)

/*===========================================================================
 * Loader Structure
 *===========================================================================*/

// Loader manages loading and lifecycle of eBPF programs
type Loader struct {
	// eBPF objects
	tcpObjs *tcpObjects
	udpObjs *udpObjects
	tcObjs  *tcObjects
	
	// Links
	tcpLinks []link.Link
	udpLinks []link.Link
	tcLinks  []link.Link
	
	// Ring buffer readers
	TCPReader *ringbuf.Reader
	UDPReader *ringbuf.Reader
	TCReader  *ringbuf.Reader
}

/*===========================================================================
 * Public Methods
 *===========================================================================*/

// NewLoader creates a new eBPF program loader
func NewLoader() (*Loader, error) {
	// Remove memory lock limit for eBPF maps
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	return &Loader{}, nil
}

// LoadTCP loads and attaches TCP tracing programs
func (l *Loader) LoadTCP() error {
	log.Info("Loading TCP tracer eBPF programs...")
	
	// Load eBPF objects from compiled bytecode
	objs := &tcpObjects{}
	if err := loadTcpObjects(objs, nil); err != nil {
		return fmt.Errorf("failed to load TCP eBPF objects: %w", err)
	}
	l.tcpObjs = objs

	// Attach to inet_sock_set_state tracepoint
	tp, err := link.Tracepoint("sock", "inet_sock_set_state", 
		objs.HandleInetSockSetState, nil)
	if err != nil {
		return fmt.Errorf("failed to attach tracepoint sock:inet_sock_set_state: %w", err)
	}
	l.tcpLinks = append(l.tcpLinks, tp)
	log.Info("✓ Attached tracepoint: sock/inet_sock_set_state")

	// Open ring buffer reader
	reader, err := ringbuf.NewReader(objs.TcpEvents)
	if err != nil {
		return fmt.Errorf("failed to create TCP ring buffer reader: %w", err)
	}
	l.TCPReader = reader

	log.Info("✓ TCP tracer loaded successfully")
	return nil
}

// LoadUDP loads and attaches UDP tracing programs
func (l *Loader) LoadUDP() error {
	log.Info("Loading UDP tracer eBPF programs...")
	
	objs := &udpObjects{}
	if err := loadUdpObjects(objs, nil); err != nil {
		return fmt.Errorf("failed to load UDP eBPF objects: %w", err)
	}
	l.udpObjs = objs

	// Attach to sys_enter_sendto tracepoint
	tp1, err := link.Tracepoint("syscalls", "sys_enter_sendto", 
		objs.HandleSendtoEnter, nil)
	if err != nil {
		log.Warnf("Failed to attach sys_enter_sendto: %v", err)
	} else {
		l.udpLinks = append(l.udpLinks, tp1)
		log.Info("✓ Attached tracepoint: syscalls/sys_enter_sendto")
	}

	// Attach to sys_enter_recvfrom tracepoint
	tp2, err := link.Tracepoint("syscalls", "sys_enter_recvfrom", 
		objs.HandleRecvfromEnter, nil)
	if err != nil {
		log.Warnf("Failed to attach sys_enter_recvfrom: %v", err)
	} else {
		l.udpLinks = append(l.udpLinks, tp2)
		log.Info("✓ Attached tracepoint: syscalls/sys_enter_recvfrom")
	}

	// Open ring buffer reader
	reader, err := ringbuf.NewReader(objs.UdpEvents)
	if err != nil {
		return fmt.Errorf("failed to create UDP ring buffer reader: %w", err)
	}
	l.UDPReader = reader

	log.Info("✓ UDP tracer loaded successfully")
	return nil
}

// LoadTC loads and attaches TC (Traffic Control) programs
func (l *Loader) LoadTC(ifname string) error {
	log.Infof("Loading TC tracer for interface %s...", ifname)
	
	objs := &tcObjects{}
	if err := loadTcObjects(objs, nil); err != nil {
		return fmt.Errorf("failed to load TC eBPF objects: %w", err)
	}
	l.tcObjs = objs

	// Get network interface
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", ifname, err)
	}

	// Attach TC egress classifier
	egressLink, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.TcEgress,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		return fmt.Errorf("failed to attach TC egress: %w", err)
	}
	l.tcLinks = append(l.tcLinks, egressLink)
	log.Infof("✓ Attached TC egress to %s", ifname)

	// Attach TC ingress classifier
	ingressLink, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.TcIngress,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return fmt.Errorf("failed to attach TC ingress: %w", err)
	}
	l.tcLinks = append(l.tcLinks, ingressLink)
	log.Infof("✓ Attached TC ingress to %s", ifname)

	// Open ring buffer reader
	reader, err := ringbuf.NewReader(objs.TcEvents)
	if err != nil {
		return fmt.Errorf("failed to create TC ring buffer reader: %w", err)
	}
	l.TCReader = reader

	log.Info("✓ TC tracer loaded successfully")
	return nil
}

// Close cleans up all eBPF resources
func (l *Loader) Close() error {
	log.Info("Cleaning up eBPF resources...")
	
	var errs []error

	// Close ring buffer readers
	if l.TCPReader != nil {
		if err := l.TCPReader.Close(); err != nil {
			errs = append(errs, fmt.Errorf("TCP reader: %w", err))
		}
	}
	if l.UDPReader != nil {
		if err := l.UDPReader.Close(); err != nil {
			errs = append(errs, fmt.Errorf("UDP reader: %w", err))
		}
	}
	if l.TCReader != nil {
		if err := l.TCReader.Close(); err != nil {
			errs = append(errs, fmt.Errorf("TC reader: %w", err))
		}
	}

	// Detach links
	for _, lnk := range l.tcpLinks {
		if err := lnk.Close(); err != nil {
			errs = append(errs, fmt.Errorf("TCP link: %w", err))
		}
	}
	for _, lnk := range l.udpLinks {
		if err := lnk.Close(); err != nil {
			errs = append(errs, fmt.Errorf("UDP link: %w", err))
		}
	}
	for _, lnk := range l.tcLinks {
		if err := lnk.Close(); err != nil {
			errs = append(errs, fmt.Errorf("TC link: %w", err))
		}
	}

	// Close objects
	if l.tcpObjs != nil {
		if err := l.tcpObjs.Close(); err != nil {
			errs = append(errs, fmt.Errorf("TCP objects: %w", err))
		}
	}
	if l.udpObjs != nil {
		if err := l.udpObjs.Close(); err != nil {
			errs = append(errs, fmt.Errorf("UDP objects: %w", err))
		}
	}
	if l.tcObjs != nil {
		if err := l.tcObjs.Close(); err != nil {
			errs = append(errs, fmt.Errorf("TC objects: %w", err))
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	log.Info("✓ eBPF resources cleaned up successfully")
	return nil
}
