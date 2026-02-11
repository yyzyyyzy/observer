package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf/ringbuf"
	log "github.com/sirupsen/logrus"
)

/*===========================================================================
 * Manager Structure
 *===========================================================================*/

// Manager manages eBPF programs and event processing
type Manager struct {
	loader  *Loader
	handler EventHandler
	ctx     context.Context
	cancel  context.CancelFunc
}

/*===========================================================================
 * Public Methods
 *===========================================================================*/

// NewManager creates a new eBPF manager
func NewManager(handler EventHandler) (*Manager, error) {
	loader, err := NewLoader()
	if err != nil {
		return nil, fmt.Errorf("failed to create loader: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Manager{
		loader:  loader,
		handler: handler,
		ctx:     ctx,
		cancel:  cancel,
	}, nil
}

// Start starts all eBPF programs and event processing goroutines
func (m *Manager) Start(tcpEnabled, udpEnabled bool, tcInterface string) error {
	log.Info("╔══════════════════════════════════════════════╗")
	log.Info("║   Starting Network Observer eBPF Manager    ║")
	log.Info("╚══════════════════════════════════════════════╝")

	// Load TCP tracer
	if tcpEnabled {
		if err := m.loader.LoadTCP(); err != nil {
			return fmt.Errorf("failed to load TCP tracer: %w", err)
		}
		go m.processTCPEvents()
	}

	// Load UDP tracer
	if udpEnabled {
		if err := m.loader.LoadUDP(); err != nil {
			return fmt.Errorf("failed to load UDP tracer: %w", err)
		}
		go m.processUDPEvents()
	}

	// Load TC tracer
	if tcInterface != "" {
		if err := m.loader.LoadTC(tcInterface); err != nil {
			return fmt.Errorf("failed to load TC tracer: %w", err)
		}
		go m.processTCEvents()
	}

	log.Info("✓ eBPF manager started successfully")
	return nil
}

// Stop stops the eBPF manager and cleans up resources
func (m *Manager) Stop() error {
	log.Info("Stopping eBPF manager...")
	m.cancel()
	return m.loader.Close()
}

/*===========================================================================
 * Event Processing Methods
 *===========================================================================*/

// processTCPEvents reads and processes TCP events from ring buffer
func (m *Manager) processTCPEvents() {
	log.Info("→ TCP event processor started")

	for {
		select {
		case <-m.ctx.Done():
			log.Info("← TCP event processor stopped")
			return
		default:
			record, err := m.loader.TCPReader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Errorf("Error reading TCP event: %v", err)
				continue
			}

			var event TCPEvent
			if err := binary.Read(bytes.NewReader(record.RawSample),
				binary.LittleEndian, &event); err != nil {
				log.Errorf("Failed to parse TCP event: %v", err)
				continue
			}

			m.handler.HandleTCPEvent(&event)
		}
	}
}

// processUDPEvents reads and processes UDP events from ring buffer
func (m *Manager) processUDPEvents() {
	log.Info("→ UDP event processor started")

	for {
		select {
		case <-m.ctx.Done():
			log.Info("← UDP event processor stopped")
			return
		default:
			record, err := m.loader.UDPReader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Errorf("Error reading UDP event: %v", err)
				continue
			}

			var event UDPEvent
			if err := binary.Read(bytes.NewReader(record.RawSample),
				binary.LittleEndian, &event); err != nil {
				log.Errorf("Failed to parse UDP event: %v", err)
				continue
			}

			m.handler.HandleUDPEvent(&event)
		}
	}
}

// processTCEvents reads and processes TC packet events from ring buffer
func (m *Manager) processTCEvents() {
	log.Info("→ TC event processor started")

	for {
		select {
		case <-m.ctx.Done():
			log.Info("← TC event processor stopped")
			return
		default:
			record, err := m.loader.TCReader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Errorf("Error reading TC event: %v", err)
				continue
			}

			var packet TCPacket
			if err := binary.Read(bytes.NewReader(record.RawSample),
				binary.LittleEndian, &packet); err != nil {
				log.Errorf("Failed to parse TC packet: %v", err)
				continue
			}

			m.handler.HandleTCPacket(&packet)
		}
	}
}
