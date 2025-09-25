package collectors

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"observeguard/internal/models"
	"observeguard/pkg/config"
	"observeguard/pkg/storage"
	"observeguard/pkg/websocket"
)

// Manager manages all event collectors
type Manager struct {
	config      *config.Config
	storage     storage.Storage
	wsHandler   *websocket.Handler
	collectors  map[string]Collector
	eventChan   chan *models.Event
	running     bool
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
}

// Collector interface for all event collectors
type Collector interface {
	Start(ctx context.Context) error
	Stop() error
	IsRunning() bool
	GetStats() CollectorStats
}

// CollectorStats represents collector statistics
type CollectorStats struct {
	Name           string    `json:"name"`
	Running        bool      `json:"running"`
	EventsCollected int64    `json:"events_collected"`
	ErrorsCount    int64     `json:"errors_count"`
	LastEvent      time.Time `json:"last_event"`
	StartTime      time.Time `json:"start_time"`
}

// NewManager creates a new collector manager
func NewManager(config *config.Config, storage storage.Storage, wsHandler *websocket.Handler) *Manager {
	ctx, cancel := context.WithCancel(context.Background())

	manager := &Manager{
		config:     config,
		storage:    storage,
		wsHandler:  wsHandler,
		collectors: make(map[string]Collector),
		eventChan:  make(chan *models.Event, config.Monitoring.EventBuffer),
		running:    false,
		ctx:        ctx,
		cancel:     cancel,
	}

	// Initialize collectors based on configuration
	if config.Monitoring.Collectors.Process {
		manager.collectors["process"] = NewProcessCollector(config, manager.eventChan)
	}
	if config.Monitoring.Collectors.Network {
		manager.collectors["network"] = NewNetworkCollector(config, manager.eventChan)
	}
	if config.Monitoring.Collectors.File {
		manager.collectors["file"] = NewFileCollector(config, manager.eventChan)
	}
	if config.Monitoring.Collectors.SSL {
		manager.collectors["ssl"] = NewSSLCollector(config, manager.eventChan)
	}
	if config.Monitoring.Collectors.AI {
		manager.collectors["ai"] = NewAICollector(config, manager.eventChan)
		// Add advanced AI security collector
		manager.collectors["ai_security"] = NewAISecurityCollector(config, manager.eventChan, manager.storage)
	}
	if config.Monitoring.Collectors.Syscall {
		manager.collectors["syscall"] = NewSyscallCollector(config, manager.eventChan)
	}

	return manager
}

// Start starts all collectors
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return fmt.Errorf("collector manager is already running")
	}

	log.Println("Starting collector manager...")

	// Start event processor
	go m.eventProcessor()

	// Start all collectors
	for name, collector := range m.collectors {
		log.Printf("Starting %s collector...", name)
		if err := collector.Start(m.ctx); err != nil {
			log.Printf("Failed to start %s collector: %v", name, err)
			// Continue starting other collectors
		} else {
			log.Printf("%s collector started successfully", name)
		}
	}

	m.running = true
	log.Println("Collector manager started successfully")
	return nil
}

// Stop stops all collectors
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return nil
	}

	log.Println("Stopping collector manager...")

	// Cancel context to signal all collectors to stop
	m.cancel()

	// Stop all collectors
	for name, collector := range m.collectors {
		log.Printf("Stopping %s collector...", name)
		if err := collector.Stop(); err != nil {
			log.Printf("Error stopping %s collector: %v", name, err)
		}
	}

	m.running = false
	log.Println("Collector manager stopped")
	return nil
}

// IsRunning returns whether the manager is running
func (m *Manager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// GetStats returns statistics for all collectors
func (m *Manager) GetStats() map[string]CollectorStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[string]CollectorStats)
	for name, collector := range m.collectors {
		stats[name] = collector.GetStats()
	}
	return stats
}

// eventProcessor processes events from collectors
func (m *Manager) eventProcessor() {
	log.Println("Event processor started")
	defer log.Println("Event processor stopped")

	for {
		select {
		case event := <-m.eventChan:
			if err := m.processEvent(event); err != nil {
				log.Printf("Error processing event: %v", err)
			}
		case <-m.ctx.Done():
			return
		}
	}
}

// processEvent processes a single event
func (m *Manager) processEvent(event *models.Event) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Store event in database
	if err := m.storage.StoreEvent(ctx, event); err != nil {
		log.Printf("Failed to store event: %v", err)
		return err
	}

	// Store typed events based on event type
	switch event.Type {
	case models.EventTypeProcess:
		if processEvent, ok := event.Data["process_event"].(*models.ProcessEvent); ok {
			if err := m.storage.StoreProcessEvent(ctx, processEvent); err != nil {
				log.Printf("Failed to store process event: %v", err)
			}
		}
	case models.EventTypeNetwork:
		if networkEvent, ok := event.Data["network_event"].(*models.NetworkEvent); ok {
			if err := m.storage.StoreNetworkEvent(ctx, networkEvent); err != nil {
				log.Printf("Failed to store network event: %v", err)
			}
		}
	case models.EventTypeFile:
		if fileEvent, ok := event.Data["file_event"].(*models.FileEvent); ok {
			if err := m.storage.StoreFileEvent(ctx, fileEvent); err != nil {
				log.Printf("Failed to store file event: %v", err)
			}
		}
	case models.EventTypeSSL:
		if sslEvent, ok := event.Data["ssl_event"].(*models.SSLEvent); ok {
			if err := m.storage.StoreSSLEvent(ctx, sslEvent); err != nil {
				log.Printf("Failed to store SSL event: %v", err)
			}
		}
	case models.EventTypeAISecurity:
		if aiEvent, ok := event.Data["ai_event"].(*models.AISecurityEvent); ok {
			if err := m.storage.StoreAISecurityEvent(ctx, aiEvent); err != nil {
				log.Printf("Failed to store AI security event: %v", err)
			}
		}
	case models.EventTypeThreat:
		if threatEvent, ok := event.Data["threat_event"].(*models.ThreatEvent); ok {
			if err := m.storage.StoreThreatEvent(ctx, threatEvent); err != nil {
				log.Printf("Failed to store threat event: %v", err)
			}
		}
	}

	// Publish event to WebSocket subscribers
	if m.wsHandler != nil {
		m.wsHandler.PublishEvent(event)
	}

	return nil
}

// AddCollector adds a new collector
func (m *Manager) AddCollector(name string, collector Collector) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.collectors[name] = collector
}

// RemoveCollector removes a collector
func (m *Manager) RemoveCollector(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if collector, exists := m.collectors[name]; exists {
		collector.Stop()
		delete(m.collectors, name)
	}
}

// GetCollector returns a collector by name
func (m *Manager) GetCollector(name string) (Collector, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	collector, exists := m.collectors[name]
	return collector, exists
}