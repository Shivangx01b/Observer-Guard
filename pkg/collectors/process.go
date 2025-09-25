package collectors

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"observeguard/internal/models"
	"observeguard/pkg/config"
)

// ProcessCollector collects process events
type ProcessCollector struct {
	config         *config.Config
	eventChan      chan<- *models.Event
	running        int64
	eventsCollected int64
	errorsCount    int64
	lastEvent      time.Time
	startTime      time.Time
	ctx            context.Context
	cancel         context.CancelFunc
}

// NewProcessCollector creates a new process collector
func NewProcessCollector(config *config.Config, eventChan chan<- *models.Event) *ProcessCollector {
	return &ProcessCollector{
		config:    config,
		eventChan: eventChan,
	}
}

// Start starts the process collector
func (pc *ProcessCollector) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt64(&pc.running, 0, 1) {
		return nil // Already running
	}

	pc.ctx, pc.cancel = context.WithCancel(ctx)
	pc.startTime = time.Now()

	// Start simulation goroutine (in real implementation, this would load eBPF programs)
	go pc.simulateProcessEvents()

	return nil
}

// Stop stops the process collector
func (pc *ProcessCollector) Stop() error {
	if !atomic.CompareAndSwapInt64(&pc.running, 1, 0) {
		return nil // Already stopped
	}

	if pc.cancel != nil {
		pc.cancel()
	}

	return nil
}

// IsRunning returns whether the collector is running
func (pc *ProcessCollector) IsRunning() bool {
	return atomic.LoadInt64(&pc.running) == 1
}

// GetStats returns collector statistics
func (pc *ProcessCollector) GetStats() CollectorStats {
	return CollectorStats{
		Name:            "process",
		Running:         pc.IsRunning(),
		EventsCollected: atomic.LoadInt64(&pc.eventsCollected),
		ErrorsCount:     atomic.LoadInt64(&pc.errorsCount),
		LastEvent:       pc.lastEvent,
		StartTime:       pc.startTime,
	}
}

// simulateProcessEvents simulates process events for demo purposes
func (pc *ProcessCollector) simulateProcessEvents() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	processes := []string{"python", "node", "nginx", "postgres", "redis"}
	actions := []string{"start", "exit", "fork"}

	for {
		select {
		case <-pc.ctx.Done():
			return
		case <-ticker.C:
			// Generate a simulated process event
			processName := processes[time.Now().Unix()%int64(len(processes))]
			action := actions[time.Now().Unix()%int64(len(actions))]
			pid := int32(1000 + time.Now().Unix()%9000)

			processEvent := &models.ProcessEvent{
				Event: models.Event{
					ID:        uuid.New(),
					Type:      models.EventTypeProcess,
					Timestamp: time.Now(),
					PID:       pid,
					Process:   processName,
					Data:      make(map[string]interface{}),
				},
				Action:  action,
				PPID:    int32(1),
				Command: processName,
				Args:    []string{processName, "--config", "/etc/config.conf"},
				UserID:  1000,
				GroupID: 1000,
			}

			// Create generic event with process event data
			genericEvent := &models.Event{
				ID:        processEvent.ID,
				Type:      models.EventTypeProcess,
				Timestamp: processEvent.Timestamp,
				PID:       processEvent.PID,
				Process:   processEvent.Process,
				Data: map[string]interface{}{
					"process_event": processEvent,
					"action":        action,
					"command":       processName,
				},
			}

			select {
			case pc.eventChan <- genericEvent:
				atomic.AddInt64(&pc.eventsCollected, 1)
				pc.lastEvent = time.Now()
			default:
				atomic.AddInt64(&pc.errorsCount, 1)
			}
		}
	}
}