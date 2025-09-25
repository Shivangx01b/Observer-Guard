package collectors

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"observeguard/internal/models"
	"observeguard/pkg/config"
)

// NetworkCollector collects network events
type NetworkCollector struct {
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

// NewNetworkCollector creates a new network collector
func NewNetworkCollector(config *config.Config, eventChan chan<- *models.Event) *NetworkCollector {
	return &NetworkCollector{
		config:    config,
		eventChan: eventChan,
	}
}

func (nc *NetworkCollector) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt64(&nc.running, 0, 1) {
		return nil
	}
	nc.ctx, nc.cancel = context.WithCancel(ctx)
	nc.startTime = time.Now()
	go nc.simulateNetworkEvents()
	return nil
}

func (nc *NetworkCollector) Stop() error {
	if !atomic.CompareAndSwapInt64(&nc.running, 1, 0) {
		return nil
	}
	if nc.cancel != nil {
		nc.cancel()
	}
	return nil
}

func (nc *NetworkCollector) IsRunning() bool {
	return atomic.LoadInt64(&nc.running) == 1
}

func (nc *NetworkCollector) GetStats() CollectorStats {
	return CollectorStats{
		Name:            "network",
		Running:         nc.IsRunning(),
		EventsCollected: atomic.LoadInt64(&nc.eventsCollected),
		ErrorsCount:     atomic.LoadInt64(&nc.errorsCount),
		LastEvent:       nc.lastEvent,
		StartTime:       nc.startTime,
	}
}

func (nc *NetworkCollector) simulateNetworkEvents() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	actions := []string{"connect", "bind", "listen", "close"}
	protocols := []string{"tcp", "udp"}

	for {
		select {
		case <-nc.ctx.Done():
			return
		case <-ticker.C:
			action := actions[time.Now().Unix()%int64(len(actions))]
			protocol := protocols[time.Now().Unix()%int64(len(protocols))]
			pid := int32(1000 + time.Now().Unix()%9000)

			networkEvent := &models.NetworkEvent{
				Event: models.Event{
					ID:        uuid.New(),
					Type:      models.EventTypeNetwork,
					Timestamp: time.Now(),
					PID:       pid,
					Process:   "nginx",
					Data:      make(map[string]interface{}),
				},
				Action:     action,
				Protocol:   protocol,
				LocalAddr:  "127.0.0.1",
				LocalPort:  8080,
				RemoteAddr: "192.168.1.100",
				RemotePort: 443,
				BytesSent:  1024,
				BytesRecv:  2048,
			}

			genericEvent := &models.Event{
				ID:        networkEvent.ID,
				Type:      models.EventTypeNetwork,
				Timestamp: networkEvent.Timestamp,
				PID:       networkEvent.PID,
				Process:   networkEvent.Process,
				Data: map[string]interface{}{
					"network_event": networkEvent,
					"action":        action,
					"protocol":      protocol,
				},
			}

			select {
			case nc.eventChan <- genericEvent:
				atomic.AddInt64(&nc.eventsCollected, 1)
				nc.lastEvent = time.Now()
			default:
				atomic.AddInt64(&nc.errorsCount, 1)
			}
		}
	}
}

// FileCollector collects file system events
type FileCollector struct {
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

func NewFileCollector(config *config.Config, eventChan chan<- *models.Event) *FileCollector {
	return &FileCollector{
		config:    config,
		eventChan: eventChan,
	}
}

func (fc *FileCollector) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt64(&fc.running, 0, 1) {
		return nil
	}
	fc.ctx, fc.cancel = context.WithCancel(ctx)
	fc.startTime = time.Now()
	go fc.simulateFileEvents()
	return nil
}

func (fc *FileCollector) Stop() error {
	if !atomic.CompareAndSwapInt64(&fc.running, 1, 0) {
		return nil
	}
	if fc.cancel != nil {
		fc.cancel()
	}
	return nil
}

func (fc *FileCollector) IsRunning() bool {
	return atomic.LoadInt64(&fc.running) == 1
}

func (fc *FileCollector) GetStats() CollectorStats {
	return CollectorStats{
		Name:            "file",
		Running:         fc.IsRunning(),
		EventsCollected: atomic.LoadInt64(&fc.eventsCollected),
		ErrorsCount:     atomic.LoadInt64(&fc.errorsCount),
		LastEvent:       fc.lastEvent,
		StartTime:       fc.startTime,
	}
}

func (fc *FileCollector) simulateFileEvents() {
	ticker := time.NewTicker(1500 * time.Millisecond)
	defer ticker.Stop()

	actions := []string{"open", "read", "write", "close"}
	files := []string{"/var/log/app.log", "/etc/config.conf", "/tmp/temp.dat", "/home/user/document.txt"}

	for {
		select {
		case <-fc.ctx.Done():
			return
		case <-ticker.C:
			action := actions[time.Now().Unix()%int64(len(actions))]
			file := files[time.Now().Unix()%int64(len(files))]
			pid := int32(1000 + time.Now().Unix()%9000)

			fileEvent := &models.FileEvent{
				Event: models.Event{
					ID:        uuid.New(),
					Type:      models.EventTypeFile,
					Timestamp: time.Now(),
					PID:       pid,
					Process:   "editor",
					Data:      make(map[string]interface{}),
				},
				Action:     action,
				Path:       file,
				Flags:      0644,
				Mode:       0644,
				BytesRead:  512,
				BytesWrite: 256,
			}

			genericEvent := &models.Event{
				ID:        fileEvent.ID,
				Type:      models.EventTypeFile,
				Timestamp: fileEvent.Timestamp,
				PID:       fileEvent.PID,
				Process:   fileEvent.Process,
				Data: map[string]interface{}{
					"file_event": fileEvent,
					"action":     action,
					"path":       file,
				},
			}

			select {
			case fc.eventChan <- genericEvent:
				atomic.AddInt64(&fc.eventsCollected, 1)
				fc.lastEvent = time.Now()
			default:
				atomic.AddInt64(&fc.errorsCount, 1)
			}
		}
	}
}

// SSLCollector collects SSL/TLS events
type SSLCollector struct {
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

func NewSSLCollector(config *config.Config, eventChan chan<- *models.Event) *SSLCollector {
	return &SSLCollector{
		config:    config,
		eventChan: eventChan,
	}
}

func (sc *SSLCollector) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt64(&sc.running, 0, 1) {
		return nil
	}
	sc.ctx, sc.cancel = context.WithCancel(ctx)
	sc.startTime = time.Now()
	go sc.simulateSSLEvents()
	return nil
}

func (sc *SSLCollector) Stop() error {
	if !atomic.CompareAndSwapInt64(&sc.running, 1, 0) {
		return nil
	}
	if sc.cancel != nil {
		sc.cancel()
	}
	return nil
}

func (sc *SSLCollector) IsRunning() bool {
	return atomic.LoadInt64(&sc.running) == 1
}

func (sc *SSLCollector) GetStats() CollectorStats {
	return CollectorStats{
		Name:            "ssl",
		Running:         sc.IsRunning(),
		EventsCollected: atomic.LoadInt64(&sc.eventsCollected),
		ErrorsCount:     atomic.LoadInt64(&sc.errorsCount),
		LastEvent:       sc.lastEvent,
		StartTime:       sc.startTime,
	}
}

func (sc *SSLCollector) simulateSSLEvents() {
	ticker := time.NewTicker(4 * time.Second)
	defer ticker.Stop()

	actions := []string{"handshake", "read", "write"}
	versions := []string{"TLSv1.2", "TLSv1.3"}
	ciphers := []string{"AES256-GCM-SHA384", "CHACHA20-POLY1305-SHA256"}

	for {
		select {
		case <-sc.ctx.Done():
			return
		case <-ticker.C:
			action := actions[time.Now().Unix()%int64(len(actions))]
			version := versions[time.Now().Unix()%int64(len(versions))]
			cipher := ciphers[time.Now().Unix()%int64(len(ciphers))]
			pid := int32(1000 + time.Now().Unix()%9000)

			sslEvent := &models.SSLEvent{
				Event: models.Event{
					ID:        uuid.New(),
					Type:      models.EventTypeSSL,
					Timestamp: time.Now(),
					PID:       pid,
					Process:   "nginx",
					Data:      make(map[string]interface{}),
				},
				Action:      action,
				Version:     version,
				Cipher:      cipher,
				SNI:         "api.example.com",
				DataLength:  1024,
				IsEncrypted: true,
			}

			genericEvent := &models.Event{
				ID:        sslEvent.ID,
				Type:      models.EventTypeSSL,
				Timestamp: sslEvent.Timestamp,
				PID:       sslEvent.PID,
				Process:   sslEvent.Process,
				Data: map[string]interface{}{
					"ssl_event": sslEvent,
					"action":    action,
					"version":   version,
				},
			}

			select {
			case sc.eventChan <- genericEvent:
				atomic.AddInt64(&sc.eventsCollected, 1)
				sc.lastEvent = time.Now()
			default:
				atomic.AddInt64(&sc.errorsCount, 1)
			}
		}
	}
}

// AICollector collects AI security events
type AICollector struct {
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

func NewAICollector(config *config.Config, eventChan chan<- *models.Event) *AICollector {
	return &AICollector{
		config:    config,
		eventChan: eventChan,
	}
}

func (ac *AICollector) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt64(&ac.running, 0, 1) {
		return nil
	}
	ac.ctx, ac.cancel = context.WithCancel(ctx)
	ac.startTime = time.Now()
	go ac.simulateAIEvents()
	return nil
}

func (ac *AICollector) Stop() error {
	if !atomic.CompareAndSwapInt64(&ac.running, 1, 0) {
		return nil
	}
	if ac.cancel != nil {
		ac.cancel()
	}
	return nil
}

func (ac *AICollector) IsRunning() bool {
	return atomic.LoadInt64(&ac.running) == 1
}

func (ac *AICollector) GetStats() CollectorStats {
	return CollectorStats{
		Name:            "ai",
		Running:         ac.IsRunning(),
		EventsCollected: atomic.LoadInt64(&ac.eventsCollected),
		ErrorsCount:     atomic.LoadInt64(&ac.errorsCount),
		LastEvent:       ac.lastEvent,
		StartTime:       ac.startTime,
	}
}

func (ac *AICollector) simulateAIEvents() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	actions := []string{"load", "inference", "modify", "access"}
	threatLevels := []string{"low", "medium", "high", "critical"}
	threatTypes := []string{"model_extraction", "data_exfiltration", "prompt_injection"}

	for {
		select {
		case <-ac.ctx.Done():
			return
		case <-ticker.C:
			action := actions[time.Now().Unix()%int64(len(actions))]
			threatLevel := threatLevels[time.Now().Unix()%int64(len(threatLevels))]
			threatType := threatTypes[time.Now().Unix()%int64(len(threatTypes))]
			pid := int32(1000 + time.Now().Unix()%9000)

			aiEvent := &models.AISecurityEvent{
				Event: models.Event{
					ID:        uuid.New(),
					Type:      models.EventTypeAISecurity,
					Timestamp: time.Now(),
					PID:       pid,
					Process:   "python",
					Data:      make(map[string]interface{}),
				},
				ModelID:     "model-123",
				ModelPath:   "/models/bert-large.pt",
				Action:      action,
				ThreatLevel: threatLevel,
				ThreatType:  threatType,
				Confidence:  0.85,
				Description: "Suspicious AI model activity detected",
				InputData:   "user input data",
				OutputData:  "model output",
			}

			genericEvent := &models.Event{
				ID:        aiEvent.ID,
				Type:      models.EventTypeAISecurity,
				Timestamp: aiEvent.Timestamp,
				PID:       aiEvent.PID,
				Process:   aiEvent.Process,
				Data: map[string]interface{}{
					"ai_event":     aiEvent,
					"action":       action,
					"threat_level": threatLevel,
					"threat_type":  threatType,
				},
			}

			select {
			case ac.eventChan <- genericEvent:
				atomic.AddInt64(&ac.eventsCollected, 1)
				ac.lastEvent = time.Now()
			default:
				atomic.AddInt64(&ac.errorsCount, 1)
			}
		}
	}
}

// SyscallCollector collects system call events
type SyscallCollector struct {
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

func NewSyscallCollector(config *config.Config, eventChan chan<- *models.Event) *SyscallCollector {
	return &SyscallCollector{
		config:    config,
		eventChan: eventChan,
	}
}

func (sc *SyscallCollector) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt64(&sc.running, 0, 1) {
		return nil
	}
	sc.ctx, sc.cancel = context.WithCancel(ctx)
	sc.startTime = time.Now()
	go sc.simulateSyscallEvents()
	return nil
}

func (sc *SyscallCollector) Stop() error {
	if !atomic.CompareAndSwapInt64(&sc.running, 1, 0) {
		return nil
	}
	if sc.cancel != nil {
		sc.cancel()
	}
	return nil
}

func (sc *SyscallCollector) IsRunning() bool {
	return atomic.LoadInt64(&sc.running) == 1
}

func (sc *SyscallCollector) GetStats() CollectorStats {
	return CollectorStats{
		Name:            "syscall",
		Running:         sc.IsRunning(),
		EventsCollected: atomic.LoadInt64(&sc.eventsCollected),
		ErrorsCount:     atomic.LoadInt64(&sc.errorsCount),
		LastEvent:       sc.lastEvent,
		StartTime:       sc.startTime,
	}
}

func (sc *SyscallCollector) simulateSyscallEvents() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	syscalls := []string{"open", "read", "write", "close", "connect", "bind"}

	for {
		select {
		case <-sc.ctx.Done():
			return
		case <-ticker.C:
			syscallName := syscalls[time.Now().Unix()%int64(len(syscalls))]
			pid := int32(1000 + time.Now().Unix()%9000)

			syscallEvent := &models.SyscallEvent{
				Event: models.Event{
					ID:        uuid.New(),
					Type:      models.EventTypeSyscall,
					Timestamp: time.Now(),
					PID:       pid,
					Process:   "app",
					Data:      make(map[string]interface{}),
				},
				SyscallName:   syscallName,
				SyscallNumber: 1,
				Args:          []uint64{123, 456, 789},
				ReturnValue:   0,
				Duration:      1000,
			}

			genericEvent := &models.Event{
				ID:        syscallEvent.ID,
				Type:      models.EventTypeSyscall,
				Timestamp: syscallEvent.Timestamp,
				PID:       syscallEvent.PID,
				Process:   syscallEvent.Process,
				Data: map[string]interface{}{
					"syscall_event": syscallEvent,
					"syscall_name":  syscallName,
				},
			}

			select {
			case sc.eventChan <- genericEvent:
				atomic.AddInt64(&sc.eventsCollected, 1)
				sc.lastEvent = time.Now()
			default:
				atomic.AddInt64(&sc.errorsCount, 1)
			}
		}
	}
}