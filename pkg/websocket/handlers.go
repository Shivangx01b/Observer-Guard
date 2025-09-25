package websocket

import (
	"log"
	"sync"
	"time"

	"github.com/gofiber/websocket/v2"
	"github.com/google/uuid"

	"observeguard/internal/models"
	"observeguard/pkg/config"
	"observeguard/pkg/storage"
)

// Handler manages WebSocket connections and real-time data streaming
type Handler struct {
	storage     storage.Storage
	config      *config.Config
	connections map[string]*Connection
	mu          sync.RWMutex
	eventChan   chan *models.Event
	alertChan   chan *models.Alert
	metricsChan chan *MetricsData
	threatChan  chan *models.ThreatEvent
}

// Connection represents a WebSocket connection
type Connection struct {
	ID       string
	Conn     *websocket.Conn
	Type     string // events, alerts, metrics, threats
	Filters  map[string]interface{}
	LastSeen time.Time
}

// MetricsData represents real-time metrics
type MetricsData struct {
	Timestamp    time.Time              `json:"timestamp"`
	EventCounts  map[string]int64       `json:"event_counts"`
	ThreatCounts map[string]int64       `json:"threat_counts"`
	SystemStats  map[string]interface{} `json:"system_stats"`
}

// Message represents a WebSocket message
type Message struct {
	Type      string      `json:"type"`
	Timestamp time.Time   `json:"timestamp"`
	Data      interface{} `json:"data"`
}

// NewHandler creates a new WebSocket handler
func NewHandler(storage storage.Storage, config *config.Config) *Handler {
	handler := &Handler{
		storage:     storage,
		config:      config,
		connections: make(map[string]*Connection),
		eventChan:   make(chan *models.Event, 1000),
		alertChan:   make(chan *models.Alert, 100),
		metricsChan: make(chan *MetricsData, 100),
		threatChan:  make(chan *models.ThreatEvent, 100),
	}

	// Start background workers
	go handler.eventBroadcaster()
	go handler.alertBroadcaster()
	go handler.metricsBroadcaster()
	go handler.threatBroadcaster()
	go handler.connectionCleaner()
	go handler.metricsCollector()

	return handler
}

// HandleEventStream handles real-time event streaming
func (h *Handler) HandleEventStream(c *websocket.Conn) {
	connID := uuid.New().String()
	conn := &Connection{
		ID:       connID,
		Conn:     c,
		Type:     "events",
		Filters:  make(map[string]interface{}),
		LastSeen: time.Now(),
	}

	h.mu.Lock()
	h.connections[connID] = conn
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.connections, connID)
		h.mu.Unlock()
		c.Close()
	}()

	log.Printf("WebSocket event stream connected: %s", connID)

	// Send welcome message
	welcome := Message{
		Type:      "welcome",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"connection_id": connID,
			"stream_type":   "events",
			"message":       "Connected to ObserveGuard event stream",
		},
	}
	h.sendMessage(conn, welcome)

	// Handle incoming messages for filtering
	for {
		var msg map[string]interface{}
		if err := c.ReadJSON(&msg); err != nil {
			log.Printf("WebSocket read error: %v", err)
			break
		}

		conn.LastSeen = time.Now()

		// Handle filter updates
		if msgType, ok := msg["type"].(string); ok && msgType == "set_filters" {
			if filters, ok := msg["filters"].(map[string]interface{}); ok {
				conn.Filters = filters
				h.sendMessage(conn, Message{
					Type:      "filters_updated",
					Timestamp: time.Now(),
					Data:      map[string]interface{}{"filters": filters},
				})
			}
		}
	}
}

// HandleAlertStream handles real-time alert streaming
func (h *Handler) HandleAlertStream(c *websocket.Conn) {
	connID := uuid.New().String()
	conn := &Connection{
		ID:       connID,
		Conn:     c,
		Type:     "alerts",
		Filters:  make(map[string]interface{}),
		LastSeen: time.Now(),
	}

	h.mu.Lock()
	h.connections[connID] = conn
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.connections, connID)
		h.mu.Unlock()
		c.Close()
	}()

	log.Printf("WebSocket alert stream connected: %s", connID)

	// Send welcome message
	welcome := Message{
		Type:      "welcome",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"connection_id": connID,
			"stream_type":   "alerts",
			"message":       "Connected to ObserveGuard alert stream",
		},
	}
	h.sendMessage(conn, welcome)

	// Handle incoming messages
	for {
		var msg map[string]interface{}
		if err := c.ReadJSON(&msg); err != nil {
			log.Printf("WebSocket read error: %v", err)
			break
		}
		conn.LastSeen = time.Now()
	}
}

// HandleMetricsStream handles real-time metrics streaming
func (h *Handler) HandleMetricsStream(c *websocket.Conn) {
	connID := uuid.New().String()
	conn := &Connection{
		ID:       connID,
		Conn:     c,
		Type:     "metrics",
		Filters:  make(map[string]interface{}),
		LastSeen: time.Now(),
	}

	h.mu.Lock()
	h.connections[connID] = conn
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.connections, connID)
		h.mu.Unlock()
		c.Close()
	}()

	log.Printf("WebSocket metrics stream connected: %s", connID)

	// Send welcome message
	welcome := Message{
		Type:      "welcome",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"connection_id": connID,
			"stream_type":   "metrics",
			"message":       "Connected to ObserveGuard metrics stream",
		},
	}
	h.sendMessage(conn, welcome)

	// Handle incoming messages
	for {
		var msg map[string]interface{}
		if err := c.ReadJSON(&msg); err != nil {
			log.Printf("WebSocket read error: %v", err)
			break
		}
		conn.LastSeen = time.Now()
	}
}

// HandleThreatStream handles real-time threat streaming
func (h *Handler) HandleThreatStream(c *websocket.Conn) {
	connID := uuid.New().String()
	conn := &Connection{
		ID:       connID,
		Conn:     c,
		Type:     "threats",
		Filters:  make(map[string]interface{}),
		LastSeen: time.Now(),
	}

	h.mu.Lock()
	h.connections[connID] = conn
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.connections, connID)
		h.mu.Unlock()
		c.Close()
	}()

	log.Printf("WebSocket threat stream connected: %s", connID)

	// Send welcome message
	welcome := Message{
		Type:      "welcome",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"connection_id": connID,
			"stream_type":   "threats",
			"message":       "Connected to ObserveGuard threat stream",
		},
	}
	h.sendMessage(conn, welcome)

	// Handle incoming messages
	for {
		var msg map[string]interface{}
		if err := c.ReadJSON(&msg); err != nil {
			log.Printf("WebSocket read error: %v", err)
			break
		}
		conn.LastSeen = time.Now()
	}
}

// PublishEvent publishes an event to WebSocket subscribers
func (h *Handler) PublishEvent(event *models.Event) {
	select {
	case h.eventChan <- event:
	default:
		// Channel is full, skip this event
		log.Printf("Event channel full, dropping event: %s", event.ID)
	}
}

// PublishAlert publishes an alert to WebSocket subscribers
func (h *Handler) PublishAlert(alert *models.Alert) {
	select {
	case h.alertChan <- alert:
	default:
		log.Printf("Alert channel full, dropping alert: %s", alert.ID)
	}
}

// PublishThreat publishes a threat to WebSocket subscribers
func (h *Handler) PublishThreat(threat *models.ThreatEvent) {
	select {
	case h.threatChan <- threat:
	default:
		log.Printf("Threat channel full, dropping threat: %s", threat.ID)
	}
}

// eventBroadcaster broadcasts events to WebSocket connections
func (h *Handler) eventBroadcaster() {
	for event := range h.eventChan {
		h.mu.RLock()
		for _, conn := range h.connections {
			if conn.Type == "events" && h.eventMatchesFilters(event, conn.Filters) {
				msg := Message{
					Type:      "event",
					Timestamp: time.Now(),
					Data:      event,
				}
				go h.sendMessage(conn, msg)
			}
		}
		h.mu.RUnlock()
	}
}

// alertBroadcaster broadcasts alerts to WebSocket connections
func (h *Handler) alertBroadcaster() {
	for alert := range h.alertChan {
		h.mu.RLock()
		for _, conn := range h.connections {
			if conn.Type == "alerts" {
				msg := Message{
					Type:      "alert",
					Timestamp: time.Now(),
					Data:      alert,
				}
				go h.sendMessage(conn, msg)
			}
		}
		h.mu.RUnlock()
	}
}

// metricsBroadcaster broadcasts metrics to WebSocket connections
func (h *Handler) metricsBroadcaster() {
	for metrics := range h.metricsChan {
		h.mu.RLock()
		for _, conn := range h.connections {
			if conn.Type == "metrics" {
				msg := Message{
					Type:      "metrics",
					Timestamp: time.Now(),
					Data:      metrics,
				}
				go h.sendMessage(conn, msg)
			}
		}
		h.mu.RUnlock()
	}
}

// threatBroadcaster broadcasts threats to WebSocket connections
func (h *Handler) threatBroadcaster() {
	for threat := range h.threatChan {
		h.mu.RLock()
		for _, conn := range h.connections {
			if conn.Type == "threats" {
				msg := Message{
					Type:      "threat",
					Timestamp: time.Now(),
					Data:      threat,
				}
				go h.sendMessage(conn, msg)
			}
		}
		h.mu.RUnlock()
	}
}

// connectionCleaner removes stale connections
func (h *Handler) connectionCleaner() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		h.mu.Lock()
		for id, conn := range h.connections {
			if now.Sub(conn.LastSeen) > 60*time.Second {
				log.Printf("Removing stale WebSocket connection: %s", id)
				conn.Conn.Close()
				delete(h.connections, id)
			}
		}
		h.mu.Unlock()
	}
}

// metricsCollector collects and publishes metrics
func (h *Handler) metricsCollector() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		metrics := &MetricsData{
			Timestamp: time.Now(),
			EventCounts: map[string]int64{
				"process": 1234,
				"network": 567,
				"file":    890,
				"ssl":     123,
				"ai":      45,
			},
			ThreatCounts: map[string]int64{
				"critical": 2,
				"high":     8,
				"medium":   23,
				"low":      67,
			},
			SystemStats: map[string]interface{}{
				"cpu_usage":    75.5,
				"memory_usage": 65.2,
				"disk_usage":   45.8,
				"connections":  len(h.connections),
			},
		}

		select {
		case h.metricsChan <- metrics:
		default:
			// Channel full, skip this update
		}
	}
}

// sendMessage sends a message to a WebSocket connection
func (h *Handler) sendMessage(conn *Connection, msg Message) {
	if err := conn.Conn.WriteJSON(msg); err != nil {
		log.Printf("Failed to send WebSocket message to %s: %v", conn.ID, err)
		// Connection is likely dead, it will be cleaned up by connectionCleaner
	}
}

// eventMatchesFilters checks if an event matches the connection filters
func (h *Handler) eventMatchesFilters(event *models.Event, filters map[string]interface{}) bool {
	// If no filters, allow all events
	if len(filters) == 0 {
		return true
	}

	// Check event type filter
	if eventTypes, ok := filters["event_types"].([]interface{}); ok {
		found := false
		for _, et := range eventTypes {
			if etStr, ok := et.(string); ok && string(event.Type) == etStr {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check PID filter
	if pids, ok := filters["pids"].([]interface{}); ok {
		found := false
		for _, p := range pids {
			if pidFloat, ok := p.(float64); ok && int32(pidFloat) == event.PID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check process filter
	if processes, ok := filters["processes"].([]interface{}); ok {
		found := false
		for _, p := range processes {
			if processStr, ok := p.(string); ok && event.Process == processStr {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// GetConnectionStats returns WebSocket connection statistics
func (h *Handler) GetConnectionStats() map[string]interface{} {
	h.mu.RLock()
	defer h.mu.RUnlock()

	stats := map[string]interface{}{
		"total_connections": len(h.connections),
		"by_type": map[string]int{
			"events":  0,
			"alerts":  0,
			"metrics": 0,
			"threats": 0,
		},
		"channel_sizes": map[string]int{
			"events":  len(h.eventChan),
			"alerts":  len(h.alertChan),
			"metrics": len(h.metricsChan),
			"threats": len(h.threatChan),
		},
	}

	byType := stats["by_type"].(map[string]int)
	for _, conn := range h.connections {
		byType[conn.Type]++
	}

	return stats
}