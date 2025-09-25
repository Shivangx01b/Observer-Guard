package models

import (
	"time"

	"github.com/google/uuid"
)

// EventType represents the type of system event
type EventType string

const (
	EventTypeProcess    EventType = "process"
	EventTypeNetwork    EventType = "network"
	EventTypeFile       EventType = "file"
	EventTypeSSL        EventType = "ssl"
	EventTypeSyscall    EventType = "syscall"
	EventTypeAISecurity EventType = "ai_security"
	EventTypeThreat     EventType = "threat"
)

// Event represents a generic system event
type Event struct {
	ID        uuid.UUID              `json:"id" validate:"required"`
	Type      EventType              `json:"type" validate:"required"`
	Timestamp time.Time              `json:"timestamp" validate:"required"`
	PID       int32                  `json:"pid"`
	Process   string                 `json:"process,omitempty"`
	Data      map[string]interface{} `json:"data"`
	Metadata  map[string]string      `json:"metadata,omitempty"`
}

// ProcessEvent represents process lifecycle events
type ProcessEvent struct {
	Event
	Action       string `json:"action"` // start, exit, fork
	PPID         int32  `json:"ppid"`
	Command      string `json:"command"`
	Args         []string `json:"args"`
	Environment  []string `json:"environment,omitempty"`
	WorkingDir   string `json:"working_dir,omitempty"`
	UserID       int32  `json:"user_id"`
	GroupID      int32  `json:"group_id"`
	ExitCode     int32  `json:"exit_code,omitempty"`
}

// NetworkEvent represents network activity events
type NetworkEvent struct {
	Event
	Action     string `json:"action"` // connect, bind, listen, close
	Protocol   string `json:"protocol"` // tcp, udp
	LocalAddr  string `json:"local_addr"`
	LocalPort  uint16 `json:"local_port"`
	RemoteAddr string `json:"remote_addr"`
	RemotePort uint16 `json:"remote_port"`
	BytesSent  uint64 `json:"bytes_sent"`
	BytesRecv  uint64 `json:"bytes_recv"`
}

// FileEvent represents file system events
type FileEvent struct {
	Event
	Action      string `json:"action"` // open, read, write, close, delete
	Path        string `json:"path" validate:"required"`
	Flags       uint32 `json:"flags"`
	Mode        uint32 `json:"mode"`
	BytesRead   uint64 `json:"bytes_read,omitempty"`
	BytesWrite  uint64 `json:"bytes_write,omitempty"`
	Permissions string `json:"permissions,omitempty"`
}

// SSLEvent represents SSL/TLS traffic events
type SSLEvent struct {
	Event
	Action        string `json:"action"` // handshake, read, write
	Version       string `json:"version"`
	Cipher        string `json:"cipher"`
	SNI           string `json:"sni,omitempty"`
	Certificate   string `json:"certificate,omitempty"`
	DataLength    uint32 `json:"data_length"`
	IsEncrypted   bool   `json:"is_encrypted"`
}

// AISecurityEvent represents AI-specific security events
type AISecurityEvent struct {
	Event
	ModelID       string `json:"model_id,omitempty"`
	ModelPath     string `json:"model_path,omitempty"`
	Action        string `json:"action"` // load, inference, modify, access
	ThreatLevel   string `json:"threat_level"` // low, medium, high, critical
	ThreatType    string `json:"threat_type"` // model_extraction, data_exfiltration, prompt_injection
	Confidence    float64 `json:"confidence"`
	Description   string `json:"description"`
	InputData     string `json:"input_data,omitempty"`
	OutputData    string `json:"output_data,omitempty"`
}

// ThreatEvent represents detected security threats
type ThreatEvent struct {
	Event
	ThreatID      string   `json:"threat_id" validate:"required"`
	Severity      string   `json:"severity" validate:"required"` // low, medium, high, critical
	Category      string   `json:"category" validate:"required"`
	Title         string   `json:"title" validate:"required"`
	Description   string   `json:"description"`
	Indicators    []string `json:"indicators"`
	Mitigations   []string `json:"mitigations,omitempty"`
	Status        string   `json:"status"` // active, mitigated, false_positive
	Source        string   `json:"source"` // system source that detected the threat
	RelatedEvents []uuid.UUID `json:"related_events,omitempty"`
}

// SyscallEvent represents system call events
type SyscallEvent struct {
	Event
	SyscallName   string `json:"syscall_name" validate:"required"`
	SyscallNumber int    `json:"syscall_number"`
	Args          []uint64 `json:"args"`
	ReturnValue   int64  `json:"return_value"`
	Duration      int64  `json:"duration_ns"`
}