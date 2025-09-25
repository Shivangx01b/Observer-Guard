package storage

import (
	"context"
	"time"

	"github.com/google/uuid"

	"observeguard/internal/models"
)

// Storage interface defines the contract for event storage
type Storage interface {
	// Event operations
	StoreEvent(ctx context.Context, event *models.Event) error
	GetEvent(ctx context.Context, id uuid.UUID) (*models.Event, error)
	ListEvents(ctx context.Context, filter EventFilter) ([]*models.Event, error)
	DeleteEvent(ctx context.Context, id uuid.UUID) error
	CountEvents(ctx context.Context, filter EventFilter) (int64, error)

	// Process operations
	StoreProcessEvent(ctx context.Context, event *models.ProcessEvent) error
	GetProcessEvents(ctx context.Context, pid int32) ([]*models.ProcessEvent, error)
	ListProcesses(ctx context.Context, filter ProcessFilter) ([]*models.ProcessEvent, error)

	// Network operations
	StoreNetworkEvent(ctx context.Context, event *models.NetworkEvent) error
	GetNetworkEvents(ctx context.Context, filter NetworkFilter) ([]*models.NetworkEvent, error)

	// File operations
	StoreFileEvent(ctx context.Context, event *models.FileEvent) error
	GetFileEvents(ctx context.Context, filter FileFilter) ([]*models.FileEvent, error)

	// SSL operations
	StoreSSLEvent(ctx context.Context, event *models.SSLEvent) error
	GetSSLEvents(ctx context.Context, filter SSLFilter) ([]*models.SSLEvent, error)

	// AI Security operations
	StoreAISecurityEvent(ctx context.Context, event *models.AISecurityEvent) error
	GetAISecurityEvents(ctx context.Context, filter AISecurityFilter) ([]*models.AISecurityEvent, error)
	StoreAIModel(ctx context.Context, model *models.AIModel) error
	GetAIModel(ctx context.Context, id string) (*models.AIModel, error)
	ListAIModels(ctx context.Context) ([]*models.AIModel, error)
	StoreAIRuntime(ctx context.Context, runtime *models.AIRuntime) error
	GetAIRuntime(ctx context.Context, id string) (*models.AIRuntime, error)
	ListAIRuntimes(ctx context.Context) ([]*models.AIRuntime, error)

	// Threat operations
	StoreThreatEvent(ctx context.Context, event *models.ThreatEvent) error
	GetThreatEvent(ctx context.Context, id uuid.UUID) (*models.ThreatEvent, error)
	ListThreatEvents(ctx context.Context, filter ThreatFilter) ([]*models.ThreatEvent, error)

	// Security policy operations
	StoreSecurityPolicy(ctx context.Context, policy *models.SecurityPolicy) error
	GetSecurityPolicy(ctx context.Context, id uuid.UUID) (*models.SecurityPolicy, error)
	ListSecurityPolicies(ctx context.Context) ([]*models.SecurityPolicy, error)
	UpdateSecurityPolicy(ctx context.Context, policy *models.SecurityPolicy) error
	DeleteSecurityPolicy(ctx context.Context, id uuid.UUID) error

	// Alert operations
	StoreAlert(ctx context.Context, alert *models.Alert) error
	GetAlert(ctx context.Context, id uuid.UUID) (*models.Alert, error)
	ListAlerts(ctx context.Context, filter AlertFilter) ([]*models.Alert, error)
	UpdateAlert(ctx context.Context, alert *models.Alert) error

	// System operations
	StoreSyscallEvent(ctx context.Context, event *models.SyscallEvent) error
	GetSyscallEvents(ctx context.Context, filter SyscallFilter) ([]*models.SyscallEvent, error)

	// Data management
	ExportData(ctx context.Context, startTime, endTime time.Time) ([]byte, error)
	ImportData(ctx context.Context, data []byte) error
	CleanupOldData(ctx context.Context, before time.Time) error
	GetStorageStats(ctx context.Context) (*StorageStats, error)

	// Lifecycle
	Close() error
	Ping(ctx context.Context) error
}

// EventFilter represents filtering options for events
type EventFilter struct {
	EventTypes []models.EventType `json:"event_types,omitempty"`
	PIDs       []int32            `json:"pids,omitempty"`
	StartTime  *time.Time         `json:"start_time,omitempty"`
	EndTime    *time.Time         `json:"end_time,omitempty"`
	Limit      int                `json:"limit,omitempty"`
	Offset     int                `json:"offset,omitempty"`
	SortBy     string             `json:"sort_by,omitempty"`
	SortOrder  string             `json:"sort_order,omitempty"`
	Search     string             `json:"search,omitempty"`
}

// ProcessFilter represents filtering options for process events
type ProcessFilter struct {
	PIDs      []int32    `json:"pids,omitempty"`
	PPIDs     []int32    `json:"ppids,omitempty"`
	Actions   []string   `json:"actions,omitempty"`
	Commands  []string   `json:"commands,omitempty"`
	StartTime *time.Time `json:"start_time,omitempty"`
	EndTime   *time.Time `json:"end_time,omitempty"`
	Limit     int        `json:"limit,omitempty"`
	Offset    int        `json:"offset,omitempty"`
}

// NetworkFilter represents filtering options for network events
type NetworkFilter struct {
	PIDs        []int32    `json:"pids,omitempty"`
	Actions     []string   `json:"actions,omitempty"`
	Protocols   []string   `json:"protocols,omitempty"`
	LocalPorts  []uint16   `json:"local_ports,omitempty"`
	RemotePorts []uint16   `json:"remote_ports,omitempty"`
	RemoteIPs   []string   `json:"remote_ips,omitempty"`
	StartTime   *time.Time `json:"start_time,omitempty"`
	EndTime     *time.Time `json:"end_time,omitempty"`
	Limit       int        `json:"limit,omitempty"`
	Offset      int        `json:"offset,omitempty"`
}

// FileFilter represents filtering options for file events
type FileFilter struct {
	PIDs       []int32    `json:"pids,omitempty"`
	Actions    []string   `json:"actions,omitempty"`
	Paths      []string   `json:"paths,omitempty"`
	Extensions []string   `json:"extensions,omitempty"`
	StartTime  *time.Time `json:"start_time,omitempty"`
	EndTime    *time.Time `json:"end_time,omitempty"`
	Limit      int        `json:"limit,omitempty"`
	Offset     int        `json:"offset,omitempty"`
}

// SSLFilter represents filtering options for SSL events
type SSLFilter struct {
	PIDs      []int32    `json:"pids,omitempty"`
	Actions   []string   `json:"actions,omitempty"`
	SNIs      []string   `json:"snis,omitempty"`
	Versions  []string   `json:"versions,omitempty"`
	StartTime *time.Time `json:"start_time,omitempty"`
	EndTime   *time.Time `json:"end_time,omitempty"`
	Limit     int        `json:"limit,omitempty"`
	Offset    int        `json:"offset,omitempty"`
}

// AISecurityFilter represents filtering options for AI security events
type AISecurityFilter struct {
	PIDs         []int32    `json:"pids,omitempty"`
	ModelIDs     []string   `json:"model_ids,omitempty"`
	Actions      []string   `json:"actions,omitempty"`
	ThreatLevels []string   `json:"threat_levels,omitempty"`
	ThreatTypes  []string   `json:"threat_types,omitempty"`
	StartTime    *time.Time `json:"start_time,omitempty"`
	EndTime      *time.Time `json:"end_time,omitempty"`
	Limit        int        `json:"limit,omitempty"`
	Offset       int        `json:"offset,omitempty"`
}

// ThreatFilter represents filtering options for threat events
type ThreatFilter struct {
	ThreatIDs  []string               `json:"threat_ids,omitempty"`
	Severities []models.ThreatSeverity `json:"severities,omitempty"`
	Categories []string               `json:"categories,omitempty"`
	Statuses   []string               `json:"statuses,omitempty"`
	StartTime  *time.Time             `json:"start_time,omitempty"`
	EndTime    *time.Time             `json:"end_time,omitempty"`
	Limit      int                    `json:"limit,omitempty"`
	Offset     int                    `json:"offset,omitempty"`
}

// AlertFilter represents filtering options for alerts
type AlertFilter struct {
	PolicyIDs  []uuid.UUID            `json:"policy_ids,omitempty"`
	RuleIDs    []string               `json:"rule_ids,omitempty"`
	Severities []models.ThreatSeverity `json:"severities,omitempty"`
	Statuses   []models.AlertStatus    `json:"statuses,omitempty"`
	StartTime  *time.Time             `json:"start_time,omitempty"`
	EndTime    *time.Time             `json:"end_time,omitempty"`
	Limit      int                    `json:"limit,omitempty"`
	Offset     int                    `json:"offset,omitempty"`
}

// SyscallFilter represents filtering options for syscall events
type SyscallFilter struct {
	PIDs          []int32    `json:"pids,omitempty"`
	SyscallNames  []string   `json:"syscall_names,omitempty"`
	SyscallNumbers []int     `json:"syscall_numbers,omitempty"`
	StartTime     *time.Time `json:"start_time,omitempty"`
	EndTime       *time.Time `json:"end_time,omitempty"`
	Limit         int        `json:"limit,omitempty"`
	Offset        int        `json:"offset,omitempty"`
}

// StorageStats represents storage statistics
type StorageStats struct {
	TotalEvents      int64  `json:"total_events"`
	TotalSize        int64  `json:"total_size"`
	EventsByType     map[string]int64 `json:"events_by_type"`
	OldestEventTime  time.Time `json:"oldest_event_time"`
	NewestEventTime  time.Time `json:"newest_event_time"`
	StorageType      string `json:"storage_type"`
	Health           string `json:"health"`
}

// QueryOptions represents advanced query options
type QueryOptions struct {
	Select    []string               `json:"select,omitempty"`
	Where     map[string]interface{} `json:"where,omitempty"`
	GroupBy   []string               `json:"group_by,omitempty"`
	OrderBy   []string               `json:"order_by,omitempty"`
	Limit     int                    `json:"limit,omitempty"`
	Offset    int                    `json:"offset,omitempty"`
	Aggregate map[string]string      `json:"aggregate,omitempty"` // field -> function (count, sum, avg, max, min)
}