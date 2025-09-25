package models

import (
	"time"

	"github.com/google/uuid"
)

// SecurityPolicy represents a security monitoring policy
type SecurityPolicy struct {
	ID          uuid.UUID         `json:"id" validate:"required"`
	Name        string            `json:"name" validate:"required"`
	Description string            `json:"description"`
	Enabled     bool              `json:"enabled"`
	Rules       []SecurityRule    `json:"rules"`
	Actions     []SecurityAction  `json:"actions"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	Version     int               `json:"version"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// SecurityRule represents a single security detection rule
type SecurityRule struct {
	ID          string            `json:"id" validate:"required"`
	Name        string            `json:"name" validate:"required"`
	Description string            `json:"description"`
	Type        RuleType          `json:"type" validate:"required"`
	Condition   RuleCondition     `json:"condition" validate:"required"`
	Severity    ThreatSeverity    `json:"severity" validate:"required"`
	Enabled     bool              `json:"enabled"`
	Tags        []string          `json:"tags,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// RuleType represents the type of security rule
type RuleType string

const (
	RuleTypeSignature    RuleType = "signature"    // Pattern-based detection
	RuleTypeAnomaly      RuleType = "anomaly"      // Behavioral anomaly detection
	RuleTypeBaseline     RuleType = "baseline"     // Baseline deviation detection
	RuleTypeML           RuleType = "ml"           // Machine learning based
	RuleTypeThreshold    RuleType = "threshold"    // Threshold-based detection
	RuleTypeCorrelation  RuleType = "correlation"  // Event correlation
)

// RuleCondition represents the conditions for rule matching
type RuleCondition struct {
	EventTypes []EventType       `json:"event_types"`
	Filters    []ConditionFilter `json:"filters"`
	Timeframe  string            `json:"timeframe,omitempty"` // e.g., "5m", "1h"
	Threshold  int               `json:"threshold,omitempty"` // For threshold-based rules
	Logic      string            `json:"logic,omitempty"`     // AND, OR
}

// ConditionFilter represents a single filter condition
type ConditionFilter struct {
	Field    string      `json:"field" validate:"required"`
	Operator string      `json:"operator" validate:"required"` // eq, ne, gt, lt, contains, regex
	Value    interface{} `json:"value" validate:"required"`
}

// SecurityAction represents actions to take when rules are triggered
type SecurityAction struct {
	Type        ActionType        `json:"type" validate:"required"`
	Parameters  map[string]string `json:"parameters,omitempty"`
	Enabled     bool              `json:"enabled"`
	Description string            `json:"description"`
}

// ActionType represents the type of security action
type ActionType string

const (
	ActionTypeAlert       ActionType = "alert"        // Generate alert
	ActionTypeBlock       ActionType = "block"        // Block process/connection
	ActionTypeKill        ActionType = "kill"         // Kill process
	ActionTypeQuarantine  ActionType = "quarantine"   // Quarantine file/process
	ActionTypeLog         ActionType = "log"          // Enhanced logging
	ActionTypeNotify      ActionType = "notify"       // Send notification
	ActionTypeScript      ActionType = "script"       // Execute custom script
)

// ThreatSeverity represents threat severity levels
type ThreatSeverity string

const (
	SeverityLow      ThreatSeverity = "low"
	SeverityMedium   ThreatSeverity = "medium"
	SeverityHigh     ThreatSeverity = "high"
	SeverityCritical ThreatSeverity = "critical"
)

// Alert represents a security alert
type Alert struct {
	ID            uuid.UUID      `json:"id" validate:"required"`
	ThreatID      string         `json:"threat_id"`
	PolicyID      uuid.UUID      `json:"policy_id"`
	RuleID        string         `json:"rule_id"`
	Severity      ThreatSeverity `json:"severity" validate:"required"`
	Title         string         `json:"title" validate:"required"`
	Description   string         `json:"description"`
	Status        AlertStatus    `json:"status" validate:"required"`
	Events        []uuid.UUID    `json:"events"` // Related event IDs
	Indicators    []Indicator    `json:"indicators"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	AcknowledgedBy string        `json:"acknowledged_by,omitempty"`
	AcknowledgedAt *time.Time    `json:"acknowledged_at,omitempty"`
	ResolvedAt     *time.Time    `json:"resolved_at,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// AlertStatus represents the status of an alert
type AlertStatus string

const (
	AlertStatusOpen         AlertStatus = "open"
	AlertStatusAcknowledged AlertStatus = "acknowledged"
	AlertStatusInProgress   AlertStatus = "in_progress"
	AlertStatusResolved     AlertStatus = "resolved"
	AlertStatusFalsePositive AlertStatus = "false_positive"
)

// Indicator represents a threat indicator
type Indicator struct {
	Type        string `json:"type" validate:"required"`        // ip, domain, hash, process, file
	Value       string `json:"value" validate:"required"`
	Confidence  float64 `json:"confidence"`                     // 0.0 to 1.0
	Source      string `json:"source"`                         // Source of the indicator
	Description string `json:"description"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// AIModel represents an AI model being monitored
type AIModel struct {
	ID          string            `json:"id" validate:"required"`
	Name        string            `json:"name" validate:"required"`
	Path        string            `json:"path" validate:"required"`
	Type        string            `json:"type"`                    // tensorflow, pytorch, onnx, etc.
	Version     string            `json:"version"`
	Hash        string            `json:"hash"`                    // Model file hash
	Size        int64             `json:"size"`                    // Model file size
	CreatedAt   time.Time         `json:"created_at"`
	LastAccess  time.Time         `json:"last_access"`
	AccessCount int64             `json:"access_count"`
	Status      ModelStatus       `json:"status"`
	SecurityProfile ModelSecurityProfile `json:"security_profile"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// ModelStatus represents the security status of an AI model
type ModelStatus string

const (
	ModelStatusSecure      ModelStatus = "secure"
	ModelStatusSuspicious  ModelStatus = "suspicious"
	ModelStatusCompromised ModelStatus = "compromised"
	ModelStatusQuarantined ModelStatus = "quarantined"
)

// ModelSecurityProfile represents security information about an AI model
type ModelSecurityProfile struct {
	RiskScore          float64   `json:"risk_score"`           // 0.0 to 1.0
	ThreatLevel        string    `json:"threat_level"`
	KnownVulnerabilities []string `json:"known_vulnerabilities,omitempty"`
	Permissions        []string  `json:"permissions"`
	AccessPatterns     []string  `json:"access_patterns"`
	LastSecurityScan   time.Time `json:"last_security_scan"`
	Compliance         map[string]bool `json:"compliance"` // compliance checks
}

// AIRuntime represents an AI runtime environment being monitored
type AIRuntime struct {
	ID          string            `json:"id" validate:"required"`
	Name        string            `json:"name" validate:"required"`
	Type        string            `json:"type"`                    // python, nodejs, etc.
	Version     string            `json:"version"`
	PID         int32             `json:"pid"`
	Status      RuntimeStatus     `json:"status"`
	Models      []string          `json:"models"`                  // Model IDs
	StartTime   time.Time         `json:"start_time"`
	LastActivity time.Time        `json:"last_activity"`
	SecurityProfile RuntimeSecurityProfile `json:"security_profile"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// RuntimeStatus represents the status of an AI runtime
type RuntimeStatus string

const (
	RuntimeStatusRunning    RuntimeStatus = "running"
	RuntimeStatusStopped    RuntimeStatus = "stopped"
	RuntimeStatusSuspicious RuntimeStatus = "suspicious"
	RuntimeStatusBlocked    RuntimeStatus = "blocked"
)

// RuntimeSecurityProfile represents security information about an AI runtime
type RuntimeSecurityProfile struct {
	RiskScore       float64   `json:"risk_score"`       // 0.0 to 1.0
	ThreatLevel     string    `json:"threat_level"`
	Permissions     []string  `json:"permissions"`
	NetworkAccess   []string  `json:"network_access"`   // Allowed network destinations
	FileAccess      []string  `json:"file_access"`      // Allowed file paths
	ResourceLimits  map[string]interface{} `json:"resource_limits"`
	Violations      []SecurityViolation `json:"violations"`
}

// SecurityViolation represents a security policy violation
type SecurityViolation struct {
	ID          uuid.UUID   `json:"id"`
	Type        string      `json:"type"`        // permission, resource, behavior
	Description string      `json:"description"`
	Severity    ThreatSeverity `json:"severity"`
	Timestamp   time.Time   `json:"timestamp"`
	Resolved    bool        `json:"resolved"`
}