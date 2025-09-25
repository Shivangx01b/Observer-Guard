package config

import (
	"time"

	"github.com/spf13/viper"
)

// Config represents the application configuration
type Config struct {
	Server     ServerConfig     `mapstructure:"server"`
	Storage    StorageConfig    `mapstructure:"storage"`
	Security   SecurityConfig   `mapstructure:"security"`
	Monitoring MonitoringConfig `mapstructure:"monitoring"`
	Logging    LoggingConfig    `mapstructure:"logging"`
	eBPF       EBPFConfig       `mapstructure:"ebpf"`
}

// ServerConfig represents server configuration
type ServerConfig struct {
	Port         string        `mapstructure:"port"`
	Host         string        `mapstructure:"host"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	IdleTimeout  time.Duration `mapstructure:"idle_timeout"`
	MaxBodySize  int           `mapstructure:"max_body_size"`
	EnablePprof  bool          `mapstructure:"enable_pprof"`
	TLS          TLSConfig     `mapstructure:"tls"`
}

// TLSConfig represents TLS configuration
type TLSConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

// StorageConfig represents storage configuration
type StorageConfig struct {
	Type     string        `mapstructure:"type"` // badger, redis, postgres
	Path     string        `mapstructure:"path"`
	MaxSize  int64         `mapstructure:"max_size"`
	TTL      time.Duration `mapstructure:"ttl"`
	Redis    RedisConfig   `mapstructure:"redis"`
	Postgres PostgresConfig `mapstructure:"postgres"`
}

// RedisConfig represents Redis configuration
type RedisConfig struct {
	Address  string `mapstructure:"address"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

// PostgresConfig represents PostgreSQL configuration
type PostgresConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Database string `mapstructure:"database"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	SSLMode  string `mapstructure:"ssl_mode"`
}

// SecurityConfig represents security configuration
type SecurityConfig struct {
	JWTSecret       string        `mapstructure:"jwt_secret"`
	JWTExpiration   time.Duration `mapstructure:"jwt_expiration"`
	APIKey          string        `mapstructure:"api_key"`
	EnableAuth      bool          `mapstructure:"enable_auth"`
	RateLimit       RateLimitConfig `mapstructure:"rate_limit"`
	ThreatDetection ThreatDetectionConfig `mapstructure:"threat_detection"`
}

// RateLimitConfig represents rate limiting configuration
type RateLimitConfig struct {
	Enabled    bool          `mapstructure:"enabled"`
	MaxRequest int           `mapstructure:"max_requests"`
	Window     time.Duration `mapstructure:"window"`
	SkipIPs    []string      `mapstructure:"skip_ips"`
}

// ThreatDetectionConfig represents threat detection configuration
type ThreatDetectionConfig struct {
	Enabled           bool     `mapstructure:"enabled"`
	SensitivityLevel  string   `mapstructure:"sensitivity_level"` // low, medium, high
	EnabledDetectors  []string `mapstructure:"enabled_detectors"`
	ModelPaths        []string `mapstructure:"model_paths"`
	WhitelistedIPs    []string `mapstructure:"whitelisted_ips"`
	BlacklistedIPs    []string `mapstructure:"blacklisted_ips"`
	MaxFileSize       int64    `mapstructure:"max_file_size"`
	SuspiciousPatterns []string `mapstructure:"suspicious_patterns"`
}

// MonitoringConfig represents monitoring configuration
type MonitoringConfig struct {
	Enabled        bool          `mapstructure:"enabled"`
	Interval       time.Duration `mapstructure:"interval"`
	EventBuffer    int           `mapstructure:"event_buffer"`
	MetricsEnabled bool          `mapstructure:"metrics_enabled"`
	PrometheusPort int           `mapstructure:"prometheus_port"`
	HealthCheck    HealthCheckConfig `mapstructure:"health_check"`
	Collectors     CollectorConfig   `mapstructure:"collectors"`
}

// HealthCheckConfig represents health check configuration
type HealthCheckConfig struct {
	Enabled  bool          `mapstructure:"enabled"`
	Interval time.Duration `mapstructure:"interval"`
	Timeout  time.Duration `mapstructure:"timeout"`
}

// CollectorConfig represents collector configuration
type CollectorConfig struct {
	SSL     bool `mapstructure:"ssl"`
	Process bool `mapstructure:"process"`
	Network bool `mapstructure:"network"`
	File    bool `mapstructure:"file"`
	AI      bool `mapstructure:"ai"`
	Syscall bool `mapstructure:"syscall"`
}

// LoggingConfig represents logging configuration
type LoggingConfig struct {
	Level      string `mapstructure:"level"` // debug, info, warn, error
	Format     string `mapstructure:"format"` // json, text
	Output     string `mapstructure:"output"` // stdout, file
	Filename   string `mapstructure:"filename"`
	MaxSize    int    `mapstructure:"max_size"`    // MB
	MaxBackups int    `mapstructure:"max_backups"`
	MaxAge     int    `mapstructure:"max_age"`     // days
	Compress   bool   `mapstructure:"compress"`
}

// EBPFConfig represents eBPF configuration
type EBPFConfig struct {
	Enabled     bool     `mapstructure:"enabled"`
	ProgramPath string   `mapstructure:"program_path"`
	Programs    []string `mapstructure:"programs"`
	BufferSize  int      `mapstructure:"buffer_size"`
	MaxEvents   int      `mapstructure:"max_events"`
	Timeout     time.Duration `mapstructure:"timeout"`
}

// Load loads configuration from file
func Load(configPath string) (*Config, error) {
	viper.SetConfigFile(configPath)
	viper.SetConfigType("yaml")

	// Set default values
	setDefaults()

	// Read environment variables
	viper.AutomaticEnv()

	// Read config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found, use defaults
		} else {
			return nil, err
		}
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// setDefaults sets default configuration values
func setDefaults() {
	// Server defaults
	viper.SetDefault("server.port", "8080")
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("server.read_timeout", "30s")
	viper.SetDefault("server.write_timeout", "30s")
	viper.SetDefault("server.idle_timeout", "120s")
	viper.SetDefault("server.max_body_size", 4*1024*1024) // 4MB
	viper.SetDefault("server.enable_pprof", false)

	// TLS defaults
	viper.SetDefault("server.tls.enabled", false)

	// Storage defaults
	viper.SetDefault("storage.type", "badger")
	viper.SetDefault("storage.path", "./data")
	viper.SetDefault("storage.max_size", 1024*1024*1024) // 1GB
	viper.SetDefault("storage.ttl", "24h")

	// Redis defaults
	viper.SetDefault("storage.redis.address", "localhost:6379")
	viper.SetDefault("storage.redis.db", 0)

	// PostgreSQL defaults
	viper.SetDefault("storage.postgres.host", "localhost")
	viper.SetDefault("storage.postgres.port", 5432)
	viper.SetDefault("storage.postgres.ssl_mode", "disable")

	// Security defaults
	viper.SetDefault("security.jwt_expiration", "24h")
	viper.SetDefault("security.enable_auth", false)

	// Rate limiting defaults
	viper.SetDefault("security.rate_limit.enabled", true)
	viper.SetDefault("security.rate_limit.max_requests", 100)
	viper.SetDefault("security.rate_limit.window", "1m")

	// Threat detection defaults
	viper.SetDefault("security.threat_detection.enabled", true)
	viper.SetDefault("security.threat_detection.sensitivity_level", "medium")
	viper.SetDefault("security.threat_detection.enabled_detectors", []string{
		"model_access", "data_exfiltration", "privilege_escalation", "anomaly_detection",
	})
	viper.SetDefault("security.threat_detection.max_file_size", 100*1024*1024) // 100MB

	// Monitoring defaults
	viper.SetDefault("monitoring.enabled", true)
	viper.SetDefault("monitoring.interval", "1s")
	viper.SetDefault("monitoring.event_buffer", 1000)
	viper.SetDefault("monitoring.metrics_enabled", true)
	viper.SetDefault("monitoring.prometheus_port", 9090)

	// Health check defaults
	viper.SetDefault("monitoring.health_check.enabled", true)
	viper.SetDefault("monitoring.health_check.interval", "30s")
	viper.SetDefault("monitoring.health_check.timeout", "5s")

	// Collector defaults
	viper.SetDefault("monitoring.collectors.ssl", true)
	viper.SetDefault("monitoring.collectors.process", true)
	viper.SetDefault("monitoring.collectors.network", true)
	viper.SetDefault("monitoring.collectors.file", true)
	viper.SetDefault("monitoring.collectors.ai", true)
	viper.SetDefault("monitoring.collectors.syscall", false)

	// Logging defaults
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")
	viper.SetDefault("logging.output", "stdout")
	viper.SetDefault("logging.max_size", 100)
	viper.SetDefault("logging.max_backups", 3)
	viper.SetDefault("logging.max_age", 28)
	viper.SetDefault("logging.compress", true)

	// eBPF defaults
	viper.SetDefault("ebpf.enabled", true)
	viper.SetDefault("ebpf.program_path", "./ebpf/programs")
	viper.SetDefault("ebpf.programs", []string{
		"ssl_monitor", "process_monitor", "network_security", "model_security",
	})
	viper.SetDefault("ebpf.buffer_size", 256*1024) // 256KB
	viper.SetDefault("ebpf.max_events", 10000)
	viper.SetDefault("ebpf.timeout", "1s")
}