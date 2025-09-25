package commands

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/websocket/v2"
	"github.com/goccy/go-json"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"observeguard/pkg/api"
	"observeguard/pkg/config"
	"observeguard/pkg/storage"
	wsHandler "observeguard/pkg/websocket"
)

// NewServerCommand creates the server command
func NewServerCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Start the ObserveGuard API server",
		Long:  `Start the ObserveGuard API server with monitoring and security capabilities.`,
		RunE:  runServer,
	}

	// Server-specific flags
	cmd.Flags().String("port", "8080", "Port to listen on")
	cmd.Flags().String("host", "0.0.0.0", "Host to bind to")
	cmd.Flags().Bool("enable-tls", false, "Enable TLS")
	cmd.Flags().String("cert-file", "", "TLS certificate file")
	cmd.Flags().String("key-file", "", "TLS private key file")
	cmd.Flags().Bool("enable-monitoring", true, "Enable monitoring")
	cmd.Flags().Bool("enable-ai-security", true, "Enable AI security monitoring")

	// Bind flags
	viper.BindPFlag("server.port", cmd.Flags().Lookup("port"))
	viper.BindPFlag("server.host", cmd.Flags().Lookup("host"))
	viper.BindPFlag("server.tls.enabled", cmd.Flags().Lookup("enable-tls"))
	viper.BindPFlag("server.tls.cert_file", cmd.Flags().Lookup("cert-file"))
	viper.BindPFlag("server.tls.key_file", cmd.Flags().Lookup("key-file"))
	viper.BindPFlag("monitoring.enabled", cmd.Flags().Lookup("enable-monitoring"))
	viper.BindPFlag("security.threat_detection.enabled", cmd.Flags().Lookup("enable-ai-security"))

	return cmd
}

func runServer(cmd *cobra.Command, args []string) error {
	// Load configuration
	configFile, _ := cmd.Flags().GetString("config")
	if configFile == "" {
		configFile = "configs/apiserver.yaml"
	}

	cfg, err := config.Load(configFile)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Initialize storage
	storageBackend, err := storage.NewBadgerStorage(cfg.Storage.Path)
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
	}
	defer storageBackend.Close()

	// Create Fiber app
	app := createFiberApp(cfg)

	// Setup API routes
	setupAPIRoutes(app, storageBackend, cfg)

	// Start server
	return startServer(app, cfg)
}

func createFiberApp(cfg *config.Config) *fiber.App {
	app := fiber.New(fiber.Config{
		JSONEncoder: json.Marshal,
		JSONDecoder: json.Unmarshal,
		ErrorHandler: func(ctx *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return ctx.Status(code).JSON(fiber.Map{
				"error":     true,
				"message":   err.Error(),
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			})
		},
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	})

	// Middleware
	app.Use(recover.New())
	app.Use(logger.New(logger.Config{
		Format: "${time} ${status} - ${method} ${path} ${latency}\n",
	}))

	// Basic CORS middleware
	app.Use(func(c *fiber.Ctx) error {
		c.Set("Access-Control-Allow-Origin", "*")
		c.Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
		c.Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization")
		if c.Method() == "OPTIONS" {
			return c.SendStatus(200)
		}
		return c.Next()
	})

	// Basic security headers
	app.Use(func(c *fiber.Ctx) error {
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("X-Frame-Options", "DENY")
		return c.Next()
	})

	return app
}

func setupAPIRoutes(app *fiber.App, storage storage.Storage, cfg *config.Config) {
	// API handlers
	apiHandler := api.NewHandler(storage, cfg)
	wsHandler := wsHandler.NewHandler(storage, cfg)

	// Health check endpoint
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":    "healthy",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"version":   "1.0.0",
		})
	})

	// API v1 routes
	v1 := app.Group("/api/v1")

	// Event Management APIs
	events := v1.Group("/events")
	events.Get("/", apiHandler.GetEvents)
	events.Get("/:id", apiHandler.GetEvent)
	events.Post("/query", apiHandler.QueryEvents)

	// Process Monitoring APIs
	processes := v1.Group("/processes")
	processes.Get("/", apiHandler.GetProcesses)
	processes.Get("/:pid", apiHandler.GetProcess)
	processes.Get("/:pid/tree", apiHandler.GetProcessTree)
	processes.Get("/:pid/files", apiHandler.GetProcessFiles)

	// Network Monitoring APIs
	network := v1.Group("/network")
	network.Get("/connections", apiHandler.GetNetworkConnections)
	network.Get("/traffic", apiHandler.GetNetworkTraffic)
	network.Get("/ssl", apiHandler.GetSSLTraffic)

	// System Monitoring APIs
	system := v1.Group("/system")
	system.Get("/calls", apiHandler.GetSystemCalls)
	system.Get("/metrics", apiHandler.GetSystemMetrics)

	// AI Security APIs
	ai := v1.Group("/ai")
	ai.Get("/runtimes", apiHandler.GetAIRuntimes)
	ai.Get("/models", apiHandler.GetAIModels)
	ai.Get("/models/:id/security", apiHandler.GetModelSecurity)
	ai.Post("/models/:id/scan", apiHandler.ScanModel)

	// Threat Detection APIs
	threats := v1.Group("/threats")
	threats.Get("/", apiHandler.GetThreats)
	threats.Get("/stats", apiHandler.GetThreatStats)
	threats.Post("/test", apiHandler.CreateTestThreat)
	threats.Get("/:id", apiHandler.GetThreat)
	threats.Post("/:id/respond", apiHandler.RespondToThreat)

	// Security Policies APIs
	policies := v1.Group("/policies")
	policies.Get("/", apiHandler.GetPolicies)
	policies.Post("/", apiHandler.CreatePolicy)
	policies.Get("/:id", apiHandler.GetPolicy)
	policies.Put("/:id", apiHandler.UpdatePolicy)
	policies.Delete("/:id", apiHandler.DeletePolicy)

	// Alerts Management APIs
	alerts := v1.Group("/alerts")
	alerts.Get("/", apiHandler.GetAlerts)
	alerts.Post("/:id/acknowledge", apiHandler.AcknowledgeAlert)

	// Monitoring Control APIs
	monitoring := v1.Group("/monitoring")
	monitoring.Post("/start", apiHandler.StartMonitoring)
	monitoring.Post("/stop", apiHandler.StopMonitoring)
	monitoring.Get("/status", apiHandler.GetMonitoringStatus)
	monitoring.Post("/config", apiHandler.UpdateMonitoringConfig)

	// Data Management APIs
	data := v1.Group("/data")
	data.Get("/export", apiHandler.ExportData)
	data.Post("/import", apiHandler.ImportData)
	data.Delete("/cleanup", apiHandler.CleanupData)

	// Metrics endpoint for Prometheus
	app.Get("/metrics", apiHandler.GetMetrics)

	// Version endpoint
	app.Get("/api/v1/version", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"version":    "1.0.0",
			"build_time": time.Now().UTC().Format(time.RFC3339),
			"go_version": "go1.21",
			"git_commit": "dev",
		})
	})

	// WebSocket endpoints
	ws := app.Group("/ws")
	ws.Use(func(c *fiber.Ctx) error {
		if websocket.IsWebSocketUpgrade(c) {
			c.Locals("allowed", true)
			return c.Next()
		}
		return fiber.ErrUpgradeRequired
	})

	ws.Get("/events", websocket.New(wsHandler.HandleEventStream))
	ws.Get("/alerts", websocket.New(wsHandler.HandleAlertStream))
	ws.Get("/metrics", websocket.New(wsHandler.HandleMetricsStream))
	ws.Get("/threats", websocket.New(wsHandler.HandleThreatStream))
}

func startServer(app *fiber.App, cfg *config.Config) error {
	// Graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server in goroutine
	go func() {
		addr := fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port)
		log.Printf("Starting ObserveGuard API server on %s", addr)

		var err error
		if cfg.Server.TLS.Enabled {
			err = app.ListenTLS(addr, cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
		} else {
			err = app.Listen(addr)
		}

		if err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 10*time.Second)
	defer shutdownCancel()

	if err := app.ShutdownWithContext(shutdownCtx); err != nil {
		log.Printf("Server forced shutdown: %v", err)
	}

	log.Println("Server shutdown complete")
	return nil
}