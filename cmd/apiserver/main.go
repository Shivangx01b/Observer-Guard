package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	fiberws "github.com/gofiber/websocket/v2"
	"github.com/goccy/go-json"

	"observeguard/pkg/api"
	"observeguard/pkg/config"
	"observeguard/pkg/storage"
	"observeguard/pkg/websocket"
)

var (
	configPath = flag.String("config", "configs/apiserver.yaml", "Path to configuration file")
	port       = flag.String("port", "8080", "Port to listen on")
	debug      = flag.Bool("debug", false, "Enable debug mode")
)

func init() {
	flag.Parse()
}

func main() {
	// Initialize configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize storage
	storageBackend, err := storage.NewBadgerStorage(cfg.Storage.Path)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}
	defer storageBackend.Close()

	// Create Fiber app
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
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	})

	// Middleware
	app.Use(recover.New())
	app.Use(logger.New(logger.Config{
		Format: "${time} ${status} - ${method} ${path} ${latency}\n",
	}))

	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowMethods: "GET,POST,PUT,DELETE,OPTIONS",
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
	}))

	app.Use(helmet.New())

	// Rate limiting
	app.Use(limiter.New(limiter.Config{
		Max:        100,
		Expiration: 1 * time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.Get("X-Forwarded-For", c.IP())
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error":   true,
				"message": "Rate limit exceeded",
			})
		},
	}))

	// API handlers
	apiHandler := api.NewHandler(storageBackend, cfg)
	wsHandler := websocket.NewHandler(storageBackend, cfg)

	// Health check endpoint
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":     "healthy",
			"timestamp":  time.Now().UTC().Format(time.RFC3339),
			"version":    "1.0.0",
			"uptime":     time.Since(time.Now()).String(),
		})
	})

	// API v1 routes
	v1 := app.Group("/api/v1")

	// Event Management APIs
	events := v1.Group("/events")
	events.Get("/", apiHandler.GetEvents)
	events.Get("/:id", apiHandler.GetEvent)
	events.Post("/query", apiHandler.QueryEvents)
	events.Get("/stream", fiberws.New(wsHandler.HandleEventStream))

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
	alerts.Get("/stream", fiberws.New(wsHandler.HandleAlertStream))

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
		if fiberws.IsWebSocketUpgrade(c) {
			c.Locals("allowed", true)
			return c.Next()
		}
		return fiber.ErrUpgradeRequired
	})

	ws.Get("/events", fiberws.New(wsHandler.HandleEventStream))
	ws.Get("/alerts", fiberws.New(wsHandler.HandleAlertStream))
	ws.Get("/metrics", fiberws.New(wsHandler.HandleMetricsStream))
	ws.Get("/threats", fiberws.New(wsHandler.HandleThreatStream))

	// Graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server in goroutine
	go func() {
		addr := fmt.Sprintf(":%s", *port)
		log.Printf("Starting ObserveGuard API server on %s", addr)
		if err := app.Listen(addr); err != nil {
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
}