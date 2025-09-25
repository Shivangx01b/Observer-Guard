# ObserveGuard Makefile

.PHONY: all build clean test run-server run-collector install deps ebpf

# Build settings
BINARY_NAME=observeguard
BUILD_DIR=build
GO_FILES=$(shell find . -name "*.go" -type f)
VERSION ?= $(shell git describe --tags --always --dirty)
COMMIT ?= $(shell git rev-parse HEAD)
DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Go build flags
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"

# Default target
all: deps build

# Install dependencies
deps:
	@echo "Installing dependencies..."
	go mod tidy
	go mod download

# Build the binary
build: $(BUILD_DIR)/$(BINARY_NAME)

$(BUILD_DIR)/$(BINARY_NAME): $(GO_FILES)
	@echo "Building ObserveGuard..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/observeguard

# Build for development (no CGO for faster builds in development)
build-dev:
	@echo "Building ObserveGuard for development..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/observeguard

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Run the API server
run-server: build-dev
	@echo "Starting ObserveGuard API server..."
	./$(BUILD_DIR)/$(BINARY_NAME) server --config configs/apiserver.yaml

# Run the data collector
run-collector: build-dev
	@echo "Starting ObserveGuard data collector..."
	./$(BUILD_DIR)/$(BINARY_NAME) collect --config configs/collector.yaml

# Install the binary
install: build
	@echo "Installing ObserveGuard..."
	cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/

# Clean build artifacts
clean:
	@echo "Cleaning up..."
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html
	rm -rf data/

# Format Go code
fmt:
	@echo "Formatting Go code..."
	go fmt ./...

# Lint Go code
lint:
	@echo "Linting Go code..."
	golangci-lint run ./...

# Create data directory
setup-dirs:
	@echo "Creating necessary directories..."
	mkdir -p data
	mkdir -p logs
	mkdir -p configs

# Docker build
docker-build:
	@echo "Building Docker image..."
	docker build -t observeguard:$(VERSION) .

# Docker run
docker-run:
	@echo "Running Docker container..."
	docker run -p 8080:8080 -v $(PWD)/data:/app/data observeguard:$(VERSION)

# Development setup
dev-setup: deps setup-dirs
	@echo "Setting up development environment..."
	@echo "Development setup complete!"

# Quick start (for demo purposes)
demo: build-dev setup-dirs
	@echo "Starting ObserveGuard demo..."
	@echo "Starting API server in background..."
	./$(BUILD_DIR)/$(BINARY_NAME) server --config configs/apiserver.yaml &
	@sleep 3
	@echo "API server started on http://localhost:8080"
	@echo "Starting data collector..."
	./$(BUILD_DIR)/$(BINARY_NAME) collect --config configs/collector.yaml --duration 30s

# Stop demo processes
stop-demo:
	@echo "Stopping demo processes..."
	pkill -f observeguard || true

# Help
help:
	@echo "Available targets:"
	@echo "  all           - Install dependencies and build"
	@echo "  build         - Build the binary"
	@echo "  build-dev     - Build for development (faster)"
	@echo "  test          - Run tests"
	@echo "  test-coverage - Run tests with coverage"
	@echo "  run-server    - Run the API server"
	@echo "  run-collector - Run the data collector"
	@echo "  install       - Install the binary"
	@echo "  clean         - Clean build artifacts"
	@echo "  fmt           - Format Go code"
	@echo "  lint          - Lint Go code"
	@echo "  setup-dirs    - Create necessary directories"
	@echo "  docker-build  - Build Docker image"
	@echo "  docker-run    - Run Docker container"
	@echo "  dev-setup     - Set up development environment"
	@echo "  demo          - Quick demo of the application"
	@echo "  stop-demo     - Stop demo processes"
	@echo "  help          - Show this help"