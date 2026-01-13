#!/bin/bash

# =============================================================================
# Proxy Server Setup Script for Ubuntu
# One-line setup: curl -sSL <url>/setup.sh | sudo bash
# Or: sudo ./setup.sh
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
GO_VERSION="1.21.6"
APP_NAME="proxy-server"
APP_USER="proxyserver"
APP_DIR="/opt/${APP_NAME}"
SERVICE_PORT="3000"

# Print colored message
print_msg() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_step() {
    echo -e "\n${BLUE}==>${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Detect script directory or use embedded files
detect_source() {
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)" || SCRIPT_DIR=""
    
    # Check if we have source files
    if [[ -f "${SCRIPT_DIR}/main.go" ]]; then
        USE_LOCAL_FILES=true
        print_msg "Using local source files from ${SCRIPT_DIR}"
    else
        USE_LOCAL_FILES=false
        print_msg "Will create source files in ${APP_DIR}"
    fi
}

# Update system packages
update_system() {
    print_step "Updating system packages"
    apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
    print_msg "System updated"
}

# Install required packages
install_dependencies() {
    print_step "Installing dependencies"
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        curl \
        wget \
        git \
        build-essential \
        ufw \
        ca-certificates
    print_msg "Dependencies installed"
}

# Install Go
install_go() {
    print_step "Installing Go"
    
    if command -v go &> /dev/null; then
        INSTALLED_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        print_msg "Go is already installed (version: $INSTALLED_VERSION)"
        export PATH=$PATH:/usr/local/go/bin
        return
    fi

    cd /tmp
    wget -q --show-progress "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
    
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
    
    echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go.sh
    chmod +x /etc/profile.d/go.sh
    export PATH=$PATH:/usr/local/go/bin
    
    rm -f "go${GO_VERSION}.linux-amd64.tar.gz"
    
    print_msg "Go ${GO_VERSION} installed"
}

# Create application user
create_app_user() {
    print_step "Creating application user"
    
    if id "$APP_USER" &>/dev/null; then
        print_msg "User ${APP_USER} already exists"
        return
    fi

    useradd --system --no-create-home --shell /bin/false "$APP_USER"
    print_msg "User ${APP_USER} created"
}

# Create source files (embedded in script for one-liner support)
create_source_files() {
    print_step "Creating application files"
    
    mkdir -p "$APP_DIR/cache"
    mkdir -p "$APP_DIR/handlers"

    # go.mod
    cat > "$APP_DIR/go.mod" << 'GOMOD'
module proxy-server

go 1.21

require (
	github.com/gofiber/fiber/v2 v2.52.0
	github.com/joho/godotenv v1.5.1
	github.com/redis/go-redis/v9 v9.4.0
)

require (
	github.com/andybalholm/brotli v1.0.5 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/google/uuid v1.5.0 // indirect
	github.com/klauspost/compress v1.17.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.15 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasthttp v1.51.0 // indirect
	github.com/valyala/tcplisten v1.0.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
)
GOMOD

    # cache/redis.go
    cat > "$APP_DIR/cache/redis.go" << 'REDISGO'
package cache

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

type CachedResponse struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       []byte            `json:"body"`
}

type RedisClient struct {
	client *redis.Client
	ctx    context.Context
}

func NewRedisClient() *RedisClient {
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}

	redisPassword := os.Getenv("REDIS_PASSWORD")

	client := redis.NewClient(&redis.Options{
		Addr:         redisAddr,
		Password:     redisPassword,
		DB:           0,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolSize:     100,
		MinIdleConns: 10,
	})

	ctx := context.Background()

	_, err := client.Ping(ctx).Result()
	if err != nil {
		log.Printf("Warning: Redis connection failed: %v. Caching will be disabled.", err)
	} else {
		log.Println("Redis connection established")
	}

	return &RedisClient{client: client, ctx: ctx}
}

func (r *RedisClient) Get(key string) (*CachedResponse, error) {
	data, err := r.client.Get(r.ctx, key).Bytes()
	if err != nil {
		return nil, err
	}
	var response CachedResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

func (r *RedisClient) Set(key string, response *CachedResponse, ttl time.Duration) error {
	data, err := json.Marshal(response)
	if err != nil {
		return err
	}
	return r.client.Set(r.ctx, key, data, ttl).Err()
}

func (r *RedisClient) Close() error {
	return r.client.Close()
}

func (r *RedisClient) IsConnected() bool {
	_, err := r.client.Ping(r.ctx).Result()
	return err == nil
}
REDISGO

    # handlers/proxy.go
    cat > "$APP_DIR/handlers/proxy.go" << 'PROXYGO'
package handlers

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"proxy-server/cache"

	"github.com/gofiber/fiber/v2"
)

const (
	DefaultCacheTTL = 300
	RequestTimeout  = 30 * time.Second
)

type ProxyHandler struct {
	redis      *cache.RedisClient
	httpClient *http.Client
}

func NewProxyHandler(redis *cache.RedisClient) *ProxyHandler {
	return &ProxyHandler{
		redis: redis,
		httpClient: &http.Client{
			Timeout: RequestTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (h *ProxyHandler) Handle(c *fiber.Ctx) error {
	targetURL := c.Query("url")
	if targetURL == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "url parameter is required"})
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid url: must be http or https"})
	}

	cacheKey := c.Query("cache_key")
	cacheTTLStr := c.Query("cache_ttl")
	
	cacheTTL := DefaultCacheTTL
	if cacheTTLStr != "" {
		if ttl, err := strconv.Atoi(cacheTTLStr); err == nil && ttl > 0 {
			cacheTTL = ttl
		}
	}

	if cacheKey != "" && h.redis.IsConnected() {
		if cached, err := h.redis.Get(cacheKey); err == nil {
			log.Printf("Cache HIT for key: %s", cacheKey)
			for key, value := range cached.Headers {
				c.Set(key, value)
			}
			c.Set("X-Cache", "HIT")
			return c.Status(cached.StatusCode).Send(cached.Body)
		}
		log.Printf("Cache MISS for key: %s", cacheKey)
	}

	finalURL := h.buildTargetURL(targetURL, c)

	var req *http.Request
	method := c.Method()

	if method == fiber.MethodPost {
		req, err = http.NewRequest(method, finalURL, bytes.NewReader(c.Body()))
	} else {
		req, err = http.NewRequest(method, finalURL, nil)
	}

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create request"})
	}

	h.forwardRequestHeaders(c, req)

	resp, err := h.httpClient.Do(req)
	if err != nil {
		log.Printf("Proxy request failed: %v", err)
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "failed to reach target URL"})
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to read response"})
	}

	responseHeaders := make(map[string]string)
	headersToForward := []string{"Content-Type", "Content-Encoding", "Cache-Control", "ETag", "Last-Modified", "Expires"}

	for _, header := range headersToForward {
		if value := resp.Header.Get(header); value != "" {
			responseHeaders[header] = value
			c.Set(header, value)
		}
	}

	if cacheKey != "" && h.redis.IsConnected() {
		cachedResp := &cache.CachedResponse{StatusCode: resp.StatusCode, Headers: responseHeaders, Body: body}
		if err := h.redis.Set(cacheKey, cachedResp, time.Duration(cacheTTL)*time.Second); err != nil {
			log.Printf("Failed to cache response: %v", err)
		} else {
			log.Printf("Cached response for key: %s (TTL: %ds)", cacheKey, cacheTTL)
		}
	}

	c.Set("X-Cache", "MISS")
	return c.Status(resp.StatusCode).Send(body)
}

func (h *ProxyHandler) buildTargetURL(targetURL string, c *fiber.Ctx) string {
	parsedURL, _ := url.Parse(targetURL)
	query := parsedURL.Query()
	excludeParams := map[string]bool{"url": true, "cache_key": true, "cache_ttl": true}

	c.Request().URI().QueryArgs().VisitAll(func(key, value []byte) {
		keyStr := string(key)
		if !excludeParams[keyStr] {
			query.Add(keyStr, string(value))
		}
	})

	parsedURL.RawQuery = query.Encode()
	return parsedURL.String()
}

func (h *ProxyHandler) forwardRequestHeaders(c *fiber.Ctx, req *http.Request) {
	headersToForward := []string{"Content-Type", "Accept", "Accept-Language", "Accept-Encoding", "Authorization", "User-Agent", "X-Requested-With"}

	for _, header := range headersToForward {
		if value := c.Get(header); value != "" {
			req.Header.Set(header, value)
		}
	}

	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "ProxyServer/1.0")
	}

	clientIP := c.IP()
	if existing := c.Get("X-Forwarded-For"); existing != "" {
		req.Header.Set("X-Forwarded-For", existing+", "+clientIP)
	} else {
		req.Header.Set("X-Forwarded-For", clientIP)
	}

	proto := "http"
	if strings.HasPrefix(c.Protocol(), "https") {
		proto = "https"
	}
	req.Header.Set("X-Forwarded-Proto", proto)
}
PROXYGO

    # main.go
    cat > "$APP_DIR/main.go" << 'MAINGO'
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"proxy-server/cache"
	"proxy-server/handlers"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	redisClient := cache.NewRedisClient()
	defer redisClient.Close()

	app := fiber.New(fiber.Config{
		Prefork:       false,
		ServerHeader:  "ProxyServer",
		StrictRouting: false,
		CaseSensitive: false,
		BodyLimit:     10 * 1024 * 1024,
	})

	app.Use(recover.New())
	app.Use(logger.New(logger.Config{
		Format:     "${time} | ${status} | ${latency} | ${ip} | ${method} | ${path}\n",
		TimeFormat: "2006-01-02 15:04:05",
	}))
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowMethods: "GET,POST",
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
	}))

	proxyHandler := handlers.NewProxyHandler(redisClient)

	app.Get("/health", healthCheck(redisClient))
	app.Get("/proxy", proxyHandler.Handle)
	app.Post("/proxy", proxyHandler.Handle)

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		log.Println("Gracefully shutting down...")
		if err := app.Shutdown(); err != nil {
			log.Printf("Error during shutdown: %v", err)
		}
	}()

	log.Printf("Proxy server starting on port %s", port)
	if err := app.Listen(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func healthCheck(redis *cache.RedisClient) fiber.Handler {
	return func(c *fiber.Ctx) error {
		status := fiber.Map{"status": "healthy", "redis": "disconnected"}
		if redis.IsConnected() {
			status["redis"] = "connected"
		}
		return c.JSON(status)
	}
}
MAINGO

    # .env file (configure REDIS_ADDR for your shared instance)
    cat > "$APP_DIR/.env" << ENVFILE
PORT=${SERVICE_PORT}
REDIS_ADDR=your-redis-host:6379
REDIS_PASSWORD=
ENVFILE

    chown -R "$APP_USER":"$APP_USER" "$APP_DIR"
    print_msg "Application files created"
    print_warn "IMPORTANT: Update REDIS_ADDR in $APP_DIR/.env before starting"
}

# Copy local source files
copy_local_files() {
    print_step "Copying application files"
    
    mkdir -p "$APP_DIR"
    
    cp "$SCRIPT_DIR/go.mod" "$APP_DIR/"
    cp "$SCRIPT_DIR/go.sum" "$APP_DIR/" 2>/dev/null || true
    cp "$SCRIPT_DIR/main.go" "$APP_DIR/"
    cp -r "$SCRIPT_DIR/cache" "$APP_DIR/"
    cp -r "$SCRIPT_DIR/handlers" "$APP_DIR/"
    
    # Prefer .env if it exists, otherwise use env.example
    if [[ -f "$SCRIPT_DIR/.env" ]]; then
        cp "$SCRIPT_DIR/.env" "$APP_DIR/.env"
        print_msg "Copied .env configuration"
    elif [[ -f "$SCRIPT_DIR/env.example" ]]; then
        cp "$SCRIPT_DIR/env.example" "$APP_DIR/.env"
        print_warn "Copied env.example - update REDIS_ADDR in $APP_DIR/.env"
    else
        cat > "$APP_DIR/.env" << ENVFILE
PORT=${SERVICE_PORT}
REDIS_ADDR=your-redis-host:6379
REDIS_PASSWORD=
ENVFILE
        print_warn "Created default .env - update REDIS_ADDR in $APP_DIR/.env"
    fi
    
    chown -R "$APP_USER":"$APP_USER" "$APP_DIR"
    print_msg "Application files copied to ${APP_DIR}"
}

# Build the application
build_application() {
    print_step "Building application"
    
    cd "$APP_DIR"
    
    export PATH=$PATH:/usr/local/go/bin
    export GOCACHE=/tmp/go-cache
    export GOPATH=/tmp/go
    export HOME=/tmp
    
    go mod download
    CGO_ENABLED=0 go build -ldflags="-s -w" -o "${APP_NAME}" .
    
    chown "$APP_USER":"$APP_USER" "${APP_NAME}"
    chmod +x "${APP_NAME}"
    
    print_msg "Application built successfully"
}

# Create systemd service
create_systemd_service() {
    print_step "Creating systemd service"
    
    cat > "/etc/systemd/system/${APP_NAME}.service" << EOF
[Unit]
Description=Proxy Server API
After=network.target

[Service]
Type=simple
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${APP_DIR}
ExecStart=${APP_DIR}/${APP_NAME}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${APP_NAME}

EnvironmentFile=${APP_DIR}/.env

NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=${APP_DIR}

LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "${APP_NAME}"
    
    print_msg "Systemd service created"
}

# Configure firewall
configure_firewall() {
    print_step "Configuring firewall"
    
    ufw --force enable
    ufw allow ssh
    ufw allow "${SERVICE_PORT}/tcp"
    
    print_msg "Firewall configured (port ${SERVICE_PORT} opened)"
}

# Start the service
start_service() {
    print_step "Starting service"
    
    systemctl start "${APP_NAME}"
    
    sleep 3
    if systemctl is-active --quiet "${APP_NAME}"; then
        print_msg "${APP_NAME} service started successfully"
    else
        print_error "Failed to start ${APP_NAME} service"
        journalctl -u "${APP_NAME}" -n 20 --no-pager
        exit 1
    fi
}

# Verify installation
verify_installation() {
    print_step "Verifying installation"
    
    sleep 2
    
    if curl -s "http://localhost:${SERVICE_PORT}/health" | grep -q "healthy"; then
        print_msg "Health check passed"
    else
        print_warn "Health check failed - service may still be starting"
    fi
}

# Print summary
print_summary() {
    PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")
    
    echo ""
    echo -e "${GREEN}=============================================="
    echo -e "  Setup Complete!"
    echo -e "==============================================${NC}"
    echo ""
    echo "Your proxy server is now running!"
    echo ""
    echo -e "${BLUE}Endpoints:${NC}"
    echo "  Health:  http://${PUBLIC_IP}:${SERVICE_PORT}/health"
    echo "  Proxy:   http://${PUBLIC_IP}:${SERVICE_PORT}/proxy?url=<target>"
    echo ""
    echo -e "${BLUE}Quick Test:${NC}"
    echo "  curl 'http://localhost:${SERVICE_PORT}/health'"
    echo "  curl 'http://localhost:${SERVICE_PORT}/proxy?url=https://httpbin.org/get'"
    echo ""
    echo -e "${BLUE}With Caching:${NC}"
    echo "  curl 'http://localhost:${SERVICE_PORT}/proxy?url=https://api.example.com&cache_key=mykey&cache_ttl=60'"
    echo ""
    echo -e "${BLUE}Service Commands:${NC}"
    echo "  Logs:     journalctl -u ${APP_NAME} -f"
    echo "  Restart:  systemctl restart ${APP_NAME}"
    echo "  Stop:     systemctl stop ${APP_NAME}"
    echo "  Status:   systemctl status ${APP_NAME}"
    echo ""
    echo -e "${BLUE}Configure Redis:${NC}"
    echo "  Edit ${APP_DIR}/.env and set REDIS_ADDR to your shared Redis instance"
    echo "  Example: REDIS_ADDR=redis.example.com:6379"
    echo "  Then restart: systemctl restart ${APP_NAME}"
    echo ""
}

# Main installation function
main() {
    echo ""
    echo -e "${BLUE}=============================================="
    echo -e "  Proxy Server Setup"
    echo -e "==============================================${NC}"
    echo ""
    
    check_root
    detect_source
    update_system
    install_dependencies
    install_go
    create_app_user
    
    if [[ "$USE_LOCAL_FILES" == true ]]; then
        copy_local_files
    else
        create_source_files
    fi
    
    build_application
    create_systemd_service
    configure_firewall
    start_service
    verify_installation
    print_summary
}

# Run main function
main "$@"
