# Proxy Server API

A high-performance proxy API service built with Go and Fiber framework, featuring Redis caching support.

## Features

- **Fast**: Built with Fiber (10x faster than Express.js)
- **Redis Caching**: Optional response caching with custom TTL
- **GET & POST Support**: Proxies both GET and POST requests
- **Header Forwarding**: Forwards relevant headers in both directions
- **Graceful Shutdown**: Clean shutdown handling
- **Health Check**: Built-in health endpoint with Redis status

## Quick Start

### Prerequisites

- Go 1.21+
- Redis server (optional, caching disabled if unavailable)

### Local Development

```bash
# Clone and navigate to the project
cd proxy-server

# Copy environment config
cp env.example .env

# Download dependencies
go mod download

# Run the server
go run main.go
```

### Build Binary

```bash
go build -o proxy-server .
./proxy-server
```

## Configuration

Environment variables (set in `.env` or system environment):

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Server port |
| `REDIS_ADDR` | `localhost:6379` | Redis server address |
| `REDIS_PASSWORD` | (empty) | Redis password (if required) |
| `SCRAPE_DO_TOKEN` | (empty) | Scrape.do API token for advanced proxy |

## API Reference

### Health Check

```
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "redis": "connected"
}
```

### Proxy Request

```
GET  /proxy?url=<target>&cache_key=<key>&cache_ttl=<seconds>
POST /proxy?url=<target>&cache_key=<key>&cache_ttl=<seconds>
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `url` | query | **Yes** | Target URL to proxy (must be http/https) |
| `cache_key` | query | No | Custom cache key. **Caching is skipped if not provided** |
| `cache_ttl` | query | No | Cache TTL in seconds (default: 300) |
| `useAdvancedProxy` | query | No | Set to `true` to route through scrape.do (min cache: 1 day) |

#### Additional Query Parameters

Any query parameters besides `url`, `cache_key`, and `cache_ttl` are forwarded to the target URL.

## Request Handling

### GET Requests

- Query parameters (except proxy params) are forwarded to the target URL
- Headers like `Accept`, `Authorization`, `User-Agent` are forwarded
- Response body and relevant headers are returned to the client

**Example:**
```bash
curl "http://localhost:3000/proxy?url=https://api.github.com/users/octocat"
```

### POST Requests

- Request body is forwarded as-is to the target URL
- `Content-Type` header is forwarded (JSON, form data, etc.)
- Query parameters work the same as GET requests

**Example:**
```bash
# JSON POST
curl -X POST "http://localhost:3000/proxy?url=https://httpbin.org/post" \
  -H "Content-Type: application/json" \
  -d '{"name": "test", "value": 123}'

# Form POST
curl -X POST "http://localhost:3000/proxy?url=https://httpbin.org/post" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=test&value=123"
```

### Headers Forwarded

**Request headers forwarded to target:**
- `Content-Type`
- `Accept`
- `Accept-Language`
- `Accept-Encoding`
- `Authorization`
- `User-Agent`
- `X-Requested-With`
- `X-Forwarded-For` (client IP appended)
- `X-Forwarded-Proto`

**Response headers returned to client:**
- `Content-Type`
- `Content-Encoding`
- `Cache-Control`
- `ETag`
- `Last-Modified`
- `Expires`
- `X-Cache` (HIT or MISS)
- `X-Advanced-Proxy` (true or false)

## Advanced Proxy (Scrape.do)

For URLs that require anti-bot bypass or residential proxies, use the `useAdvancedProxy` parameter to route requests through [scrape.do](https://scrape.do).

**Requirements:**
- Set `SCRAPE_DO_TOKEN` environment variable with your API token

**Behavior:**
- Requests are routed through scrape.do's proxy network
- **Minimum cache TTL is enforced to 1 day (86400 seconds)** to optimize API usage
- Headers are handled by scrape.do (not forwarded from client)

**Example:**
```bash
# Route through advanced proxy (cache enforced to 1 day minimum)
curl "http://localhost:3000/proxy?url=https://example.com/api&useAdvancedProxy=true&cache_key=example-api"
```

## Caching Behavior

Caching only occurs when `cache_key` is provided:

| Scenario | Behavior |
|----------|----------|
| No `cache_key` | Request goes directly to target, no caching |
| `cache_key` provided, cache hit | Returns cached response with `X-Cache: HIT` |
| `cache_key` provided, cache miss | Fetches from target, stores in cache, returns with `X-Cache: MISS` |
| Redis unavailable | Works normally, caching silently disabled |

**Example with caching:**
```bash
# First request - cache miss
curl "http://localhost:3000/proxy?url=https://api.github.com&cache_key=github&cache_ttl=60"
# Response header: X-Cache: MISS

# Second request within 60s - cache hit
curl "http://localhost:3000/proxy?url=https://api.github.com&cache_key=github"
# Response header: X-Cache: HIT
```

## Ubuntu Server Deployment

A complete setup script is included for Ubuntu servers:

```bash
# Make executable
chmod +x setup.sh

# Run as root (installs Go, Redis, creates systemd service)
sudo ./setup.sh
```

### What the script does:

1. Updates system packages
2. Installs Go 1.21.6
3. Installs and configures Redis
4. Creates a `proxyserver` system user
5. Copies app to `/opt/proxy-server`
6. Builds the application
7. Creates a systemd service
8. Configures UFW firewall (opens port 3000)
9. Starts the service

### Managing the Service

```bash
# View logs
journalctl -u proxy-server -f

# Restart
sudo systemctl restart proxy-server

# Stop
sudo systemctl stop proxy-server

# Status
sudo systemctl status proxy-server

# Edit config
sudo nano /opt/proxy-server/.env
sudo systemctl restart proxy-server
```

## Error Responses

| Status | Description |
|--------|-------------|
| 400 | Missing `url` parameter or invalid URL |
| 502 | Failed to reach target URL |
| 500 | Internal server error |

**Error format:**
```json
{
  "error": "error message here"
}
```

## Performance

- Built with Fiber (fasthttp under the hood)
- Connection pooling for outbound requests
- Redis connection pooling (100 connections, 10 idle)
- 30 second request timeout
- 10MB max request body size

## License

MIT
