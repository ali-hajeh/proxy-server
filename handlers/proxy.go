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
	DefaultCacheTTL = 300 // 5 minutes in seconds
	RequestTimeout  = 30 * time.Second
)

// ProxyHandler handles proxy requests with caching
type ProxyHandler struct {
	redis      *cache.RedisClient
	httpClient *http.Client
}

// NewProxyHandler creates a new proxy handler
func NewProxyHandler(redis *cache.RedisClient) *ProxyHandler {
	return &ProxyHandler{
		redis: redis,
		httpClient: &http.Client{
			Timeout: RequestTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects automatically
			},
		},
	}
}

// Handle processes GET and POST proxy requests
func (h *ProxyHandler) Handle(c *fiber.Ctx) error {
	// Get required URL parameter
	targetURL := c.Query("url")
	if targetURL == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "url parameter is required",
		})
	}

	// Validate URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid url: must be http or https",
		})
	}

	// Get optional cache parameters
	cacheKey := c.Query("cache_key")
	cacheTTLStr := c.Query("cache_ttl")
	
	cacheTTL := DefaultCacheTTL
	if cacheTTLStr != "" {
		if ttl, err := strconv.Atoi(cacheTTLStr); err == nil && ttl > 0 {
			cacheTTL = ttl
		}
	}

	// Check cache if cache_key is provided
	if cacheKey != "" && h.redis.IsConnected() {
		if cached, err := h.redis.Get(cacheKey); err == nil {
			log.Printf("Cache HIT for key: %s", cacheKey)
			
			// Set cached headers
			for key, value := range cached.Headers {
				c.Set(key, value)
			}
			c.Set("X-Cache", "HIT")
			
			return c.Status(cached.StatusCode).Send(cached.Body)
		}
		log.Printf("Cache MISS for key: %s", cacheKey)
	}

	// Build the target URL with forwarded query params
	finalURL := h.buildTargetURL(targetURL, c)

	// Create the proxy request
	var req *http.Request
	method := c.Method()

	if method == fiber.MethodPost {
		req, err = http.NewRequest(method, finalURL, bytes.NewReader(c.Body()))
	} else {
		req, err = http.NewRequest(method, finalURL, nil)
	}

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to create request",
		})
	}

	// Forward relevant headers
	h.forwardRequestHeaders(c, req)

	// Execute the request
	resp, err := h.httpClient.Do(req)
	if err != nil {
		log.Printf("Proxy request failed: %v", err)
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"error": "failed to reach target URL",
		})
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to read response",
		})
	}

	// Collect response headers
	responseHeaders := make(map[string]string)
	headersToForward := []string{
		"Content-Type",
		"Content-Encoding",
		"Cache-Control",
		"ETag",
		"Last-Modified",
		"Expires",
	}

	for _, header := range headersToForward {
		if value := resp.Header.Get(header); value != "" {
			responseHeaders[header] = value
			c.Set(header, value)
		}
	}

	// Cache the response if cache_key is provided
	if cacheKey != "" && h.redis.IsConnected() {
		cachedResp := &cache.CachedResponse{
			StatusCode: resp.StatusCode,
			Headers:    responseHeaders,
			Body:       body,
		}
		
		if err := h.redis.Set(cacheKey, cachedResp, time.Duration(cacheTTL)*time.Second); err != nil {
			log.Printf("Failed to cache response: %v", err)
		} else {
			log.Printf("Cached response for key: %s (TTL: %ds)", cacheKey, cacheTTL)
		}
	}

	c.Set("X-Cache", "MISS")
	return c.Status(resp.StatusCode).Send(body)
}

// buildTargetURL constructs the final URL with query params (excluding proxy params)
func (h *ProxyHandler) buildTargetURL(targetURL string, c *fiber.Ctx) string {
	parsedURL, _ := url.Parse(targetURL)
	
	// Get existing query params from target URL
	query := parsedURL.Query()
	
	// Add query params from request (except our proxy params)
	excludeParams := map[string]bool{
		"url":       true,
		"cache_key": true,
		"cache_ttl": true,
	}

	c.Request().URI().QueryArgs().VisitAll(func(key, value []byte) {
		keyStr := string(key)
		if !excludeParams[keyStr] {
			query.Add(keyStr, string(value))
		}
	})

	parsedURL.RawQuery = query.Encode()
	return parsedURL.String()
}

// forwardRequestHeaders copies relevant headers from the incoming request
func (h *ProxyHandler) forwardRequestHeaders(c *fiber.Ctx, req *http.Request) {
	headersToForward := []string{
		"Content-Type",
		"Accept",
		"Accept-Language",
		"Accept-Encoding",
		"Authorization",
		"User-Agent",
		"X-Requested-With",
	}

	for _, header := range headersToForward {
		if value := c.Get(header); value != "" {
			req.Header.Set(header, value)
		}
	}

	// Set a default User-Agent if not provided
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "ProxyServer/1.0")
	}

	// Forward X-Forwarded headers
	clientIP := c.IP()
	if existing := c.Get("X-Forwarded-For"); existing != "" {
		req.Header.Set("X-Forwarded-For", existing+", "+clientIP)
	} else {
		req.Header.Set("X-Forwarded-For", clientIP)
	}

	// Set X-Forwarded-Proto
	proto := "http"
	if strings.HasPrefix(c.Protocol(), "https") {
		proto = "https"
	}
	req.Header.Set("X-Forwarded-Proto", proto)
}
