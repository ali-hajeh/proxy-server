package cache

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

// CachedResponse stores the response data in Redis
type CachedResponse struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       []byte            `json:"body"`
}

// RedisClient wraps the go-redis client
type RedisClient struct {
	client *redis.Client
	ctx    context.Context
}

// NewRedisClient creates a new Redis client connection
func NewRedisClient() *RedisClient {
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}

	redisPassword := os.Getenv("REDIS_PASSWORD")
	redisDB := 0

	client := redis.NewClient(&redis.Options{
		Addr:         redisAddr,
		Password:     redisPassword,
		DB:           redisDB,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolSize:     100,
		MinIdleConns: 10,
	})

	ctx := context.Background()

	// Test connection
	_, err := client.Ping(ctx).Result()
	if err != nil {
		log.Printf("Warning: Redis connection failed: %v. Caching will be disabled.", err)
	} else {
		log.Println("Redis connection established")
	}

	return &RedisClient{
		client: client,
		ctx:    ctx,
	}
}

// Get retrieves a cached response by key
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

// Set stores a response in cache with the specified TTL
func (r *RedisClient) Set(key string, response *CachedResponse, ttl time.Duration) error {
	data, err := json.Marshal(response)
	if err != nil {
		return err
	}

	return r.client.Set(r.ctx, key, data, ttl).Err()
}

// Close closes the Redis connection
func (r *RedisClient) Close() error {
	return r.client.Close()
}

// IsConnected checks if Redis is connected
func (r *RedisClient) IsConnected() bool {
	_, err := r.client.Ping(r.ctx).Result()
	return err == nil
}
