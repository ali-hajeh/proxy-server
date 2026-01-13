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
	// Load environment variables from .env file (optional)
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	// Initialize Redis client
	redisClient := cache.NewRedisClient()
	defer redisClient.Close()

	// Create Fiber app with optimized config
	app := fiber.New(fiber.Config{
		Prefork:       false, // Set to true for multi-process mode in production
		ServerHeader:  "ProxyServer",
		StrictRouting: false,
		CaseSensitive: false,
		BodyLimit:     10 * 1024 * 1024, // 10MB max body size
	})

	// Middleware
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

	// Initialize handlers
	proxyHandler := handlers.NewProxyHandler(redisClient)

	// Routes
	app.Get("/health", healthCheck(redisClient))
	app.Get("/proxy", proxyHandler.Handle)
	app.Post("/proxy", proxyHandler.Handle)

	// Get port from environment
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	// Graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		log.Println("Gracefully shutting down...")
		if err := app.Shutdown(); err != nil {
			log.Printf("Error during shutdown: %v", err)
		}
	}()

	// Start server
	log.Printf("Proxy server starting on port %s", port)
	if err := app.Listen(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	log.Println("Server stopped")
}

// healthCheck returns a health check handler
func healthCheck(redis *cache.RedisClient) fiber.Handler {
	return func(c *fiber.Ctx) error {
		status := fiber.Map{
			"status": "healthy",
			"redis":  "disconnected",
		}

		if redis.IsConnected() {
			status["redis"] = "connected"
		}

		return c.JSON(status)
	}
}
