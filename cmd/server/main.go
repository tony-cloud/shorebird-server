package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shorebird-server/internal/api/handlers"
	"github.com/shorebird-server/internal/auth"
	"github.com/shorebird-server/internal/config"
	"github.com/shorebird-server/internal/db"
	"github.com/shorebird-server/internal/storage"
)

func main() {
	// Load configuration
	cfg := config.Load()

	// Initialize database
	ctx := context.Background()
	database, err := db.New(ctx, cfg.Database.URL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer database.Close()
	log.Println("Connected to PostgreSQL")

	// Initialize auth service
	authService := auth.NewService(cfg.Auth.JWTSecret, cfg.Auth.TokenDuration)
	log.Println("Auth service initialized")

	// Initialize storage service
	store, err := storage.NewService(
		cfg.Storage.Endpoint,
		cfg.Storage.AccessKeyID,
		cfg.Storage.SecretAccessKey,
		cfg.Storage.ReleaseBucket,
		cfg.Storage.PatchBucket,
		cfg.Storage.UseSSL,
	)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}
	log.Println("Storage service initialized")

	// Create router
	router := handlers.NewRouter(authService, database, store)

	// Configure HTTP server
	addr := fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Printf("Shorebird self-hosted server starting on %s", addr)
		log.Printf("API: http://%s/api/v1", addr)
		log.Printf("Auth: http://%s/auth", addr)
		log.Printf("Health: http://%s/health", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server stopped")
}
