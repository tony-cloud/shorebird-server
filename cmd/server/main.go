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
	"github.com/shorebird-server/internal/email"
	"github.com/shorebird-server/internal/storage"
)

func main() {
	cfg := config.Load()
	ctx := context.Background()

	// --- Database ---
	var dsn string
	switch cfg.DB.Driver {
	case "postgres", "postgresql", "pg":
		dsn = cfg.DB.URL
	default:
		dsn = cfg.DB.Path
	}
	database, err := db.NewStore(ctx, cfg.DB.Driver, dsn)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer database.Close()
	log.Printf("Database: %s (%s)", cfg.DB.Driver, cfg.DB.Path)

	adminHash, err := auth.HashPassword(cfg.Admin.Password)
	if err != nil {
		log.Fatalf("Failed to hash default admin password: %v", err)
	}
	createdAdmin, err := database.EnsureDefaultAdmin(ctx, cfg.Admin.Email, cfg.Admin.Name, adminHash)
	if err != nil {
		log.Fatalf("Failed to ensure default admin account: %v", err)
	}
	if createdAdmin {
		log.Printf("Created default admin account %s with default password; password change required at first login", cfg.Admin.Email)
	}

	// --- Auth ---
	authService := auth.NewService(cfg.Auth.JWTSecret, cfg.Auth.TokenDuration)
	mailer := email.NewMailer(email.Config{
		Host:     cfg.Email.Host,
		Port:     cfg.Email.Port,
		Username: cfg.Email.Username,
		Password: cfg.Email.Password,
		From:     cfg.Email.From,
	})

	// --- Storage ---
	store, err := storage.NewStore(storage.Config{
		Type:            cfg.Storage.Driver,
		LocalDir:        cfg.Storage.LocalDir,
		ServerBaseURL:   cfg.Server.BaseURL,
		S3Endpoint:      cfg.Storage.S3Endpoint,
		S3AccessKey:     cfg.Storage.S3AccessKey,
		S3SecretKey:     cfg.Storage.S3SecretKey,
		S3UseSSL:        cfg.Storage.S3UseSSL,
		S3ReleaseBucket: cfg.Storage.S3ReleaseBucket,
		S3PatchBucket:   cfg.Storage.S3PatchBucket,
	})
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}
	log.Printf("Storage: %s", store.BackendName())

	// --- Router ---
	router := handlers.NewRouter(authService, database, store, mailer, cfg.Server.BaseURL)

	// --- HTTP Server ---
	addr := fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("Shorebird server starting on %s", addr)
		log.Printf("  Dashboard: http://%s", addr)
		log.Printf("  API:       http://%s/api/v1", addr)
		log.Printf("  Auth:      http://%s/auth", addr)
		log.Printf("  Storage:   %s", store.BackendName())
		log.Printf("  Database:  %s", cfg.DB.Driver)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Shutdown error: %v", err)
	}
	log.Println("Server stopped")
}
