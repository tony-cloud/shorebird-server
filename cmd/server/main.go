package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shorebird-server/internal/api/handlers"
	"github.com/shorebird-server/internal/artifactgateway"
	"github.com/shorebird-server/internal/auth"
	"github.com/shorebird-server/internal/config"
	"github.com/shorebird-server/internal/db"
	"github.com/shorebird-server/internal/email"
	"github.com/shorebird-server/internal/storage"
	"github.com/shorebird-server/internal/updater"
	"github.com/shorebird-server/internal/version"
)

func main() { os.Exit(run()) }

func run() int {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		// Exits before reading configuration: the updater probes staged
		// images with it.
		fmt.Println(version.Current())
		return 0
	}
	cfg := config.Load()
	su := resolveSelfUpdate(cfg)
	if su.plan.Mode == updater.ModeActive && !updater.IsSupervised() {
		return runSupervisor(cfg, su)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return runChild(ctx, cfg, su)
}

// coreEnv is what the core needs from the process.
type coreEnv struct {
	cfg        *config.Config
	su         selfUpdate
	service    *updater.Service
	auditor    updater.Auditor
	restart    chan struct{}
	supervised bool
	onReady    func()
}

// runCore starts the core services and serves them until shutdown. A startup
// condition that keeps the core from running is returned as a failure; the
// caller then decides between exiting and maintenance.
func runCore(ctx context.Context, env *coreEnv) (exitCode int, fail *startupFailure) {
	cfg := env.cfg
	var signingMasterKey []byte
	if cfg.Signing.MasterKey != "" {
		var err error
		signingMasterKey, err = base64.StdEncoding.DecodeString(cfg.Signing.MasterKey)
		if err != nil || len(signingMasterKey) != 32 {
			return 0, operatorFailure("SIGNING_KEY_INVALID", "config", "Set PATCH_SIGNING_MASTER_KEY to base64-encoded 32 random bytes and restart the service", nil)
		}
	}

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
		return 0, transientFailure("DATABASE_UNAVAILABLE", "database", "Start the database or fix DB_DRIVER/DATABASE_URL/DB_PATH", err)
	}
	defer database.Close()
	log.Printf("Database: %s (%s)", cfg.DB.Driver, cfg.DB.Path)

	adminHash, err := auth.HashPassword(cfg.Admin.Password)
	if err != nil {
		return 0, operatorFailure("ADMIN_BOOTSTRAP_FAILED", "database", "Fix DEFAULT_ADMIN_PASSWORD and restart the service", err)
	}
	createdAdmin, err := database.EnsureDefaultAdmin(ctx, cfg.Admin.Email, cfg.Admin.Name, adminHash)
	if err != nil {
		return 0, transientFailure("DATABASE_INIT_FAILED", "database", "Check the database (permissions, disk space, migrations) or upload a fixed signed update", err)
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
		UploadSecret:    cfg.Auth.JWTSecret,
		S3Endpoint:      cfg.Storage.S3Endpoint,
		S3AccessKey:     cfg.Storage.S3AccessKey,
		S3SecretKey:     cfg.Storage.S3SecretKey,
		S3UseSSL:        cfg.Storage.S3UseSSL,
		S3ReleaseBucket: cfg.Storage.S3ReleaseBucket,
		S3PatchBucket:   cfg.Storage.S3PatchBucket,
	})
	if err != nil {
		return 0, transientFailure("STORAGE_UNAVAILABLE", "storage", "Start the object store or fix STORAGE_DRIVER/STORAGE_* settings", err)
	}
	log.Printf("Storage: %s", store.BackendName())

	// --- Router ---
	router := handlers.NewRouterWithOptions(authService, database, store, mailer, cfg.Server.BaseURL, handlers.PatchDeliveryConfig{
		EncryptionMode:        cfg.PatchDelivery.EncryptionMode,
		AESSecret:             []byte(cfg.PatchDelivery.AESSecret),
		CacheEncryptedPatches: cfg.PatchDelivery.CacheEncryptedPatches,
	}, handlers.RouterOptions{
		Signing:      handlers.SigningConfig{MasterKey: signingMasterKey},
		ServerUpdate: &handlers.ServerUpdateHandler{DB: database, Service: env.service, Auditor: env.auditor},
	})

	handler, err := artifactgateway.Wrap(router, os.Getenv("SHOREBIRD_ARTIFACTS_DIR"), os.Getenv("ARTIFACT_PROXY_UPSTREAM"))
	if err != nil {
		return 0, operatorFailure("ARTIFACT_CONFIG_INVALID", "config", "Fix SHOREBIRD_ARTIFACTS_DIR/ARTIFACT_PROXY_UPSTREAM and restart the service", err)
	}

	// --- HTTP Server ---
	addr := fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  60 * time.Second,
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return 0, transientFailure("LISTEN_FAILED", "listen", "Stop the process holding the port or fix SERVER_HOST/SERVER_PORT", err)
	}
	serverFailed := make(chan struct{}, 1)
	go func() {
		log.Printf("Shorebird server %s starting on %s", version.Current(), addr)
		log.Printf("  Dashboard: http://%s", addr)
		log.Printf("  API:       http://%s/api/v1", addr)
		log.Printf("  Auth:      http://%s/auth", addr)
		log.Printf("  Storage:   %s", store.BackendName())
		log.Printf("  Database:  %s", cfg.DB.Driver)
		log.Printf("  Self-update: %s", describeMode(env.service.Status()))
		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server stopped: %v", err)
			select {
			case serverFailed <- struct{}{}:
			default:
			}
		}
	}()

	stopping := make(chan struct{}, 1)
	ready := make(chan struct{})
	heartbeatCtx, heartbeatCancel := context.WithCancel(context.Background())
	defer heartbeatCancel()
	if env.supervised {
		healthURL := "http://" + loopbackAddr(listener.Addr()) + "/health"
		probe := func(ctx context.Context) error { return probeHealth(ctx, healthURL, database) }
		go updater.Heartbeat(heartbeatCtx, probe, version.Current(), func() {
			select {
			case stopping <- struct{}{}:
			default:
			}
		}, func() { close(ready) })
	} else {
		close(ready)
	}

	// Never replace another binary before this image acknowledged a healthy start.
	waiting := true
	for waiting {
		select {
		case <-ready:
			if env.onReady != nil {
				env.onReady()
			}
			env.service.Start()
			ready = nil
			continue
		case <-ctx.Done():
		case <-stopping:
		case <-serverFailed:
			exitCode = 1
		case <-env.restart:
			log.Print("Self-update: restarting into the new image")
			exitCode = updater.UpdateExitCode
		}
		waiting = false
	}
	heartbeatCancel()
	env.service.Close()

	log.Println("Shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("Shutdown error: %v", err)
		_ = srv.Close()
	}
	log.Println("Server stopped")
	return exitCode, nil
}

func loopbackAddr(addr net.Addr) string {
	host, port, _ := net.SplitHostPort(addr.String())
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return net.JoinHostPort(host, port)
}

// probeHealth is the supervisor heartbeat: the HTTP health route answers and
// the database responds.
func probeHealth(ctx context.Context, url string, database db.Store) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health status %d", resp.StatusCode)
	}
	if pinger, ok := database.(interface{ Ping(context.Context) error }); ok {
		return pinger.Ping(ctx)
	}
	return nil
}

func describeMode(status updater.Status) string {
	switch status.Mode {
	case updater.ModeManagedExternally:
		return "managed externally (" + status.ManagedBy + "); update the image instead"
	case updater.ModeUnavailable, updater.ModeDisabled:
		return status.Mode + " (" + status.UnavailableReason + ")"
	}
	return fmt.Sprintf("active, channel %s, automatic %t", status.Channel, status.AutoUpdate)
}
