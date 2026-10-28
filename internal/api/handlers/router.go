package handlers

import (
	_ "embed"
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/shorebird-server/internal/api/middleware"
	authpkg "github.com/shorebird-server/internal/auth"
	"github.com/shorebird-server/internal/db"
	"github.com/shorebird-server/internal/email"
	"github.com/shorebird-server/internal/storage"
)

//go:embed openapi.yaml
var openAPISpec []byte

// NewRouter creates the HTTP router with all API routes.
func NewRouter(authService *authpkg.Service, database db.Store, store storage.Store, mailer *email.Mailer, baseURL string, patchDelivery PatchDeliveryConfig) *chi.Mux {
	r := chi.NewRouter()
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)

	// CORS
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Version"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	// Initialize handlers
	authHandler := &AuthHandler{DB: database, AuthService: authService, Mailer: mailer, BaseURL: baseURL}
	userHandler := &UserHandler{DB: database, BaseURL: baseURL}
	appHandler := &AppHandler{DB: database}
	channelHandler := &ChannelHandler{DB: database}
	orgHandler := &OrganizationHandler{DB: database}
	releaseHandler := &ReleaseHandler{DB: database, Storage: store, BaseURL: baseURL}
	patchHandler := &PatchHandler{DB: database, Storage: store}
	metricsHandler := &MetricsHandler{DB: database}
	deviceHandler := &DeviceHandler{DB: database, Storage: store, PatchDelivery: patchDelivery}
	diagHandler := &DiagnosticsHandler{}
	adminHandler := &AdminHandler{DB: database}
	storageHandler := NewStorageHandler(store)

	// Auth middleware
	authMw := middleware.AuthMiddleware(authService, database)

	r.Get("/openapi.yaml", serveOpenAPISpec)
	r.Get("/api/v1/openapi.yaml", serveOpenAPISpec)

	// --- Local storage upload/download (used when STORAGE_DRIVER=local) ---
	r.Route("/storage", func(r chi.Router) {
		r.Post("/upload/{scope}/*", storageHandler.Upload)
		r.Get("/dl/{scope}/*", storageHandler.Download)
	})

	// --- Auth routes (no auth required) ---
	r.Route("/auth", func(r chi.Router) {
		r.Get("/login", authHandler.LoginPage)
		r.Post("/login", authHandler.LoginPage)
		r.Get("/public-settings", authHandler.PublicSettings)
		r.Post("/token", authHandler.Login)
		r.Post("/register", authHandler.Register)
		r.Post("/verify-email/request", authHandler.RequestVerificationEmail)
		r.Get("/verify-email", authHandler.VerifyEmail)
		r.Post("/password-reset/request", authHandler.RequestPasswordReset)
		r.Get("/password-reset", authHandler.PasswordResetPage)
		r.Post("/password-reset", authHandler.ResetPassword)
		r.Get("/sso/login", authHandler.SSOLogin)
		r.Get("/sso/callback", authHandler.SSOCallback)
		r.Post("/refresh", authHandler.Refresh)
	})

	// --- API v1 routes ---
	r.Route("/api/v1", func(r chi.Router) {
		// Public endpoints (no auth required - called by devices)
		r.Post("/patches/check", deviceHandler.PatchCheck)
		r.Post("/patches/events", deviceHandler.PatchEvents)

		// Authenticated endpoints
		r.Group(func(r chi.Router) {
			r.Use(authMw)

			// Users
			r.Get("/users/me", userHandler.GetCurrentUser)
			r.Patch("/users/me/password", userHandler.UpdatePassword)
			r.Post("/users", userHandler.CreateUser)

			// Organizations
			r.Get("/organizations", orgHandler.GetOrganizations)
			r.Post("/organizations", orgHandler.CreateOrganization)
			r.Get("/organizations/{orgId}/users", orgHandler.ListOrganizationUsers)
			r.Post("/organizations/{orgId}/users", orgHandler.AddOrganizationUser)

			// Apps
			r.Get("/apps", appHandler.GetApps)
			r.Get("/apps/{appId}", appHandler.GetApp)
			r.Post("/apps", appHandler.CreateApp)
			r.Delete("/apps/{appId}", appHandler.DeleteApp)
			r.Patch("/apps/{appId}/transfer", appHandler.TransferApp)
			r.Get("/apps/{appId}/metrics/active-hours", metricsHandler.GetActiveHours)
			r.Get("/apps/{appId}/metrics/unique-users", metricsHandler.GetUniqueUsers)
			r.Get("/apps/{appId}/metrics/version-distribution", metricsHandler.GetVersionDistribution)
			r.Get("/apps/{appId}/metrics/patch-adoption", metricsHandler.GetPatchAdoption)

			// Channels
			r.Get("/apps/{appId}/channels", channelHandler.GetChannels)
			r.Post("/apps/{appId}/channels", channelHandler.CreateChannel)

			// Releases
			r.Get("/apps/{appId}/releases", releaseHandler.GetReleases)
			r.Post("/apps/{appId}/releases", releaseHandler.CreateRelease)
			r.Patch("/apps/{appId}/releases/{releaseId}", releaseHandler.UpdateRelease)
			r.Delete("/apps/{appId}/releases/{releaseId}", releaseHandler.DeleteRelease)

			// Release artifacts
			r.Post("/apps/{appId}/releases/{releaseId}/artifacts", releaseHandler.CreateReleaseArtifact)
			r.Get("/apps/{appId}/releases/{releaseId}/artifacts", releaseHandler.GetReleaseArtifacts)

			// Patches
			r.Post("/apps/{appId}/patches", patchHandler.CreatePatch)
			r.Patch("/apps/{appId}/patches/{patchId}", patchHandler.UpdatePatch)

			// Patch artifacts
			r.Post("/apps/{appId}/patches/{patchId}/artifacts", patchHandler.CreatePatchArtifact)

			// Patch listing and promotion
			r.Get("/apps/{appId}/releases/{releaseId}/patches", patchHandler.GetPatches)
			r.Post("/apps/{appId}/patches/promote", patchHandler.PromotePatch)

			// Rollback
			r.Post("/apps/{appId}/releases/{releaseId}/patches/{patchId}/rollback", patchHandler.RollbackPatch)
			r.Post("/apps/{appId}/releases/{releaseId}/patches/{patchId}/rollforward", patchHandler.RollforwardPatch)
			r.Post("/apps/{appId}/patches/rollback", deviceHandler.RollbackPatch)

			// Diagnostics
			r.Get("/diagnostics/gcp_upload", diagHandler.GCPUploadSpeedTest)
			r.Get("/diagnostics/gcp_download", diagHandler.GCPDownloadSpeedTest)

			// Admin: user listing
			r.Get("/admin/users", adminHandler.ListUsers)
			r.Post("/admin/users/{userId}/verify-email", adminHandler.VerifyUserEmail)
			r.Post("/admin/users/{userId}/admin", adminHandler.SetUserAdmin)
			r.Get("/admin/settings", adminHandler.GetSettings)
			r.Put("/admin/settings", adminHandler.UpdateSettings)

			// Admin: targeted device patching
			r.Post("/admin/patches/{patchId}/target-devices", adminHandler.AddTargetDevice)
			r.Delete("/admin/patches/{patchId}/target-devices/{clientId}", adminHandler.RemoveTargetDevice)
			r.Get("/admin/patches/{patchId}/target-devices", adminHandler.GetTargetDevices)
			r.Get("/admin/apps/{appId}/events", adminHandler.GetPatchEvents)
		})
	})

	// --- Static files: Web UI ---
	webDir := findWebDir()
	if webDir != "" {
		fileServer := http.FileServer(http.Dir(webDir))
		r.Handle("/web/*", http.StripPrefix("/web/", fileServer))

		// Catch-all: serve the SPA index.html for the dashboard
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, filepath.Join(webDir, "index.html"))
		})
		r.Get("/dashboard", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, filepath.Join(webDir, "index.html"))
		})
	}

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		backend := map[string]string{
			"storage":  "local",
			"database": "sqlite",
		}
		if _, ok := store.(interface{ BackendName() string }); ok {
			backend["storage"] = store.BackendName()
		}
		// Determine DB backend from the store interface
		switch database.(type) {
		case interface{ DriverName() string }:
			// If PgStore has DriverName method
			backend["database"] = "postgres"
		default:
			backend["database"] = "sqlite"
		}
		w.Write([]byte(`{"status":"ok","backend":{"storage":"` + backend["storage"] + `","database":"` + backend["database"] + `"}}`))
	})

	return r
}

func serveOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(openAPISpec)
}

// findWebDir locates the web/ directory. It searches relative to the
// binary and from common workspace paths so that the dashboard works
// in local development as well as in the Docker image.
func findWebDir() string {
	candidates := []string{
		"web",
		"../../web",
		filepath.Join("..", "web"),
	}
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, "web"))
	}
	// Also check relative to the executable
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "web"))
	}
	for _, p := range candidates {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			return p
		}
	}
	return ""
}
