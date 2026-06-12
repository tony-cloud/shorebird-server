package config

import (
	"os"
	"time"
)

// Config holds all configuration for the Shorebird server.
type Config struct {
	Server  ServerConfig
	DB      DBConfig
	Storage StorageConfig
	Auth    AuthConfig
	Email   EmailConfig
	Admin   AdminConfig
	Redis   RedisConfig
}

// ServerConfig holds HTTP server configuration.
type ServerConfig struct {
	Host         string
	Port         string
	BaseURL      string // public-facing URL, used for download links
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// DBConfig holds database configuration.
type DBConfig struct {
	// Driver is "postgres" or "sqlite". Empty defaults to "sqlite".
	Driver string
	// URL is the PostgreSQL connection string (used when driver=postgres).
	URL string
	// Path is the SQLite database file path (used when driver=sqlite).
	Path string
}

// StorageConfig holds object storage configuration.
type StorageConfig struct {
	// Driver is "local" or "s3". Empty defaults to "local".
	Driver string

	// Local settings
	LocalDir string

	// S3/MinIO settings
	S3Endpoint      string
	S3AccessKey     string
	S3SecretKey     string
	S3UseSSL        bool
	S3ReleaseBucket string
	S3PatchBucket   string
}

// AuthConfig holds JWT authentication configuration.
type AuthConfig struct {
	JWTSecret     string
	TokenDuration time.Duration
}

// EmailConfig holds SMTP configuration for account emails.
type EmailConfig struct {
	Host     string
	Port     string
	Username string
	Password string
	From     string
}

// AdminConfig holds bootstrap admin configuration.
type AdminConfig struct {
	Email    string
	Password string
	Name     string
}

// RedisConfig holds Redis connection configuration.
type RedisConfig struct {
	Addr     string
	Password string
	DB       int
}

// Load reads configuration from environment variables with sensible defaults.
func Load() *Config {
	port := envOrDefault("SERVER_PORT", "8080")
	baseURL := envOrDefault("SERVER_BASE_URL", "http://localhost:"+port)

	return &Config{
		Server: ServerConfig{
			Host:         envOrDefault("SERVER_HOST", "0.0.0.0"),
			Port:         port,
			BaseURL:      baseURL,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 30 * time.Second,
		},
		DB: DBConfig{
			Driver: envOrDefault("DB_DRIVER", "sqlite"),
			URL:    envOrDefault("DATABASE_URL", "postgres://shorebird:shorebird@localhost:5432/shorebird?sslmode=disable"),
			Path:   envOrDefault("DB_PATH", "data/shorebird.db"),
		},
		Storage: StorageConfig{
			Driver:          envOrDefault("STORAGE_DRIVER", "local"),
			LocalDir:        envOrDefault("STORAGE_LOCAL_DIR", "data/storage"),
			S3Endpoint:      envOrDefault("STORAGE_S3_ENDPOINT", "localhost:9000"),
			S3AccessKey:     envOrDefault("STORAGE_S3_ACCESS_KEY", "minioadmin"),
			S3SecretKey:     envOrDefault("STORAGE_S3_SECRET_KEY", "minioadmin"),
			S3UseSSL:        os.Getenv("STORAGE_S3_USE_SSL") == "true",
			S3ReleaseBucket: envOrDefault("STORAGE_S3_RELEASE_BUCKET", "shorebird-releases"),
			S3PatchBucket:   envOrDefault("STORAGE_S3_PATCH_BUCKET", "shorebird-patches"),
		},
		Auth: AuthConfig{
			JWTSecret:     envOrDefault("JWT_SECRET", "change-me-in-production-use-a-long-random-string"),
			TokenDuration: 24 * time.Hour,
		},
		Email: EmailConfig{
			Host:     envOrDefault("SMTP_HOST", ""),
			Port:     envOrDefault("SMTP_PORT", "587"),
			Username: envOrDefault("SMTP_USERNAME", ""),
			Password: envOrDefault("SMTP_PASSWORD", ""),
			From:     envOrDefault("SMTP_FROM", "shorebird@localhost"),
		},
		Admin: AdminConfig{
			Email:    envOrDefault("DEFAULT_ADMIN_EMAIL", "admin@example.com"),
			Password: envOrDefault("DEFAULT_ADMIN_PASSWORD", "admin123"),
			Name:     envOrDefault("DEFAULT_ADMIN_NAME", "Administrator"),
		},
		Redis: RedisConfig{
			Addr:     envOrDefault("REDIS_ADDR", "localhost:6379"),
			Password: envOrDefault("REDIS_PASSWORD", ""),
			DB:       0,
		},
	}
}

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
