package config

import (
	"os"
	"time"
)

// Config holds all configuration for the Shorebird server.
type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Storage  StorageConfig
	Auth     AuthConfig
	Redis    RedisConfig
}

// ServerConfig holds HTTP server configuration.
type ServerConfig struct {
	Host         string
	Port         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// DatabaseConfig holds PostgreSQL connection configuration.
type DatabaseConfig struct {
	URL string
}

// StorageConfig holds object storage (S3/MinIO) configuration.
type StorageConfig struct {
	Endpoint        string
	AccessKeyID     string
	SecretAccessKey string
	UseSSL          bool
	ReleaseBucket   string
	PatchBucket     string
}

// AuthConfig holds JWT authentication configuration.
type AuthConfig struct {
	JWTSecret     string
	TokenDuration time.Duration
}

// RedisConfig holds Redis connection configuration.
type RedisConfig struct {
	Addr     string
	Password string
	DB       int
}

// Load reads configuration from environment variables with sensible defaults.
func Load() *Config {
	return &Config{
		Server: ServerConfig{
			Host:         envOrDefault("SERVER_HOST", "0.0.0.0"),
			Port:         envOrDefault("SERVER_PORT", "8080"),
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 30 * time.Second,
		},
		Database: DatabaseConfig{
			URL: envOrDefault("DATABASE_URL", "postgres://shorebird:shorebird@localhost:5432/shorebird?sslmode=disable"),
		},
		Storage: StorageConfig{
			Endpoint:        envOrDefault("STORAGE_ENDPOINT", "localhost:9000"),
			AccessKeyID:     envOrDefault("STORAGE_ACCESS_KEY", "minioadmin"),
			SecretAccessKey: envOrDefault("STORAGE_SECRET_KEY", "minioadmin"),
			UseSSL:          false,
			ReleaseBucket:   envOrDefault("STORAGE_RELEASE_BUCKET", "shorebird-releases"),
			PatchBucket:     envOrDefault("STORAGE_PATCH_BUCKET", "shorebird-patches"),
		},
		Auth: AuthConfig{
			JWTSecret:     envOrDefault("JWT_SECRET", "change-me-in-production-use-a-long-random-string"),
			TokenDuration: 24 * time.Hour,
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
