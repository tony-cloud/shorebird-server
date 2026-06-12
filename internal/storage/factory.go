package storage

import "fmt"

// Config holds common storage configuration used by the factory.
type Config struct {
	// Type is "local" or "s3". Empty defaults to "local".
	Type string

	// Local settings
	LocalDir        string
	ServerBaseURL   string

	// S3 settings
	S3Endpoint        string
	S3AccessKey       string
	S3SecretKey       string
	S3UseSSL          bool
	S3ReleaseBucket   string
	S3PatchBucket     string
}

// NewStore creates the appropriate Store backend based on Config.Type.
func NewStore(cfg Config) (Store, error) {
	switch cfg.Type {
	case "s3", "minio":
		return NewS3Store(
			cfg.S3Endpoint, cfg.S3AccessKey, cfg.S3SecretKey,
			cfg.S3ReleaseBucket, cfg.S3PatchBucket, cfg.S3UseSSL,
		)
	default:
		if cfg.Type != "" && cfg.Type != "local" {
			fmt.Printf("storage: unknown type %q, falling back to local\n", cfg.Type)
		}
		return NewLocalStore(cfg.LocalDir, cfg.ServerBaseURL)
	}
}
