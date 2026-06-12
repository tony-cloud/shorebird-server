package db

import (
	"context"
	"fmt"
)

// NewStore creates the appropriate database backend based on the driver name.
// Supported drivers: "sqlite" (default), "postgres".
func NewStore(ctx context.Context, driver, dsn string) (Store, error) {
	switch driver {
	case "postgres", "postgresql", "pg":
		return NewPostgresStore(ctx, dsn)
	default:
		if driver != "" && driver != "sqlite" {
			fmt.Printf("db: unknown driver %q, falling back to sqlite\n", driver)
		}
		return NewSqliteStore(dsn)
	}
}
