package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"auth-proxy/logging"
)

// retryPing handles remote databases that are starting or briefly unavailable.
// The configured URL must already be syntactically valid before retrying.
func retryPing(db *sql.DB) error {
	var lastErr error
	for attempt := 1; attempt <= 15; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		lastErr = db.PingContext(ctx)
		cancel()
		if lastErr == nil {
			return nil
		}
		if attempt < 15 {
			logging.AppLog.Warn("Database not ready; retrying", "attempt", attempt)
			time.Sleep(2 * time.Second)
		}
	}
	return fmt.Errorf("database not reachable after retries: %w", lastErr)
}
