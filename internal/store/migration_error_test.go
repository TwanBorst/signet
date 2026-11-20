package store

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestMigrationError(t *testing.T) {
	const secret = "sensitive database detail"
	for _, tc := range []struct {
		name  string
		cause error
		want  string
	}{
		{"permissions", &pgconn.PgError{Code: "42501", Message: secret, Detail: secret}, "insufficient database privileges (SQLSTATE 42501)"},
		{"authentication", &pgconn.PgError{Code: "28P01", Message: secret}, "database password authentication failed (SQLSTATE 28P01)"},
		{"other SQLSTATE", &pgconn.PgError{Code: "42703", Message: secret}, "PostgreSQL error (SQLSTATE 42703)"},
		{"invalid SQLSTATE", &pgconn.PgError{Code: secret}, "underlying error details suppressed"},
		{"deadline", context.DeadlineExceeded, "timed out"},
		{"canceled", context.Canceled, "canceled"},
		{"unknown", errors.New(secret), "underlying error details suppressed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			action := "ensure signet_schema migration table exists"
			err := &migrationError{action, fmt.Errorf("%s: %w", secret, tc.cause)}
			if got, want := err.Error(), action+": "+tc.want; got != want {
				t.Errorf("error = %q, want %q", got, want)
			}
			if !errors.Is(err, tc.cause) {
				t.Error("original error is not available to callers")
			}
		})
	}
}
