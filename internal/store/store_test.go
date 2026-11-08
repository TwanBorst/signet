package store_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	api "github.com/TwanBorst/signet/api/v1alpha1"
	"github.com/TwanBorst/signet/internal/store"
	"github.com/TwanBorst/signet/internal/testutil"
)

func TestMigrationsRacesAndAuditOutage(t *testing.T) {
	s := testutil.DB(t)
	ctx := context.Background()
	if _, err := s.Pool.Exec(ctx, "DROP TABLE audit, requests, signet_schema"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if err := s.Migrate(ctx); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	cr, _ := testutil.Request(t, "immutable")
	for range 8 {
		wg.Go(func() { testutil.Ensure(t, s, cr, api.IssuerSpec{}, "issuer-uid") })
	}
	wg.Wait()
	var count int
	if err := s.Pool.QueryRow(ctx, "SELECT count(*) FROM requests").Scan(&count); err != nil || count != 1 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	var successes atomic.Int32
	for range 8 {
		wg.Go(func() {
			_, err := s.Mutate(ctx, string(cr.UID), "operator@example.com", "cancel", 1, func(r *store.Request) error { r.State = "cancelled"; r.Reason = "No longer needed"; return nil })
			if err == nil {
				successes.Add(1)
			}
		})
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("racing decisions succeeded %d times", successes.Load())
	}
	if matches, err := s.List(ctx, "operator@example.com", "", ""); err != nil || len(matches) != 1 {
		t.Fatalf("audit actor search matches=%d err=%v", len(matches), err)
	}
	audits, err := s.Audits(ctx, string(cr.UID))
	if err != nil || len(audits) != 11 {
		t.Fatalf("audit count=%d err=%v", len(audits), err)
	}
	if _, err := s.Pool.Exec(ctx, "ALTER TABLE audit RENAME TO audit_unavailable"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Access(ctx, string(cr.UID), "operator@example.com", "Download"); err == nil {
		t.Fatal("CSR released without durable audit")
	}
	if _, err := s.Mutate(ctx, string(cr.UID), "operator@example.com", "upload", 2, func(r *store.Request) error { r.State = "uploaded"; return nil }); err == nil {
		t.Fatal("changed state without audit")
	}
	r, err := s.Get(ctx, string(cr.UID))
	if err != nil || r.State != "cancelled" {
		t.Fatalf("state=%s err=%v", r.State, err)
	}
	if _, err := s.Pool.Exec(ctx, "ALTER TABLE audit_unavailable RENAME TO audit"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Access(ctx, string(cr.UID), "operator@example.com", "Download"); err != nil {
		t.Fatal(err)
	}
	changed := cr.DeepCopy()
	changed.Spec.IsCA = true
	if err := s.Ensure(ctx, store.Request{UID: string(cr.UID)}, store.Snapshot{Request: *changed}); err == nil {
		t.Fatal("accepted changed UID spec")
	}
	if _, err := s.Pool.Exec(ctx, "UPDATE signet_schema SET checksum='changed'"); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err == nil {
		t.Fatal("accepted changed migration")
	}
	if _, err := s.Pool.Exec(ctx, "INSERT INTO signet_schema VALUES (2,'future')"); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err == nil {
		t.Fatal("accepted newer migration")
	}
}
