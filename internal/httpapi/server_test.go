package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	api "github.com/TwanBorst/signet/api/v1alpha1"
	"github.com/TwanBorst/signet/internal/httpapi"
	"github.com/TwanBorst/signet/internal/store"
	"github.com/TwanBorst/signet/internal/testutil"
)

func TestIdentityInjection(t *testing.T) {
	for _, values := range [][]string{
		nil, {""}, {"a@example.com", "b@example.com"}, {"a@example.com,b@example.com"},
		{"Person <a@example.com>"}, {" a@example.com"}, {"a@example.com "}, {"a@example.com\nInjected: yes"}, {"user"}, {"a@@example.com"}, {"a@example.com;admin"},
	} {
		h := http.Header{"X-Auth-Request-Email": values}
		if actor, err := httpapi.Identity(h, "x-auth-request-email"); err == nil {
			t.Fatalf("accepted %q as %s", values, actor)
		}
	}
	if actor, err := httpapi.Identity(http.Header{"X-Identity": []string{"operator@example.com"}}, "X-Identity"); err != nil || actor != "operator@example.com" {
		t.Fatalf("custom header: %s %v", actor, err)
	}
}
func TestAPIWorkflowAuditAndCSRF(t *testing.T) {
	s := testutil.DB(t)
	cr, _ := testutil.Request(t, "api")
	testutil.Ensure(t, s, cr, api.IssuerSpec{}, "issuer-uid")
	h := &httpapi.Server{Store: s, AuthHeader: "x-auth-request-email", Origin: "https://signet.example.com", UI: http.NotFoundHandler(), Live: func(context.Context, store.Request) error { return nil }}
	send := func(method, path string, body any, origin, actor string) *httptest.ResponseRecorder {
		var data []byte
		if body != nil {
			data, _ = json.Marshal(body)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(data))
		if actor != "" {
			req.Header.Set("x-auth-request-email", actor)
		}
		if method == "POST" {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Signet-CSRF", "1")
			req.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	if w := send("GET", "/api/me", nil, "", ""); w.Code != 401 {
		t.Fatalf("missing auth %d", w.Code)
	}
	for _, path := range []string{"/api/me", "/api/requests", "/api/requests/api", "/api/requests/api/audit", "/api/requests/api/csr"} {
		if w := send("GET", path, nil, "", "operator@example.com"); w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
	}
	if w := send("GET", "/api/requests/api", nil, "", "operator@example.com"); bytes.Contains(w.Body.Bytes(), []byte("CERTIFICATE REQUEST")) {
		t.Fatal("details exposed unaudited CSR")
	}
	if w := send("POST", "/api/requests/api/cancel", map[string]any{"version": 1, "reason": "No longer needed"}, "https://attacker.example", "operator@example.com"); w.Code != 403 {
		t.Fatalf("CSRF %d", w.Code)
	}
	if w := send("POST", "/api/requests/api/cancel", map[string]any{"version": 1, "reason": ""}, "https://signet.example.com", "operator@example.com"); w.Code != 400 {
		t.Fatalf("reason %d", w.Code)
	}
	cert, ca := testutil.Bundle(t, cr)
	if w := send("POST", "/api/requests/api/upload", map[string]any{"version": 1, "certificate": cert, "chain": ca}, "https://signet.example.com", "operator@example.com"); w.Code != 200 {
		t.Fatalf("upload %d %s", w.Code, w.Body)
	}
	if w := send("POST", "/api/requests/api/deny", map[string]any{"version": 1, "reason": "Late denial"}, "https://signet.example.com", "operator@example.com"); w.Code != 409 {
		t.Fatalf("race %d", w.Code)
	}
	audits, err := s.Audits(context.Background(), "api")
	if err != nil {
		t.Fatal(err)
	}
	access, failed := 0, 0
	for _, a := range audits {
		if a.Action == "csr.access" {
			access++
		}
		if a.Outcome == "failure" {
			failed++
		}
	}
	if access < 3 || failed < 2 {
		t.Fatalf("audit accesses=%d failures=%d", access, failed)
	}
	if _, err := s.Pool.Exec(context.Background(), "ALTER TABLE audit RENAME TO audit_unavailable"); err != nil {
		t.Fatal(err)
	}
	if w := send("GET", "/api/requests/api/csr", nil, "", "operator@example.com"); w.Code != 503 || bytes.Contains(w.Body.Bytes(), []byte("CERTIFICATE REQUEST")) {
		t.Fatal("released CSR during outage")
	}
}
