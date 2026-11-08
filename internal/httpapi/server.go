package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/TwanBorst/signet/internal/pki"
	"github.com/TwanBorst/signet/internal/store"
)

type Server struct {
	Store      *store.Store
	AuthHeader string
	Origin     string
	UI         http.Handler
	Live       func(context.Context, store.Request) error
}

func Identity(h http.Header, name string) (string, error) {
	values := h.Values(name)
	if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > 254 {
		return "", errors.New("missing or ambiguous authenticated identity")
	}
	value := values[0]
	for _, r := range value {
		if r <= 32 || r >= 127 || strings.ContainsRune(",;<>\"\\", r) {
			return "", errors.New("malformed authenticated identity")
		}
	}
	addr, err := mail.ParseAddress(value)
	if err != nil || addr.Address != value || strings.Count(value, "@") != 1 {
		return "", errors.New("malformed authenticated identity")
	}
	return value, nil
}
func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		slog.Warn("HTTP response write failed")
	}
}
func failure(w http.ResponseWriter, err error) {
	var ae *store.ActionError
	if errors.As(err, &ae) {
		respond(w, ae.Status, map[string]string{"error": ae.Message})
		return
	}
	slog.Error("Request failed: durable store or dependency unavailable")
	respond(w, 503, map[string]string{"error": "Durable audit or a required dependency is unavailable. No successful outcome is claimed; refresh before retrying."})
}
func (s *Server) reject(w http.ResponseWriter, r *http.Request, uid, actor, action string, status int, message string) {
	if err := s.Store.Record(r.Context(), uid, actor, action, "failure", message); err != nil {
		failure(w, err)
		return
	}
	failure(w, store.Reject(status, message))
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
	if r.URL.Path == "/healthz" {
		w.WriteHeader(200)
		return
	}
	if r.URL.Path == "/readyz" {
		if err := s.Store.Pool.Ping(r.Context()); err != nil {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
		return
	}
	actor, err := Identity(r.Header, s.AuthHeader)
	uid := ""
	if strings.HasPrefix(r.URL.Path, "/api/requests/") {
		part := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/requests/"), "/")[0]
		if len(part) <= 100 {
			uid = part
		}
	}
	if err != nil {
		s.reject(w, r, uid, "system:unauthenticated", "identity", 401, err.Error())
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		s.UI.ServeHTTP(w, r)
		return
	}
	if r.Method != http.MethodGet {
		if r.Method != http.MethodPost {
			s.reject(w, r, "", actor, "http.method", 405, "method not allowed")
			return
		}
		if r.Header.Get("Origin") != s.Origin || len(r.Header.Values("Origin")) != 1 ||
			r.Header.Get("X-Signet-CSRF") != "1" || len(r.Header.Values("X-Signet-CSRF")) != 1 ||
			r.Header.Get("Content-Type") != "application/json" {
			s.reject(w, r, uid, actor, "csrf", 403, "request origin, CSRF header, or content type is invalid")
			return
		}
	}
	s.route(w, r, actor)
}

func (s *Server) route(w http.ResponseWriter, r *http.Request, actor string) {
	if r.Method == "GET" && r.URL.Path == "/api/me" {
		respond(w, 200, map[string]string{"actor": actor})
		return
	}
	if r.Method == "GET" && r.URL.Path == "/api/requests" {
		q, state, before := r.URL.Query().Get("q"), r.URL.Query().Get("state"), r.URL.Query().Get("before")
		if len(q) > 200 || len(state) > 20 || len(before) > 100 {
			s.reject(w, r, "", actor, "search", 400, "search parameter too long")
			return
		}
		result, err := s.Store.List(r.Context(), q, state, before)
		if err != nil {
			failure(w, err)
			return
		}
		respond(w, 200, result)
		return
	}
	path := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/requests/"), "/")
	if !strings.HasPrefix(r.URL.Path, "/api/requests/") || len(path) > 2 || path[0] == "" || len(path[0]) > 100 {
		s.reject(w, r, "", actor, "http.route", 404, "endpoint not found")
		return
	}
	uid := path[0]
	if r.Method == "GET" {
		switch {
		case len(path) == 1:
			result, err := s.Store.Get(r.Context(), uid)
			if err != nil {
				s.rejectOrFail(w, r, uid, actor, "details", err)
				return
			}
			respond(w, 200, result)
			return
		case path[1] == "audit":
			result, err := s.Store.Audits(r.Context(), uid)
			if err != nil {
				failure(w, err)
				return
			}
			respond(w, 200, result)
			return
		case path[1] == "csr":
			snap, err := s.Store.Access(r.Context(), uid, actor, "Operator CSR download")
			if err != nil {
				failure(w, err)
				return
			}
			if len(snap.Request.Spec.Request) == 0 {
				s.reject(w, r, uid, actor, "csr.download", 409, "CSR was not retained because validation failed")
				return
			}
			w.Header().Set("Content-Type", "application/x-pem-file")
			w.Header().Set("Content-Disposition", `attachment; filename="request.csr.pem"`)
			if _, err := w.Write(snap.Request.Spec.Request); err != nil {
				slog.Warn("CSR response write failed")
				auditCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
				defer cancel()
				if err := s.Store.Record(auditCtx, uid, actor, "csr.download", "failure", "Response interrupted after audited CSR access"); err != nil {
					slog.Error("CSR download interruption audit could not be committed")
				}
			}
			return
		}
	}
	if r.Method != "POST" || len(path) != 2 || (path[1] != "upload" && path[1] != "deny" && path[1] != "cancel") {
		s.reject(w, r, uid, actor, "http.route", 404, "endpoint not found")
		return
	}
	action := path[1]
	var input struct {
		Certificate string `json:"certificate"`
		Chain       string `json:"chain"`
		Reason      string `json:"reason"`
		Version     int64  `json:"version"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 384*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		s.reject(w, r, uid, actor, action, 400, "invalid or oversized JSON body")
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		s.reject(w, r, uid, actor, action, 400, "only one JSON value is allowed")
		return
	}
	if input.Version < 1 {
		s.reject(w, r, uid, actor, action, 400, "request version is required")
		return
	}
	var snap store.Snapshot
	if action == "upload" {
		var err error
		snap, err = s.Store.Access(r.Context(), uid, actor, "Upload certificate validation")
		if err != nil {
			failure(w, err)
			return
		}
	}
	result, err := s.Store.Mutate(r.Context(), uid, actor, action, input.Version, func(req *store.Request) error {
		if req.State != "pending" {
			return store.Reject(409, "request is not awaiting an operator decision")
		}
		if err := s.Live(r.Context(), *req); err != nil {
			return err
		}
		if action == "upload" {
			verified, err := pki.Validate(&snap.Request, snap.Policy, input.Certificate, input.Chain, time.Now())
			if err != nil {
				return store.Reject(400, err.Error())
			}
			req.Certificate = input.Certificate
			req.Chain = input.Chain
			req.TrustVerified = verified
			req.State = "uploaded"
		} else {
			reason := strings.TrimSpace(input.Reason)
			if len(reason) == 0 || len(reason) > 1024 || strings.Contains(strings.ToUpper(reason), "PRIVATE KEY") {
				return store.Reject(400, "a non-sensitive reason of 1-1024 bytes is required")
			}
			for _, c := range reason {
				if c < 32 || c == 127 {
					return store.Reject(400, "reason cannot contain control characters")
				}
			}
			req.Reason = reason
			if action == "deny" {
				req.State = "denied"
			} else {
				req.State = "cancelled"
			}
		}
		return nil
	})
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, 200, result)
}
func (s *Server) rejectOrFail(w http.ResponseWriter, r *http.Request, uid, actor, action string, err error) {
	var ae *store.ActionError
	if errors.As(err, &ae) {
		s.reject(w, r, uid, actor, action, ae.Status, ae.Message)
	} else {
		failure(w, err)
	}
}
