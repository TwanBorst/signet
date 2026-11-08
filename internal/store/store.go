package store

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	api "github.com/TwanBorst/signet/api/v1alpha1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS

type Request struct {
	UID           string           `json:"uid"`
	Namespace     string           `json:"namespace"`
	Name          string           `json:"name"`
	IssuerKind    string           `json:"issuerKind"`
	IssuerName    string           `json:"issuerName"`
	State         string           `json:"state"`
	DNSNames      []string         `json:"dnsNames"`
	Usages        []cmapi.KeyUsage `json:"usages,omitempty"`
	Duration      string           `json:"duration,omitempty"`
	IsCA          bool             `json:"isCA"`
	Requester     string           `json:"requester,omitempty"`
	CreatedAt     time.Time        `json:"createdAt"`
	UpdatedAt     time.Time        `json:"updatedAt"`
	Certificate   string           `json:"certificate,omitempty"`
	Chain         string           `json:"chain,omitempty"`
	TrustVerified bool             `json:"trustVerified"`
	Reason        string           `json:"reason,omitempty"`
	Version       int64            `json:"version"`
}
type Snapshot struct {
	Request   cmapi.CertificateRequest `json:"request"`
	Policy    api.IssuerSpec           `json:"policy"`
	IssuerUID string                   `json:"issuerUID"`
}
type Audit struct {
	ID        int64     `json:"id"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Outcome   string    `json:"outcome"`
	Detail    string    `json:"detail"`
	CreatedAt time.Time `json:"createdAt"`
}
type Store struct{ Pool *pgxpool.Pool }

type ActionError struct {
	Status  int
	Message string
}

func (e *ActionError) Error() string          { return e.Message }
func Reject(status int, message string) error { return &ActionError{status, message} }

func (s *Store) Migrate(ctx context.Context) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Transaction-scoped lock serializes all database-using replicas, including
	// first creation of the migration table. DDL and version commit together.
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(731924018)"); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "CREATE TABLE IF NOT EXISTS signet_schema(version integer PRIMARY KEY, checksum text NOT NULL)"); err != nil {
		return err
	}
	var latest int
	if err = tx.QueryRow(ctx, "SELECT COALESCE(max(version),0) FROM signet_schema").Scan(&latest); err != nil {
		return err
	}
	if latest > 1 {
		return errors.New("database schema is newer than this binary")
	}
	sql, err := migrations.ReadFile("migrations/001_initial.sql")
	if err != nil {
		return err
	}
	hash := sha256.Sum256(sql)
	checksum := hex.EncodeToString(hash[:])
	if latest == 0 {
		if _, err = tx.Exec(ctx, string(sql)); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "INSERT INTO signet_schema VALUES (1,$1)", checksum); err != nil {
			return err
		}
	} else {
		var existing string
		if err = tx.QueryRow(ctx, "SELECT checksum FROM signet_schema WHERE version=1").Scan(&existing); err != nil {
			return err
		}
		if existing != checksum {
			return errors.New("migration checksum mismatch; do not modify applied migrations")
		}
	}
	return tx.Commit(ctx)
}
func (s *Store) Record(ctx context.Context, uid, actor, action, outcome, detail string) error {
	_, err := s.Pool.Exec(ctx, "INSERT INTO audit(uid,actor,action,outcome,detail) VALUES($1,$2,$3,$4,$5)", uid, actor, action, outcome, detail)
	return err
}
func audit(ctx context.Context, tx pgx.Tx, uid, actor, action, outcome, detail string) error {
	_, err := tx.Exec(ctx, "INSERT INTO audit(uid,actor,action,outcome,detail) VALUES($1,$2,$3,$4,$5)", uid, actor, action, outcome, detail)
	return err
}
func Fingerprint(cr *cmapi.CertificateRequest) string {
	issuance := cr.Spec
	issuance.Username = ""
	issuance.Groups = nil
	issuance.Extra = nil
	spec, _ := json.Marshal(issuance)
	h := sha256.Sum256(spec)
	return hex.EncodeToString(h[:])
}

func (s *Store) Ensure(ctx context.Context, r Request, snap Snapshot) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if r.State != "failed" {
		r.State = "pending"
	}
	r.DNSNames = append([]string{}, r.DNSNames...)
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	snapshot, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO requests(uid,namespace,name,state,data,snapshot,fingerprint)
		VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(uid) DO NOTHING`,
		r.UID, r.Namespace, r.Name, r.State, data, snapshot, Fingerprint(&snap.Request))
	if err != nil {
		return err
	}
	if tag.RowsAffected() > 0 {
		detail := "Validated CSR and immutable request specification retained"
		if r.State == "failed" {
			detail = "Unsafe request rejected; only non-sensitive metadata retained"
		}
		if err = audit(ctx, tx, r.UID, "system:controller", "snapshot", "success", detail); err != nil {
			return err
		}
		if err = audit(ctx, tx, r.UID, "system:controller", "state."+r.State, "success", r.Reason); err != nil {
			return err
		}
		if r.State != "failed" {
			if err = audit(ctx, tx, r.UID, "system:controller", "csr.access", "success", "Request ingestion"); err != nil {
				return err
			}
		}
	} else {
		var fingerprint string
		if err = tx.QueryRow(ctx, "SELECT fingerprint FROM requests WHERE uid=$1", r.UID).Scan(&fingerprint); err != nil {
			return err
		}
		if fingerprint != Fingerprint(&snap.Request) {
			return Reject(409, "request specification changed for immutable UID")
		}
	}
	return tx.Commit(ctx)
}

func read(row pgx.Row) (Request, error) {
	var r Request
	var data []byte
	err := row.Scan(&data, &r.State, &r.Version, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return r, err
	}
	state, version, created, updated := r.State, r.Version, r.CreatedAt, r.UpdatedAt
	if err := json.Unmarshal(data, &r); err != nil {
		return r, err
	}
	r.State, r.Version, r.CreatedAt, r.UpdatedAt = state, version, created, updated
	return r, nil
}

const columns = "data,state,version,created_at,updated_at"

func (s *Store) Get(ctx context.Context, uid string) (Request, error) {
	r, err := read(s.Pool.QueryRow(ctx, "SELECT "+columns+" FROM requests WHERE uid=$1", uid))
	if errors.Is(err, pgx.ErrNoRows) {
		return r, Reject(404, "request not found")
	}
	return r, err
}
func (s *Store) List(ctx context.Context, q, state, before string) ([]Request, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+columns+` FROM requests
		WHERE ($1='' OR namespace ILIKE '%'||$1||'%' OR name ILIKE '%'||$1||'%' OR data::text ILIKE '%'||$1||'%'
			OR EXISTS (SELECT 1 FROM audit a WHERE a.uid=requests.uid
				AND (a.actor ILIKE '%'||$1||'%' OR a.action ILIKE '%'||$1||'%'
					OR a.outcome ILIKE '%'||$1||'%' OR a.detail ILIKE '%'||$1||'%')))
		AND ($2='' OR state=$2)
		AND ($3='' OR (created_at,uid) < (SELECT created_at,uid FROM requests WHERE uid=$3))
		ORDER BY created_at DESC,uid DESC LIMIT 100`, q, state, before)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Request{}
	for rows.Next() {
		r, err := read(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}
func (s *Store) Audits(ctx context.Context, uid string) ([]Audit, error) {
	rows, err := s.Pool.Query(ctx, "SELECT id,actor,action,outcome,detail,created_at FROM audit WHERE uid=$1 ORDER BY id", uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Audit{}
	for rows.Next() {
		var a Audit
		if err := rows.Scan(&a.ID, &a.Actor, &a.Action, &a.Outcome, &a.Detail, &a.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, a)
	}
	return result, rows.Err()
}

// Access returns public CSR material only after its audit transaction commits.
func (s *Store) Access(ctx context.Context, uid, actor, purpose string) (Snapshot, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	defer tx.Rollback(ctx)
	var data []byte
	if err = tx.QueryRow(ctx, "SELECT snapshot FROM requests WHERE uid=$1", uid).Scan(&data); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			if err = audit(ctx, tx, uid, actor, "csr.access", "failure", "Request not found"); err != nil {
				return Snapshot{}, err
			}
			if err = tx.Commit(ctx); err != nil {
				return Snapshot{}, err
			}
			return Snapshot{}, Reject(404, "request not found")
		}
		return Snapshot{}, err
	}
	var snap Snapshot
	if err = json.Unmarshal(data, &snap); err != nil {
		return snap, err
	}
	if err = audit(ctx, tx, uid, actor, "csr.access", "success", purpose); err != nil {
		return Snapshot{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Snapshot{}, err
	}
	return snap, nil
}

// Mutate commits a rejected action's audit, but not its tentative state. Row
// locking plus the client's version prevents duplicate and racing decisions.
func (s *Store) Mutate(ctx context.Context, uid, actor, action string, version int64, fn func(*Request) error) (Request, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Request{}, err
	}
	defer tx.Rollback(ctx)
	r, err := read(tx.QueryRow(ctx, "SELECT "+columns+" FROM requests WHERE uid=$1 FOR UPDATE", uid))
	if errors.Is(err, pgx.ErrNoRows) {
		err = Reject(404, "request not found")
	}
	if err != nil {
		var ae *ActionError
		if !errors.As(err, &ae) {
			return r, err
		}
		if aerr := audit(ctx, tx, uid, actor, action, "failure", ae.Message); aerr != nil {
			return r, aerr
		}
		if cerr := tx.Commit(ctx); cerr != nil {
			return r, cerr
		}
		return r, err
	}
	old := r
	if version != 0 && version != r.Version {
		err = Reject(409, "request changed; refresh before acting")
	} else {
		err = fn(&r)
	}
	if err != nil {
		if aerr := audit(ctx, tx, uid, actor, action, "failure", err.Error()); aerr != nil {
			return old, aerr
		}
		if cerr := tx.Commit(ctx); cerr != nil {
			return old, cerr
		}
		return old, err
	}
	r.Version++
	data, err := json.Marshal(r)
	if err != nil {
		return old, err
	}
	if _, err = tx.Exec(ctx, "UPDATE requests SET state=$2,version=$3,data=$4,updated_at=now() WHERE uid=$1", uid, r.State, r.Version, data); err != nil {
		return old, err
	}
	if err = audit(ctx, tx, uid, actor, action, "success", r.Reason); err != nil {
		return old, err
	}
	if err = tx.Commit(ctx); err != nil {
		return old, err
	}
	return s.Get(ctx, uid)
}

func (s *Store) Transition(ctx context.Context, uid, state, reason string) error {
	r, err := s.Get(ctx, uid)
	if err != nil {
		return err
	}
	if r.State == state {
		return nil
	}
	_, err = s.Mutate(ctx, uid, "system:controller", "state."+state, 0, func(r *Request) error {
		if r.State == state {
			return Reject(409, "transition already recorded")
		}
		// Preserve operator outcomes after cert-manager reports their failure.
		if state == "failed" && (r.State == "denied" || r.State == "cancelled") {
			return Reject(409, "operator outcome already recorded")
		}
		r.State = state
		r.Reason = reason
		return nil
	})
	var ae *ActionError
	if errors.As(err, &ae) && ae.Status == 409 {
		return nil
	}
	return err
}

func (s *Store) Active(ctx context.Context) ([]Request, error) {
	rows, err := s.Pool.Query(ctx, "SELECT "+columns+" FROM requests WHERE state IN ('pending','uploaded','denied','cancelled') ORDER BY created_at")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Request{}
	for rows.Next() {
		r, err := read(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}
func (s *Store) String() string { return fmt.Sprintf("Signet durable store") }
