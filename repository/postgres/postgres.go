// Package postgres is the PostgreSQL implementation of repository.Store. Tenant documents are
// isolated by row-level security on app.tenant_id, set per transaction from the request's verified
// tenant; the audit log is append-only and hash-chained; events go to the transactional outbox in
// the same transaction as the state change.
package postgres

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/events"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/go-common/outbox"
	"github.com/hostryhq/go-common/tenancy"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver

	"github.com/hostryhq/svc-identity/repository"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

var roleRE = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// Store implements repository.Store over database/sql with the pgx driver.
type Store struct {
	db *sql.DB
	// role, when set, is assumed with SET LOCAL ROLE at the start of every transaction so row-level
	// security applies even when the connection is a superuser (development and tests).
	role string
}

// Open connects and returns a Store. role may be empty when the connection already is the
// application role.
func Open(ctx context.Context, dsn, role string) (*Store, error) {
	if role != "" && !roleRE.MatchString(role) {
		return nil, fmt.Errorf("postgres: invalid role name")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(20)
	db.SetConnMaxLifetime(30 * time.Minute)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}
	return &Store{db: db, role: role}, nil
}

// DB returns the underlying handle (outbox relay, health, tests).
func (s *Store) DB() *sql.DB { return s.db }

// Close closes the pool.
func (s *Store) Close() error { return s.db.Close() }

// Ping implements repository.Store.
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// Migrate applies the embedded forward-only migrations in order, once each, under an advisory lock.
func Migrate(ctx context.Context, db *sql.DB) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock(7102001)`); err != nil {
		return err
	}
	defer conn.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock(7102001)`) //nolint:errcheck
	if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, n := range names {
		var done bool
		if err := conn.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, n).Scan(&done); err != nil {
			return err
		}
		if done {
			continue
		}
		b, err := migrationFS.ReadFile("migrations/" + n)
		if err != nil {
			return err
		}
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(b)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("postgres: migration %s: %w", n, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, n); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Tx implements repository.Store. A request on a vendor user's authority runs inside go-auth's
// audited transaction, which writes the vendor_access_log row in the same transaction (fail closed).
func (s *Store) Tx(ctx context.Context, scope string, fn func(repository.Tx) error) error {
	if p, ok := auth.PrincipalFrom(ctx); ok && p.IsVendorActor() {
		if _, has := tenancy.From(ctx); !has {
			ctx = tenancy.With(ctx, tenancy.Context{TenantID: ids.ID(repository.Platform), ActorID: p.Subject})
		}
		return auth.WithAuditedTx(ctx, s.db, func(ctx context.Context, sqlTx *sql.Tx) error {
			if s.role != "" {
				if _, err := sqlTx.ExecContext(ctx, "SET LOCAL ROLE "+s.role); err != nil {
					return err
				}
			}
			if scope != "" {
				if err := tenancy.SetDBContext(ctx, sqlTx, ids.ID(scope)); err != nil {
					return err
				}
			}
			return fn(&tx{ctx: ctx, sql: sqlTx, scope: scope})
		})
	}
	sqlTx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if s.role != "" {
		if _, err := sqlTx.ExecContext(ctx, "SET LOCAL ROLE "+s.role); err != nil {
			_ = sqlTx.Rollback()
			return err
		}
	}
	if scope != "" {
		if err := tenancy.SetDBContext(ctx, sqlTx, ids.ID(scope)); err != nil {
			_ = sqlTx.Rollback()
			return err
		}
	}
	if err := fn(&tx{ctx: ctx, sql: sqlTx, scope: scope}); err != nil {
		_ = sqlTx.Rollback()
		return err
	}
	return sqlTx.Commit()
}

type tx struct {
	ctx   context.Context
	sql   *sql.Tx
	scope string
}

func isUnique(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

func (t *tx) Get(kind, scope, id string) (repository.Record, bool, error) {
	var r repository.Record
	var err error
	if repository.IsGlobal(kind) {
		err = t.sql.QueryRowContext(t.ctx, `SELECT k1, k2, uniq, doc FROM global_records WHERE kind=$1 AND id=$2 FOR UPDATE`, kind, id).Scan(&r.K1, &r.K2, &r.Unique, &r.Doc)
		scope = ""
	} else {
		err = t.sql.QueryRowContext(t.ctx, `SELECT k1, k2, uniq, doc FROM records WHERE tenant_id=$1 AND kind=$2 AND id=$3 FOR UPDATE`, scope, kind, id).Scan(&r.K1, &r.K2, &r.Unique, &r.Doc)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return repository.Record{}, false, nil
	}
	r.Kind, r.Scope, r.ID = kind, scope, id
	return r, err == nil, err
}

func (t *tx) Put(r repository.Record) error {
	var err error
	if repository.IsGlobal(r.Kind) {
		_, err = t.sql.ExecContext(t.ctx, `INSERT INTO global_records (kind, id, k1, k2, uniq, doc) VALUES ($1,$2,$3,$4,$5,$6)
			ON CONFLICT (kind, id) DO UPDATE SET k1=EXCLUDED.k1, k2=EXCLUDED.k2, uniq=EXCLUDED.uniq, doc=EXCLUDED.doc, updated_at=now()`,
			r.Kind, r.ID, r.K1, r.K2, r.Unique, r.Doc)
	} else {
		_, err = t.sql.ExecContext(t.ctx, `INSERT INTO records (tenant_id, kind, id, k1, k2, uniq, doc) VALUES ($1,$2,$3,$4,$5,$6,$7)
			ON CONFLICT (tenant_id, kind, id) DO UPDATE SET k1=EXCLUDED.k1, k2=EXCLUDED.k2, uniq=EXCLUDED.uniq, doc=EXCLUDED.doc, updated_at=now()`,
			r.Scope, r.Kind, r.ID, r.K1, r.K2, r.Unique, r.Doc)
	}
	if isUnique(err) {
		return repository.ErrConflict
	}
	return err
}

func (t *tx) Delete(kind, scope, id string) error {
	var err error
	if repository.IsGlobal(kind) {
		_, err = t.sql.ExecContext(t.ctx, `DELETE FROM global_records WHERE kind=$1 AND id=$2`, kind, id)
	} else {
		_, err = t.sql.ExecContext(t.ctx, `DELETE FROM records WHERE tenant_id=$1 AND kind=$2 AND id=$3`, scope, kind, id)
	}
	return err
}

func (t *tx) query(kind, scope, cond string, args ...any) ([]repository.Record, error) {
	var rows *sql.Rows
	var err error
	if repository.IsGlobal(kind) {
		scope = ""
		rows, err = t.sql.QueryContext(t.ctx, `SELECT id, k1, k2, uniq, doc FROM global_records WHERE kind=$1 AND `+cond, append([]any{kind}, args...)...)
	} else {
		rows, err = t.sql.QueryContext(t.ctx, `SELECT id, k1, k2, uniq, doc FROM records WHERE tenant_id=$1 AND kind=$2 AND `+cond, append([]any{scope, kind}, args...)...)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []repository.Record
	for rows.Next() {
		r := repository.Record{Kind: kind, Scope: scope}
		if err := rows.Scan(&r.ID, &r.K1, &r.K2, &r.Unique, &r.Doc); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// placeholder numbering differs between the two tables (kind is $1 for global, $2 for tenant).
func (t *tx) ph(kind string, n int) string {
	if repository.IsGlobal(kind) {
		return fmt.Sprintf("$%d", n+1)
	}
	return fmt.Sprintf("$%d", n+2)
}

func (t *tx) FindK1(kind, scope, k string) ([]repository.Record, error) {
	return t.query(kind, scope, "k1 = "+t.ph(kind, 1)+" ORDER BY id", k)
}

func (t *tx) FindK2(kind, scope, k string) ([]repository.Record, error) {
	return t.query(kind, scope, "k2 = "+t.ph(kind, 1)+" ORDER BY id", k)
}

func (t *tx) List(kind, scope, after string, limit int) ([]repository.Record, error) {
	if limit <= 0 {
		return t.query(kind, scope, "id > "+t.ph(kind, 1)+" ORDER BY id", after)
	}
	return t.query(kind, scope, "id > "+t.ph(kind, 1)+" ORDER BY id LIMIT "+t.ph(kind, 2), after, limit)
}

func (t *tx) Emit(e events.Envelope) error { return outbox.Publish(t.ctx, t.sql, e) }

func (t *tx) AppendAudit(scope, id string, doc []byte) error {
	if _, err := t.sql.ExecContext(t.ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "audit:"+scope); err != nil {
		return err
	}
	prev := ""
	err := t.sql.QueryRowContext(t.ctx, `SELECT hash FROM audit_log WHERE tenant_id=$1 ORDER BY seq DESC LIMIT 1`, scope).Scan(&prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = t.sql.ExecContext(t.ctx, `INSERT INTO audit_log (tenant_id, id, doc, prev_hash, hash) VALUES ($1,$2,$3,$4,$5)`,
		scope, id, string(doc), prev, repository.ChainHash(prev, scope, id, doc))
	return err
}

func (t *tx) ListAudit(scope, before string, limit int) ([]repository.Record, error) {
	if limit <= 0 {
		limit = 1 << 20
	}
	rows, err := t.sql.QueryContext(t.ctx, `SELECT id, doc FROM audit_log WHERE tenant_id=$1 AND ($2 = '' OR id < $2) ORDER BY id DESC LIMIT $3`, scope, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []repository.Record
	for rows.Next() {
		r := repository.Record{Kind: "audit", Scope: scope}
		if err := rows.Scan(&r.ID, &r.Doc); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (t *tx) VerifyAuditChain(scope string) (string, error) {
	rows, err := t.sql.QueryContext(t.ctx, `SELECT id, doc, prev_hash, hash FROM audit_log WHERE tenant_id=$1 ORDER BY seq`, scope)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	prev := ""
	for rows.Next() {
		var id, ph, h string
		var doc []byte
		if err := rows.Scan(&id, &doc, &ph, &h); err != nil {
			return "", err
		}
		if ph != prev || repository.ChainHash(prev, scope, id, doc) != h {
			return id, nil
		}
		prev = h
	}
	return "", rows.Err()
}

// ---- vendor access log (go-auth hook) ----

// AccessLog implements auth.VendorAuditSink over vendor_access_log.
type AccessLog struct{ DB *sql.DB }

const insertAccess = `INSERT INTO vendor_access_log (id, at, tenant_id, vendor_user, token_type, support_session, action_key, target_id, ticket, outcome, result_count, request_id)
	VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`

func accessArgs(e auth.VendorAccessEntry) []any {
	return []any{e.ID.String(), e.Time, e.TenantID, e.VendorUser, string(e.TokenType), e.SupportSession, e.ActionKey, e.TargetID, e.Ticket, e.Outcome, e.ResultCount, e.RequestID}
}

// RecordInTx implements auth.VendorAuditSink.
func (a *AccessLog) RecordInTx(ctx context.Context, tx tenancy.Execer, e auth.VendorAccessEntry) error {
	_, err := tx.ExecContext(ctx, insertAccess, accessArgs(e)...)
	return err
}

// RecordRefused implements auth.VendorAuditSink.
func (a *AccessLog) RecordRefused(ctx context.Context, e auth.VendorAccessEntry) error {
	_, err := a.DB.ExecContext(ctx, insertAccess, accessArgs(e)...)
	return err
}
