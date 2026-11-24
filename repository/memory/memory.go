// Package memory is the in-memory repository used by the test double and by unit tests. It
// behaves like the Postgres repository: transactions are atomic and serialised, a tenant
// transaction cannot see or write another tenant's rows (the row-level security rule), unique
// keys are enforced, and events are written "to the outbox" only when the transaction commits.
package memory

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"sync"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/events"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/go-common/tenancy"
	"github.com/hostryhq/svc-identity/repository"
)

// Store is an in-memory repository.Store.
type Store struct {
	mu     sync.Mutex
	data   map[string]repository.Record
	audit  map[string][]auditRow
	events []events.Envelope

	auditDB tenancy.TxBeginner
}

type auditRow struct {
	rec  repository.Record
	hash string
}

// New returns an empty store.
func New() *Store {
	return &Store{data: map[string]repository.Record{}, audit: map[string][]auditRow{}}
}

// TamperAudit rewrites an audit entry's document without fixing the chain (IST-40 test hook).
func (s *Store) TamperAudit(scope, id string, doc []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, r := range s.audit[scope] {
		if r.rec.ID == id {
			s.audit[scope][i].rec.Doc = doc
		}
	}
}

// Events returns the events committed so far (the outbox contents).
func (s *Store) Events() []events.Envelope {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]events.Envelope(nil), s.events...)
}

// Ping implements repository.Store.
func (s *Store) Ping(context.Context) error { return nil }

// ErrTenantMismatch is returned when a tenant transaction writes another tenant's row.
var ErrTenantMismatch = errors.New("memory: row belongs to another tenant")

// AuditDB, when set, makes requests on a vendor user's authority run inside go-auth's audited
// transaction (the same path the Postgres repository takes), so the vendor access row is a
// condition for the response in the test double too.
func (s *Store) SetAuditDB(db tenancy.TxBeginner) { s.auditDB = db }

// Tx implements repository.Store.
func (s *Store) Tx(ctx context.Context, scope string, fn func(repository.Tx) error) error {
	if p, ok := auth.PrincipalFrom(ctx); ok && p.IsVendorActor() && s.auditDB != nil {
		if _, has := tenancy.From(ctx); !has {
			ctx = tenancy.With(ctx, tenancy.Context{TenantID: ids.ID(repository.Platform), ActorID: p.Subject})
		}
		return auth.WithAuditedTx(ctx, s.auditDB, func(context.Context, *sql.Tx) error { return s.run(scope, fn) })
	}
	return s.run(scope, fn)
}

func (s *Store) run(scope string, fn func(repository.Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	work := make(map[string]repository.Record, len(s.data))
	for k, v := range s.data {
		work[k] = v
	}
	au := make(map[string][]auditRow, len(s.audit))
	for k, v := range s.audit {
		au[k] = append([]auditRow(nil), v...)
	}
	t := &tx{scope: scope, data: work, audit: au}
	if err := fn(t); err != nil {
		return err
	}
	s.data = work
	s.audit = au
	s.events = append(s.events, t.events...)
	return nil
}

type tx struct {
	scope  string
	data   map[string]repository.Record
	audit  map[string][]auditRow
	events []events.Envelope
}

func (t *tx) auditOK(scope string) bool { return scope == repository.Platform || scope == t.scope }

func (t *tx) AppendAudit(scope, id string, doc []byte) error {
	if !t.auditOK(scope) {
		return ErrTenantMismatch
	}
	prev := ""
	if rows := t.audit[scope]; len(rows) > 0 {
		prev = rows[len(rows)-1].hash
	}
	doc = append([]byte(nil), doc...)
	t.audit[scope] = append(t.audit[scope], auditRow{
		rec:  repository.Record{Kind: "audit", Scope: scope, ID: id, Doc: doc},
		hash: repository.ChainHash(prev, scope, id, doc),
	})
	return nil
}

func (t *tx) ListAudit(scope, before string, limit int) ([]repository.Record, error) {
	if !t.auditOK(scope) {
		return nil, nil
	}
	rows := t.audit[scope]
	var out []repository.Record
	for i := len(rows) - 1; i >= 0; i-- {
		if before != "" && rows[i].rec.ID >= before {
			continue
		}
		out = append(out, rows[i].rec)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (t *tx) VerifyAuditChain(scope string) (string, error) {
	prev := ""
	for _, r := range t.audit[scope] {
		if repository.ChainHash(prev, scope, r.rec.ID, r.rec.Doc) != r.hash {
			return r.rec.ID, nil
		}
		prev = r.hash
	}
	return "", nil
}

func key(kind, scope, id string) string { return kind + "\x00" + scope + "\x00" + id }

// visible mirrors row-level security: tenant kinds are visible only inside their own tenant.
func (t *tx) visible(kind, scope string) bool {
	return repository.IsGlobal(kind) || scope == t.scope
}

func (t *tx) Get(kind, scope, id string) (repository.Record, bool, error) {
	if !t.visible(kind, scope) {
		return repository.Record{}, false, nil
	}
	r, ok := t.data[key(kind, scope, id)]
	return r, ok, nil
}

func (t *tx) Put(r repository.Record) error {
	if repository.IsGlobal(r.Kind) {
		r.Scope = repository.Global
	} else if r.Scope != t.scope {
		return ErrTenantMismatch
	}
	if r.Unique && r.K1 != "" {
		for _, o := range t.data {
			if o.Kind == r.Kind && o.Scope == r.Scope && o.K1 == r.K1 && o.ID != r.ID {
				return repository.ErrConflict
			}
		}
	}
	r.Doc = append([]byte(nil), r.Doc...)
	t.data[key(r.Kind, r.Scope, r.ID)] = r
	return nil
}

func (t *tx) Delete(kind, scope, id string) error {
	if !t.visible(kind, scope) {
		return nil
	}
	delete(t.data, key(kind, scope, id))
	return nil
}

func (t *tx) find(kind, scope string, match func(repository.Record) bool) []repository.Record {
	if !t.visible(kind, scope) {
		return nil
	}
	var out []repository.Record
	for _, r := range t.data {
		if r.Kind == kind && r.Scope == scope && match(r) {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (t *tx) FindK1(kind, scope, k string) ([]repository.Record, error) {
	return t.find(kind, scope, func(r repository.Record) bool { return r.K1 == k }), nil
}

func (t *tx) FindK2(kind, scope, k string) ([]repository.Record, error) {
	return t.find(kind, scope, func(r repository.Record) bool { return r.K2 == k }), nil
}

func (t *tx) List(kind, scope, after string, limit int) ([]repository.Record, error) {
	out := t.find(kind, scope, func(r repository.Record) bool { return r.ID > after })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (t *tx) Emit(e events.Envelope) error {
	if err := e.Validate(); err != nil {
		return err
	}
	t.events = append(t.events, e)
	return nil
}
