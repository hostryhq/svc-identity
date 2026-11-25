package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/hostryhq/go-common/idempotency"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/go-common/tenancy"

	"github.com/hostryhq/svc-identity/repository"
)

// Idempotency implements the idempotency store over the idempotency_records table (go-common
// idempotency.Schema, migration 0004). Keys are scoped per tenant; routes with no tenant use the
// platform pseudo-tenant. The table is not tenant data, so it carries no row-level security.
//
// RunTx claims the key, runs the request's business writes and stores the result in ONE transaction:
// the Store joins that transaction for the duration of the request (a savepoint per Tx call), so a
// crash cannot leave a key stuck and a failed request leaves nothing behind. A response that must not
// be kept (TxResult.OmitBody) is stored as a fingerprint only. Records expire after 24 hours (Sweep).
// Begin, Complete and Release serve the requests that cannot share a transaction (vendor realm).
type Idempotency struct {
	DB  *sql.DB
	Opt idempotency.PGOptions
	// Store, when set, joins the request transaction (see RunTx). Without it RunTx still claims and
	// stores in one transaction but the business writes run in their own.
	Store *Store
}

// NewIdempotency returns the store for st.
func NewIdempotency(st *Store) *Idempotency { return &Idempotency{DB: st.DB(), Store: st} }

func (i *Idempotency) pg() *idempotency.PGStore { return &idempotency.PGStore{DB: i.DB, Opt: i.Opt} }

// Begin implements idempotency.Store.
func (i *Idempotency) Begin(ctx context.Context, tenant ids.ID, key, fp string) (*idempotency.Response, bool, error) {
	return i.pg().Begin(ctx, tenant, key, fp)
}

// Complete implements idempotency.Store.
func (i *Idempotency) Complete(ctx context.Context, tenant ids.ID, key string, r idempotency.Response) error {
	return i.pg().Complete(ctx, tenant, key, r)
}

// Release implements idempotency.Store.
func (i *Idempotency) Release(ctx context.Context, tenant ids.ID, key string) error {
	return i.pg().Release(ctx, tenant, key)
}

// Sweep deletes expired records. Run it periodically.
func (i *Idempotency) Sweep(ctx context.Context) (int64, error) {
	return idempotency.Sweep(ctx, i.DB, i.Opt)
}

var _ idempotency.Store = (*Idempotency)(nil)

type reqTxKey struct{}

type reqTx struct {
	sql *sql.Tx
	n   atomic.Int64
}

// keepsWork is implemented by the error of a request that must leave no idempotency claim but whose
// writes (failure counters of a refused attempt) must commit.
type keepsWork interface{ KeepsWork() bool }

// RunTx implements api.TxIdempotency.
func (i *Idempotency) RunTx(ctx context.Context, tenant ids.ID, key, fp string, fn func(ctx context.Context) (idempotency.TxResult, error)) (idempotency.Response, bool, error) {
	return idempotency.DoTx(ctx, i.DB, i.Opt, tenant, key, fp, func(tx *sql.Tx) (idempotency.TxResult, error) {
		rctx := ctx
		if i.Store != nil {
			rctx = context.WithValue(ctx, reqTxKey{}, &reqTx{sql: tx})
		}
		res, err := fn(rctx)
		var k keepsWork
		if errors.As(err, &k) && k.KeepsWork() {
			// A refused attempt keeps its writes but leaves no claim, so the retry runs again.
			if _, derr := tx.ExecContext(ctx, `DELETE FROM idempotency_records WHERE tenant_id=$1 AND key=$2`, tenant.String(), key); derr != nil {
				return idempotency.TxResult{}, derr
			}
			return idempotency.TxResult{}, nil
		}
		return res, err
	})
}

// nested runs fn inside the request transaction under a savepoint, with the same role and tenant
// context a stand-alone transaction would have.
func (s *Store) nested(ctx context.Context, rt *reqTx, scope string, fn func(repository.Tx) error) error {
	sp := fmt.Sprintf("hostry_sp_%d", rt.n.Add(1))
	if _, err := rt.sql.ExecContext(ctx, "SAVEPOINT "+sp); err != nil {
		return err
	}
	if s.role != "" {
		if _, err := rt.sql.ExecContext(ctx, "SET LOCAL ROLE "+s.role); err != nil {
			return err
		}
	}
	if scope != "" {
		if err := tenancy.SetDBContext(ctx, rt.sql, ids.ID(scope)); err != nil {
			return err
		}
	} else if _, err := rt.sql.ExecContext(ctx, `SELECT set_config('app.tenant_id', '', true)`); err != nil {
		return err
	}
	if err := fn(&tx{ctx: ctx, sql: rt.sql, scope: scope}); err != nil {
		if _, rerr := rt.sql.ExecContext(ctx, "ROLLBACK TO SAVEPOINT "+sp); rerr != nil {
			return rerr
		}
		return err
	}
	_, err := rt.sql.ExecContext(ctx, "RELEASE SAVEPOINT "+sp)
	return err
}
