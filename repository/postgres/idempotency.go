package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/hostryhq/go-common/idempotency"
	"github.com/hostryhq/go-common/ids"
)

// Idempotency implements idempotency.Store over the idempotency_keys table. Keys are scoped per
// tenant; routes with no tenant use the platform pseudo-tenant. The table is not tenant data (a
// key is a client-chosen string), so it carries no row-level security of its own.
type Idempotency struct{ DB *sql.DB }

// Begin claims the key. Exactly one concurrent caller gets started=true.
func (i *Idempotency) Begin(ctx context.Context, tenant ids.ID, key, fp string) (*idempotency.Response, bool, error) {
	res, err := i.DB.ExecContext(ctx, `INSERT INTO idempotency_keys (tenant_id, key, fingerprint) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, tenant.String(), key, fp)
	if err != nil {
		return nil, false, err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return nil, true, nil
	}
	var stored string
	var done bool
	var r idempotency.Response
	err = i.DB.QueryRowContext(ctx, `SELECT fingerprint, done, status, content_type, body FROM idempotency_keys WHERE tenant_id=$1 AND key=$2`, tenant.String(), key).
		Scan(&stored, &done, &r.Status, &r.ContentType, &r.Body)
	if errors.Is(err, sql.ErrNoRows) { // released between the insert and the select: let the caller retry
		return nil, false, idempotency.ErrInProgress
	}
	if err != nil {
		return nil, false, err
	}
	if stored != fp {
		return nil, false, idempotency.ErrMismatch
	}
	if !done {
		return nil, false, idempotency.ErrInProgress
	}
	return &r, false, nil
}

// Complete stores the response of a started key.
func (i *Idempotency) Complete(ctx context.Context, tenant ids.ID, key string, r idempotency.Response) error {
	_, err := i.DB.ExecContext(ctx, `UPDATE idempotency_keys SET done=true, status=$3, content_type=$4, body=$5 WHERE tenant_id=$1 AND key=$2`,
		tenant.String(), key, r.Status, r.ContentType, r.Body)
	return err
}

// Release drops a started key after failure so the client may retry.
func (i *Idempotency) Release(ctx context.Context, tenant ids.ID, key string) error {
	_, err := i.DB.ExecContext(ctx, `DELETE FROM idempotency_keys WHERE tenant_id=$1 AND key=$2 AND NOT done`, tenant.String(), key)
	return err
}

var _ idempotency.Store = (*Idempotency)(nil)
