//go:build integration

package integration

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hostryhq/go-common/idempotency"
	"github.com/hostryhq/go-common/testkit"
	"github.com/hostryhq/svc-identity/repository"
	"github.com/hostryhq/svc-identity/repository/postgres"
)

// asTenant runs fn in a transaction with the application role and the tenant context set, the way a
// tenant request would see the database.
func asTenant(t *testing.T, db *sql.DB, tenant string, fn func(tx *sql.Tx)) {
	t.Helper()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "SET LOCAL ROLE identity_app"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
		t.Fatal(err)
	}
	fn(tx)
}

// CR M2: a tenant's context can neither read nor append the platform (vendor) audit chain, and
// vendor_access_log rows are visible only to their own tenant.
func TestTenantsCannotReachPlatformAuditOrOtherTenantsVendorAccess(t *testing.T) {
	st, db := newDB(t)
	ctx := context.Background()
	a, b := testkit.TenantA.String(), testkit.TenantB.String()
	if err := st.Tx(ctx, repository.Platform, func(tx repository.Tx) error {
		return tx.AppendAudit(repository.Platform, "p1", []byte(`{"a":"vendor.sign_in"}`))
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Tx(ctx, a, func(tx repository.Tx) error { return tx.AppendAudit(a, "a1", []byte(`{"a":"x"}`)) }); err != nil {
		t.Fatal(err)
	}
	// The platform chain reads back through the repository (and verifies), so the app is not locked out.
	if err := st.Tx(ctx, repository.Platform, func(tx repository.Tx) error {
		rs, err := tx.ListAudit(repository.Platform, "", 10)
		if err != nil || len(rs) != 1 {
			t.Fatalf("platform chain through the repository: %d %v", len(rs), err)
		}
		if broken, err := tx.VerifyAuditChain(repository.Platform); err != nil || broken != "" {
			t.Fatalf("chain: %q %v", broken, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	asTenant(t, db, a, func(tx *sql.Tx) {
		var n int
		if err := tx.QueryRow(`SELECT count(*) FROM audit_log WHERE tenant_id = $1`, repository.Platform).Scan(&n); err != nil || n != 0 {
			t.Fatalf("tenant context read %d platform rows: %v", n, err)
		}
		if _, err := tx.Exec(`INSERT INTO audit_log (tenant_id, id, doc, prev_hash, hash) VALUES ($1,'forged','{}','','x')`, repository.Platform); err == nil {
			t.Fatal("tenant context appended to the platform chain")
		}
	})
	asTenant(t, db, a, func(tx *sql.Tx) {
		if _, err := tx.Exec(`INSERT INTO vendor_access_log (id, at, tenant_id, vendor_user, token_type, action_key, outcome) VALUES (gen_random_uuid(), now(), $1, 'v', 'support', 'x', 'ok')`, a); err != nil {
			t.Fatal(err)
		}
	})
	asTenant(t, db, b, func(tx *sql.Tx) {
		var n int
		if err := tx.QueryRow(`SELECT count(*) FROM vendor_access_log`).Scan(&n); err != nil || n != 0 {
			t.Fatalf("tenant B sees %d vendor access rows of tenant A: %v", n, err)
		}
		if _, err := tx.Exec(`INSERT INTO vendor_access_log (id, at, tenant_id, vendor_user, token_type, action_key, outcome) VALUES (gen_random_uuid(), now(), $1, 'v', 'support', 'x', 'ok')`, a); err == nil {
			t.Fatal("tenant B wrote a vendor access row for tenant A")
		}
	})
	// No tenant context at all sees nothing.
	asTenant(t, db, "", func(tx *sql.Tx) {
		var n int
		if err := tx.QueryRow(`SELECT count(*) FROM audit_log WHERE tenant_id = $1`, repository.Platform).Scan(&n); err != nil || n != 0 {
			t.Fatalf("empty context read platform rows: %d %v", n, err)
		}
	})
}

// CR M1 / SR-H4: the claim, the business write and the result commit in one transaction; a request
// that fails leaves neither a stuck key nor a half write; a secret-bearing result is stored as a
// fingerprint only; records expire after 24 hours.
func TestIdempotencyIsTransactionalSecretFreeAndExpires(t *testing.T) {
	st, db := newDB(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	idem := postgres.NewIdempotency(st)
	idem.Opt = idempotency.PGOptions{Now: func() time.Time { return now }}
	a := testkit.TenantA
	write := func(ctx context.Context, id string) error {
		return st.Tx(ctx, a.String(), func(tx repository.Tx) error {
			return tx.Put(repository.Record{Kind: "member", Scope: a.String(), ID: id, Doc: []byte(`{"n":"x"}`)})
		})
	}
	count := func(q string, args ...any) int {
		var n int
		if err := db.QueryRow(q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// A failure after the business write rolls everything back: no claim row, no member row.
	boom := errors.New("boom")
	_, _, err := idem.RunTx(ctx, a, "k-fail", "fp", func(ctx context.Context) (idempotency.TxResult, error) {
		if err := write(ctx, "m-fail"); err != nil {
			t.Fatal(err)
		}
		return idempotency.TxResult{}, boom
	})
	if !errors.Is(err, boom) || count(`SELECT count(*) FROM idempotency_records`) != 0 || count(`SELECT count(*) FROM records WHERE id='m-fail'`) != 0 {
		t.Fatalf("failed request left state behind: %v", err)
	}
	// A nested transaction that fails inside a successful request is rolled back alone.
	_, _, err = idem.RunTx(ctx, a, "k-nested", "fp", func(ctx context.Context) (idempotency.TxResult, error) {
		_ = st.Tx(ctx, a.String(), func(tx repository.Tx) error {
			_ = tx.Put(repository.Record{Kind: "member", Scope: a.String(), ID: "m-undone", Doc: []byte(`{}`)})
			return boom
		})
		if err := write(ctx, "m-kept"); err != nil {
			t.Fatal(err)
		}
		return idempotency.TxResult{Response: idempotency.Response{Status: 201, Body: []byte(`{"ok":true}`)}}, nil
	})
	if err != nil || count(`SELECT count(*) FROM records WHERE id='m-undone'`) != 0 || count(`SELECT count(*) FROM records WHERE id='m-kept'`) != 1 {
		t.Fatalf("nested rollback: %v", err)
	}
	// Replay returns the stored response and runs nothing.
	ran := false
	resp, replayed, err := idem.RunTx(ctx, a, "k-nested", "fp", func(context.Context) (idempotency.TxResult, error) { ran = true; return idempotency.TxResult{}, nil })
	if err != nil || !replayed || ran || resp.Status != 201 {
		t.Fatalf("replay: %+v %v %v %v", resp, replayed, ran, err)
	}
	// A secret is never stored; the replay says so.
	secret := `{"access_token":"tok-abc","refresh_token":"ref-xyz"}`
	if _, _, err := idem.RunTx(ctx, a, "k-secret", "fp", func(ctx context.Context) (idempotency.TxResult, error) {
		return idempotency.TxResult{Response: idempotency.Response{Status: 201, Body: []byte(secret)}, OmitBody: true}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := idem.RunTx(ctx, a, "k-secret", "fp", nil); !errors.Is(err, idempotency.ErrBodyOmitted) {
		t.Fatalf("replay of a secret: %v", err)
	}
	rows, err := db.Query(`SELECT coalesce(convert_from(body, 'UTF8'), '') FROM idempotency_records`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var b string
		_ = rows.Scan(&b)
		if strings.Contains(b, "tok-abc") || strings.Contains(b, "ref-xyz") {
			t.Fatal("a secret is stored in idempotency_records")
		}
	}
	rows.Close()
	// Expiry: after 24 hours the records are swept and the key is free again.
	now = now.Add(25 * time.Hour)
	if n, err := idem.Sweep(ctx); err != nil || n != 2 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	if count(`SELECT count(*) FROM idempotency_records`) != 0 {
		t.Fatal("expired records remain")
	}
}
