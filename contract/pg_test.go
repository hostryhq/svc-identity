//go:build integration

package contract_test

import (
	"context"
	"database/sql"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/svc-identity/contract"
	"github.com/hostryhq/svc-identity/double"
	"github.com/hostryhq/svc-identity/repository/postgres"
	"github.com/hostryhq/svc-identity/service"
)

var secretMember = regexp.MustCompile(`"(access_token|refresh_token|approval_token|code|code_half|half|grant|offline_pack|renewal_handle|setup_token|token|tokens)"\s*:`)

func adminDSN() string {
	if v := os.Getenv("HOSTRY_PG_DSN"); v != "" {
		return v
	}
	return "postgres://hostry:hostry-dev-only@127.0.0.1:55442/hostry?sslmode=disable"
}

// TestContractAgainstPostgres runs the same suite against the service assembled over PostgreSQL
// (the real repository, row-level security, outbox and idempotency store), one throwaway database
// per operation.
func TestContractAgainstPostgres(t *testing.T) {
	ctx := context.Background()
	admin, err := sql.Open("pgx", adminDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() }) // parallel subtests outlive this function body
	if err := admin.PingContext(ctx); err != nil {
		t.Skipf("no Postgres at %s: %v", adminDSN(), err)
	}
	contract.Run(t, func(t *testing.T, cfg func(*service.Config)) *contract.World {
		name := "contract_" + regexp.MustCompile(`[^a-z0-9]`).ReplaceAllString(string(ids.New())[19:], "")
		if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+name); err != nil {
			t.Fatal(err)
		}
		dsn := regexp.MustCompile(`/hostry\?`).ReplaceAllString(adminDSN(), "/"+name+"?")
		st, err := postgres.Open(ctx, dsn, "identity_app")
		if err != nil {
			t.Fatal(err)
		}
		if err := postgres.Migrate(ctx, st.DB()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = st.Close()
			_, _ = admin.ExecContext(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		})
		// SR-H4: after every contract case no idempotency record holds a token, refresh token, code, half,
		// grant or pack. Registered after the drop, so it runs before it.
		t.Cleanup(func() {
			rows, err := st.DB().QueryContext(ctx, `SELECT key, coalesce(convert_from(body, 'UTF8'), '') FROM idempotency_records`)
			if err != nil {
				t.Errorf("read idempotency records: %v", err)
				return
			}
			defer rows.Close()
			for rows.Next() {
				var k, b string
				_ = rows.Scan(&k, &b)
				if strings.Contains(b, "eyJ") || secretMember.MatchString(b) {
					t.Errorf("idempotency record %q stores a secret: %.60s", k, b)
				}
			}
		})
		return &contract.World{D: double.New(double.Options{ExampleLiterals: true, Config: cfg, Store: st,
			AccessLog: &postgres.AccessLog{DB: st.DB(), Role: "identity_app"}, Idem: postgres.NewIdempotency(st)})}
	})
}
