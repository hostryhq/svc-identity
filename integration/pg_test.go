//go:build integration

// Package integration runs the identity service over a real PostgreSQL (the infra dev stack):
// migrations, row-level security, the append-only audit log, the transactional outbox, idempotency
// and the HTTP flows through the same assembly the double uses. Run with
//
//	HOSTRY_PG_DSN=postgres://hostry:hostry-dev-only@127.0.0.1:55442/hostry?sslmode=disable go test -tags integration ./integration/...
package integration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"sync"
	"testing"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/events"
	"github.com/hostryhq/go-common/idempotency"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/go-common/tenancy"
	"github.com/hostryhq/go-common/testkit"
	"github.com/hostryhq/svc-identity/double"
	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/repository"
	"github.com/hostryhq/svc-identity/repository/postgres"
	"github.com/hostryhq/svc-identity/service"
)

func adminDSN() string {
	if v := os.Getenv("HOSTRY_PG_DSN"); v != "" {
		return v
	}
	return "postgres://hostry:hostry-dev-only@127.0.0.1:55442/hostry?sslmode=disable"
}

// newDB creates a throwaway database, migrates it and returns an app-role store on it.
func newDB(t *testing.T) (*postgres.Store, *sql.DB) {
	t.Helper()
	ctx := context.Background()
	admin, err := sql.Open("pgx", adminDSN())
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.PingContext(ctx); err != nil {
		t.Skipf("no Postgres at %s: %v", adminDSN(), err)
	}
	name := "ident_" + regexp.MustCompile(`[^a-z0-9]`).ReplaceAllString(string(ids.New())[19:], "")
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
		_ = admin.Close()
	})
	return st, st.DB()
}

func TestMigrationsAreIdempotent(t *testing.T) {
	st, db := newDB(t)
	if err := postgres.Migrate(context.Background(), db); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if err := st.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// IST-31 at the database: row-level security hides and refuses another tenant's rows even for a
// statement that names them.
func TestRowLevelSecurityIsolatesTenants(t *testing.T) {
	st, _ := newDB(t)
	ctx := context.Background()
	a, b := testkit.TenantA.String(), testkit.TenantB.String()
	put := func(tenant, id string) error {
		return st.Tx(ctx, tenant, func(tx repository.Tx) error {
			return tx.Put(repository.Record{Kind: "member", Scope: tenant, ID: id, Doc: []byte(`{"n":"x"}`)})
		})
	}
	if err := put(a, "m1"); err != nil {
		t.Fatal(err)
	}
	if err := put(b, "m2"); err != nil {
		t.Fatal(err)
	}
	_ = st.Tx(ctx, b, func(tx repository.Tx) error {
		if _, ok, _ := tx.Get("member", a, "m1"); ok {
			t.Error("tenant B read tenant A's member")
		}
		if rs, _ := tx.List("member", a, "", 0); len(rs) != 0 {
			t.Error("tenant B listed tenant A's members")
		}
		if rs, _ := tx.List("member", b, "", 0); len(rs) != 1 {
			t.Error("tenant B cannot see its own member")
		}
		return nil
	})
	// A write that names another tenant is refused by the WITH CHECK policy.
	err := st.Tx(ctx, b, func(tx repository.Tx) error {
		return tx.Put(repository.Record{Kind: "member", Scope: a, ID: "evil", Doc: []byte(`{}`)})
	})
	if err == nil {
		t.Error("tenant B wrote a row for tenant A")
	}
	// A transaction with no tenant (global scope) sees no tenant rows at all.
	_ = st.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		if rs, _ := tx.List("member", a, "", 0); len(rs) != 0 {
			t.Error("a tenant-less transaction read tenant rows")
		}
		return nil
	})
}

// IST-40: the application role cannot update or delete audit rows; the chain detects an edit made as the owner.
func TestAuditLogIsAppendOnlyAndChained(t *testing.T) {
	st, db := newDB(t)
	ctx := context.Background()
	a := testkit.TenantA.String()
	if err := st.Tx(ctx, a, func(tx repository.Tx) error {
		for _, id := range []string{"a1", "a2", "a3"} {
			if err := tx.AppendAudit(a, id, []byte(`{"action":"`+id+`"}`)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{`UPDATE audit_log SET doc='{}'`, `DELETE FROM audit_log`, `TRUNCATE audit_log`} {
		err := st.Tx(ctx, a, func(tx repository.Tx) error { return execAs(ctx, st, stmt) })
		if err == nil {
			t.Errorf("application role ran %q on the audit log", stmt)
		}
	}
	_ = st.Tx(ctx, a, func(tx repository.Tx) error {
		if broken, _ := tx.VerifyAuditChain(a); broken != "" {
			t.Errorf("fresh chain broken at %s", broken)
		}
		return nil
	})
	// The table owner (a superuser editing storage directly) is caught by the chain.
	if _, err := db.ExecContext(ctx, `UPDATE audit_log SET doc='{"action":"altered"}' WHERE id='a2'`); err != nil {
		t.Fatal(err)
	}
	_ = st.Tx(ctx, a, func(tx repository.Tx) error {
		if broken, _ := tx.VerifyAuditChain(a); broken != "a2" {
			t.Errorf("tampered entry not detected: %q", broken)
		}
		return nil
	})
}

// execAs runs a statement through a store transaction's role (SET LOCAL ROLE identity_app).
func execAs(ctx context.Context, st *postgres.Store, stmt string) error {
	tx, err := st.DB().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "SET LOCAL ROLE identity_app"); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, stmt)
	return err
}

// E1: an event emitted in a rolled-back transaction publishes nothing; a committed one is in the outbox.
func TestOutboxIsTransactional(t *testing.T) {
	st, db := newDB(t)
	ctx := context.Background()
	a := testkit.TenantA
	emit := func(fail bool) error {
		return st.Tx(ctx, a.String(), func(tx repository.Tx) error {
			if err := tx.Put(repository.Record{Kind: "member", Scope: a.String(), ID: "m", Doc: []byte(`{}`)}); err != nil {
				return err
			}
			if err := tx.Emit(eventFor(a)); err != nil {
				return err
			}
			if fail {
				return fmt.Errorf("boom")
			}
			return nil
		})
	}
	if err := emit(true); err == nil {
		t.Fatal("expected the failure")
	}
	var n int
	_ = db.QueryRow(`SELECT count(*) FROM outbox`).Scan(&n)
	if n != 0 {
		t.Fatalf("outbox rows after rollback: %d", n)
	}
	if err := emit(false); err != nil {
		t.Fatal(err)
	}
	_ = db.QueryRow(`SELECT count(*) FROM outbox`).Scan(&n)
	if n != 1 {
		t.Fatalf("outbox rows after commit: %d", n)
	}
}

func TestIdempotencyStoreExactlyOneStarter(t *testing.T) {
	_, db := newDB(t)
	s := &postgres.Idempotency{DB: db}
	ctx := context.Background()
	var wg sync.WaitGroup
	started := make(chan bool, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, ok, err := s.Begin(ctx, testkit.TenantA, "k1", "fp")
			if err != nil && err != idempotency.ErrInProgress {
				t.Error(err)
			}
			started <- ok
		}()
	}
	wg.Wait()
	close(started)
	n := 0
	for ok := range started {
		if ok {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d callers started the same key", n)
	}
	if err := s.Complete(ctx, testkit.TenantA, "k1", idempotency.Response{Status: 201, Body: []byte(`{"a":1}`)}); err != nil {
		t.Fatal(err)
	}
	r, ok, err := s.Begin(ctx, testkit.TenantA, "k1", "fp")
	if err != nil || ok || r == nil || r.Status != 201 {
		t.Fatalf("replay: %+v %v %v", r, ok, err)
	}
	if _, _, err := s.Begin(ctx, testkit.TenantA, "k1", "other"); err != idempotency.ErrMismatch {
		t.Fatalf("different request with the same key: %v", err)
	}
}

// ---- end to end over Postgres ----

type e2e struct {
	t  *testing.T
	d  *double.Double
	db *sql.DB
	n  int
	mu sync.Mutex
}

type failingLog struct {
	postgres.AccessLog
	fail bool
}

func (f *failingLog) RecordInTx(ctx context.Context, tx tenancy.Execer, e auth.VendorAccessEntry) error {
	if f.fail {
		return fmt.Errorf("injected")
	}
	return f.AccessLog.RecordInTx(ctx, tx, e)
}

func newE2E(t *testing.T) (*e2e, *failingLog) {
	t.Helper()
	st, db := newDB(t)
	fl := &failingLog{AccessLog: postgres.AccessLog{DB: db}}
	d := double.New(double.Options{Store: st, AccessLog: fl, Idem: &postgres.Idempotency{DB: db}})
	return &e2e{t: t, d: d, db: db}, fl
}

func (e *e2e) do(method, path, token string, body any, hdr ...string) (int, []byte) {
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	req.RemoteAddr = "203.0.113.7:4000"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if method != "GET" {
		e.mu.Lock()
		e.n++
		req.Header.Set("Idempotency-Key", fmt.Sprintf("it-%d", e.n))
		e.mu.Unlock()
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	e.d.Handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func (e *e2e) must(status int, method, path, token string, body, out any, hdr ...string) {
	e.t.Helper()
	c, b := e.do(method, path, token, body, hdr...)
	if c != status {
		e.t.Fatalf("%s %s: %d want %d: %s", method, path, c, status, b)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			e.t.Fatal(err)
		}
	}
}

var otpRE = regexp.MustCompile(`[0-9]{6}`)

const (
	mobile  = "+919876543210"
	outletA = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a61"
)

func pubOf(d *double.Device) gen.PublicJwk {
	k := d.JWK()
	return gen.PublicJwk{Kty: gen.PublicJwkKtyEC, Crv: gen.PublicJwkCrvP256, X: k.X, Y: k.Y}
}

func (e *e2e) ownerSession() (gen.Session, *double.Device) {
	e.t.Helper()
	if _, _, err := e.d.Service.Seed().OwnerInvitation(context.Background(), testkit.TenantA.String(), mobile, "Asha"); err != nil {
		e.t.Fatal(err)
	}
	dev := double.NewDevice(string(ids.New()))
	var ch gen.OtpChallenge
	e.must(202, "POST", "/v1/otp-challenges", "", gen.CreateOtpChallenge{MobileE164: mobile, DeviceId: dev.ID, DevicePublicKey: pubOf(dev)}, &ch)
	m, _ := e.d.SMS.Last(mobile)
	var s gen.Session
	e.must(201, "POST", "/v1/sessions", "", gen.CreateSession{GrantType: gen.CreateSessionGrantTypeOtp, ChallengeId: ch.Id, Code: otpRE.FindString(m.Text), DeviceId: dev.ID,
		DeviceAssertion: dev.Assert(e.d.Clock.Now(), "j-"+ch.Id, service.AssertionClaims{Cid: ch.Id})}, &s)
	return s, dev
}

func (e *e2e) count(q string, args ...any) int {
	var n int
	if err := e.db.QueryRow(q, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func TestOverPostgresLoginRolesDevicesAndEvents(t *testing.T) {
	e, _ := newE2E(t)
	owner, _ := e.ownerSession()
	tok := owner.Tokens.AccessToken
	var role gen.Role
	e.must(201, "POST", "/v1/roles", tok, gen.RoleInput{Name: "Cashier", Permissions: []string{"member.read", "device.read"}}, &role)
	var m gen.Member
	e.must(201, "POST", "/v1/members", tok, gen.CreateMember{Id: string(ids.New()), DisplayName: "Ravi"}, &m)
	e.must(201, "POST", "/v1/members/"+m.Id+"/role-assignments", tok, gen.AssignmentInput{Id: string(ids.New()), RoleId: role.Id}, nil)

	// Device activation, single-use code under parallel redemption (IST-21), one revoke event.
	var code gen.ActivationCode
	e.must(201, "POST", "/v1/activation-codes", tok, gen.CreateActivationCode{OutletId: outletA, Kind: gen.Pos}, &code)
	const n = 4
	var wg sync.WaitGroup
	res := make([]int, n)
	devs := make([]*double.Device, n)
	nonces := make([]gen.DeviceNonce, n)
	for i := range devs {
		devs[i] = double.NewDevice(string(ids.New()))
		e.must(201, "POST", "/v1/device-nonces", "", nil, &nonces[i])
	}
	for i := range devs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res[i], _ = e.do("POST", "/v1/device-activations", "", gen.ActivateDevice{ActivationCode: code.Code, Id: devs[i].ID, Name: "x", PublicKey: pubOf(devs[i]),
				KeyProtection: gen.Hardware, Nonce: nonces[i].Nonce, NonceSignature: devs[i].SignNonce(nonces[i].Nonce)})
		}(i)
	}
	wg.Wait()
	wins, winner := 0, -1
	for i, c := range res {
		if c == 201 {
			wins++
			winner = i
		}
	}
	if wins != 1 {
		t.Fatalf("parallel activation results %v", res)
	}
	e.must(200, "PUT", "/v1/devices/"+devs[winner].ID+"/revocation", tok, gen.RevokeDevice{Reason: gen.RevokeDeviceReasonLost}, nil)
	if got := e.count(`SELECT count(*) FROM outbox WHERE type='identity.device.revoked'`); got != 1 {
		t.Fatalf("revoked events in the outbox: %d", got)
	}
	if got := e.count(`SELECT count(*) FROM outbox WHERE type='identity.device.registered'`); got != 1 {
		t.Fatalf("registered events in the outbox: %d", got)
	}
	// Idempotent replay with the same key returns the stored response without a second effect (PUT revoke again, new key: no second event).
	e.must(200, "PUT", "/v1/devices/"+devs[winner].ID+"/revocation", tok, gen.RevokeDevice{Reason: gen.RevokeDeviceReasonLost}, nil)
	if got := e.count(`SELECT count(*) FROM outbox WHERE type='identity.device.revoked'`); got != 1 {
		t.Fatalf("a repeated revoke emitted a second event: %d", got)
	}
	// IST-31 over HTTP with real RLS: a member of another tenant is invisible.
	other := ids.ID("018f0000-0000-7000-8000-00000000000b")
	foreign := string(ids.New())
	if err := e.d.Service.Seed().Member(context.Background(), other.String(), service.SeedMember{ID: foreign, Name: "Bee"}); err != nil {
		t.Fatal(err)
	}
	if c, _ := e.do("GET", "/v1/members/"+foreign, tok, nil); c != 404 {
		t.Fatalf("cross-tenant read: %d", c)
	}
}

// IST-42 / ADR-0013 V5 over a real transaction: the vendor access row is written in the request's
// transaction; a failing sink fails the request closed.
func TestOverPostgresSupportAccessIsFailClosed(t *testing.T) {
	e, fl := newE2E(t)
	e.ownerSession()
	link, err := e.d.Service.VendorBootstrap(context.Background(), "root@hostry.test", "it@host")
	if err != nil {
		t.Fatal(err)
	}
	svc := func() []string { return []string{"Hostry-Service-Token", e.d.ServiceToken("admin", "")} }
	var ch gen.VendorSetupChallenge
	e.must(201, "POST", "/internal/v1/vendor/setup-sessions", "", gen.BeginVendorSetup{SetupToken: link}, &ch, svc()...)
	u, _ := url.Parse(ch.TotpProvisioningUri)
	secret, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.Query().Get("secret"))
	e.must(200, "POST", "/internal/v1/vendor/setup-completions", "", gen.CompleteVendorSetup{SetupToken: link, Password: "correct-horse-battery-staple", TotpCode: crypto.TOTP(secret, e.d.Clock.Now())}, nil, svc()...)
	e.d.Clock.Advance(31 * time.Second)
	var vs gen.VendorSession
	e.must(201, "POST", "/internal/v1/vendor/sessions", "", gen.VendorSignIn{Email: "root@hostry.test", Password: "correct-horse-battery-staple", TotpCode: crypto.TOTP(secret, e.d.Clock.Now())}, &vs, svc()...)
	var st gen.SupportSessionStarted
	e.must(201, "POST", "/internal/v1/vendor/support-sessions", vs.AccessToken, gen.StartSupportSession{OrganisationId: testkit.TenantA.String(), Reason: "Owner phoned about a lost tablet", TicketReference: "SUP-1"}, &st, svc()...)
	rows := e.count(`SELECT count(*) FROM vendor_access_log`)
	if rows < 1 { // the support start is recorded
		t.Fatalf("vendor_access_log rows after a support start: %d", rows)
	}
	e.must(200, "GET", "/v1/members", st.Token.AccessToken, nil, nil, svc()...)
	if got := e.count(`SELECT count(*) FROM vendor_access_log`); got != rows+1 {
		t.Fatalf("a support read wrote %d rows, want 1", got-rows)
	}
	// The sink fails: the request is refused and no data is returned.
	fl.fail = true
	c, b := e.do("GET", "/v1/members", st.Token.AccessToken, nil, svc()...)
	if c < 500 || bytes.Contains(b, []byte("display_name")) {
		t.Fatalf("audit failure must fail closed: %d %s", c, b)
	}
	fl.fail = false
	// The tenant's own log (chained, in Postgres) shows the session start.
	var n int
	_ = e.db.QueryRow(`SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND doc::jsonb->>'action'='support.session.started'`, testkit.TenantA.String()).Scan(&n)
	if n != 1 {
		t.Fatalf("tenant audit entries for the support start: %d", n)
	}
}

func eventFor(a ids.ID) events.Envelope {
	return events.Envelope{ID: ids.New(), Type: "identity.member.changed", V: 1, Source: "identity", TenantID: a, Key: "m", KeySeq: 1, OccurredAt: time.Now().UTC(),
		Data: json.RawMessage(`{"member_id":"m","change":"created"}`)}
}
