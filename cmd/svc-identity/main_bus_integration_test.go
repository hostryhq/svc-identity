//go:build integration

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hostryhq/go-common/bus"
	"github.com/hostryhq/go-common/events"
	"github.com/hostryhq/go-common/ids"
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// startNATS starts only the NATS service of the infra dev compose under a project of its own and a free port,
// with accounts generated from the api-specs event schemas, and provisions the streams and consumers. It skips
// when Docker or the sibling checkouts are missing. HOSTRY_INFRA_DIR and HOSTRY_EVENTS_DIR override the defaults.
func startNATS(t *testing.T) (url, seedDir string) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker daemon not reachable")
	}
	compose := filepath.Join(envOr("HOSTRY_INFRA_DIR", "../../../infra"), "dev", "compose.yaml")
	if _, err := os.Stat(compose); err != nil {
		t.Skip("infra/dev/compose.yaml not found (set HOSTRY_INFRA_DIR)")
	}
	reg, err := bus.LoadRegistry(eventsOf(t, envOr("HOSTRY_EVENTS_DIR", "../../../api-specs-p2/events")))
	if err != nil {
		t.Skipf("api-specs events not loadable (set HOSTRY_EVENTS_DIR): %v", err)
	}
	conf := t.TempDir()
	keys, err := bus.GenerateKeys(reg.Services())
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.WriteDevFiles(conf, keys); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	project := fmt.Sprintf("identitywire%d", os.Getpid())
	env := append(os.Environ(), "HOSTRY_NATS_CONF_DIR="+conf, fmt.Sprintf("HOSTRY_NATS_PORT=%d", port))
	t.Cleanup(func() {
		down := exec.Command("docker", "compose", "-f", compose, "-p", project, "down", "-v", "--timeout", "2")
		down.Env = env
		_ = down.Run()
	})
	up := exec.Command("docker", "compose", "-f", compose, "-p", project, "up", "-d", "--wait", "nats")
	up.Env = env
	if out, err := up.CombinedOutput(); err != nil {
		t.Skipf("compose up nats failed: %v: %s", err, out)
	}
	url = fmt.Sprintf("nats://127.0.0.1:%d", port)
	admin, err := bus.ConnectAdmin(url, filepath.Join(conf, "seeds", bus.AdminUser+".nk"))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := bus.Provision(ctx, admin, reg, bus.ProvisionOptions{}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	return url, filepath.Join(conf, "seeds")
}

// eventsOf copies the event schemas of the services identity exchanges events with into a temporary directory.
// The sync schemas are left out: go-common's registry does not yet accept their two-segment type (sync.op).
func eventsOf(t *testing.T, dir string) fs.FS {
	t.Helper()
	dst := t.TempDir()
	src := os.DirFS(dir)
	for _, svc := range []string{"billing", "identity", "tenancy"} {
		sub, err := fs.Sub(src, svc)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.CopyFS(filepath.Join(dst, svc), sub); err != nil {
			t.Skipf("event schemas of %s not found in %s: %v", svc, dir, err)
		}
	}
	return os.DirFS(dst)
}

// newDatabase creates a throwaway database on the infra dev Postgres and returns its DSN (HOSTRY_PG_DSN selects the server).
func newDatabase(t *testing.T) string {
	t.Helper()
	admin := envOr("HOSTRY_PG_DSN", "postgres://hostry:hostry-dev-only@127.0.0.1:55442/hostry?sslmode=disable")
	db, err := sql.Open("pgx", admin)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Ping(); err != nil {
		t.Skipf("no Postgres at the HOSTRY_PG_DSN default: %v", err)
	}
	name := "ident_" + regexp.MustCompile(`[^a-z0-9]`).ReplaceAllString(string(ids.New())[19:], "")
	if _, err := db.Exec("CREATE DATABASE " + name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)")
		_ = db.Close()
	})
	return regexp.MustCompile(`/hostry\?`).ReplaceAllString(admin, "/"+name+"?")
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

// The consumer wiring of serve: with NATS configured identity binds its durable consumer on the tenancy stream
// and ConsumeTenancy handles tenancy.subscription.changed and tenancy.organisation.status_changed, each in one
// transaction with its inbox row. The handler re-reads the entitlement snapshot from tenancy (a stub here).
func TestServeConsumesTenancyEntitlementEvents(t *testing.T) {
	natsURL, seeds := startNATS(t)
	dsn := newDatabase(t)

	var reads atomic.Int32
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reads.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"as_of":"2026-11-24T13:05:11.120Z","entitlements_v":2,"features":[],"limits":{},"organisation_status":"active"}`))
	}))
	defer stub.Close()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "identity.service.pem")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	m := map[string]string{
		"HOSTRY_ENV": "test", "HOSTRY_IDENTITY_DSN": dsn, "HOSTRY_IDENTITY_DB_ROLE": "identity_app", "HOSTRY_IDENTITY_AUTO_MIGRATE": "1",
		"HOSTRY_IDENTITY_LISTEN": addr, "HOSTRY_IDENTITY_ALLOW_TEST_SMS": "1",
		"HOSTRY_NATS_URL": natsURL, "HOSTRY_NATS_SEED_FILE": filepath.Join(seeds, "identity.nk"),
		"HOSTRY_TENANCY_URL": stub.URL, "HOSTRY_SERVICE_SIGNING_KEY_FILE": keyFile,
	}
	cfg, err := loadConfig(func(k string) string { return m[k] })
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, cfg) }()
	defer func() {
		stop()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("no graceful shutdown")
		}
	}()
	eventually(t, "service ready", func() bool {
		r, err := http.Get("http://" + addr + "/readyz")
		if err != nil {
			return false
		}
		_ = r.Body.Close()
		return r.StatusCode == 200
	})

	nc, err := bus.Connect(natsURL, "tenancy", filepath.Join(seeds, "tenancy.nk"))
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	pub, err := bus.NewPublisher(nc)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = probe.Close() }()
	at := time.Now().UTC().Truncate(time.Millisecond)
	org := ids.New()
	for i, c := range []struct{ typ, data string }{
		{"tenancy.subscription.changed", `{"plan_key":"table_service","plan_version":1,"cycle":"monthly","state":"active"}`},
		{"tenancy.organisation.status_changed", `{"status":"suspended","previous_status":"active"}`},
	} {
		before := reads.Load()
		e := events.Envelope{ID: ids.New(), Type: c.typ, V: 1, Source: "tenancy", TenantID: org, Key: org.String(), KeySeq: int64(i + 1),
			OccurredAt: at, Data: []byte(c.data)}
		raw, err := e.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if err := pub.Publish(context.Background(), "evt."+c.typ+".v1", e.ID.String(), raw); err != nil {
			t.Fatal(err)
		}
		eventually(t, c.typ+" applied: snapshot re-read from tenancy and inbox row written", func() bool {
			var n int
			if err := probe.QueryRow(`SELECT count(*) FROM inbox WHERE consumer = 'identity.tenancy' AND event_id = $1`, e.ID.String()).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n == 1 && reads.Load() > before
		})
	}
}
