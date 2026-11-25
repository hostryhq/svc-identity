// Package double is the in-memory test double of the identity service. It is not a second
// implementation: it composes the same service and api layers as the real service over the
// in-memory repository, a fake clock, deterministic ids and randomness, a recording SMS sender and
// an ephemeral token signer. Behaviour therefore cannot drift from the real service, and the
// shared contract suite (contract/) runs against both. Other services' tests import it.
package double

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/authtest"
	"github.com/hostryhq/go-common/idempotency"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/go-common/testkit"
	"github.com/hostryhq/svc-identity/internal/compose"
	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/internal/nopsql"
	"github.com/hostryhq/svc-identity/internal/token"
	"github.com/hostryhq/svc-identity/repository"
	"github.com/hostryhq/svc-identity/repository/memory"
	"github.com/hostryhq/svc-identity/service"
)

// Start is the fixed instant of the double's clock: the instant of the spec's examples.
var Start = time.Date(2026, 11, 24, 13, 5, 11, 120_000_000, time.UTC)

// Options configure a double.
type Options struct {
	// ExampleLiterals makes the double accept the literal placeholder credentials of the API
	// specification's examples ("assertion.example", "proof.example", "sig.example", TOTP 123456), as
	// the shared contract suite sends them. Tokens it issues are always real and verifiable.
	ExampleLiterals bool
	// LogOut receives the structured request log (default: discarded). Used by the redaction test.
	LogOut io.Writer
	// Store, AccessLog and Idem replace the in-memory repository, vendor access log and idempotency
	// store (the integration tests run the same assembly over Postgres). All three or none.
	Store     repository.Store
	AccessLog compose.AccessSink
	Idem      idempotency.Store
	// WithTenancy wires svc-tenancy's own double as the series registry (Double.Tenancy), so billing
	// devices are issued real series codes and the checks against the tenancy contract run. Off by
	// default: without it billing devices register with no series and no outlet check.
	WithTenancy bool
	// Config overrides the default configuration (keys and cheap PIN parameters are filled in).
	Config func(*service.Config)
}

// Double is a running in-memory identity service.
type Double struct {
	Handler  http.Handler
	Service  *service.Service
	Store    repository.Store
	Memory   *memory.Store // nil when Options.Store replaced the in-memory repository
	Clock    *testkit.FakeClock
	Signer   *token.Signer
	Services *authtest.ServiceRegistry
	SMS      *SMS
	Notices  *Notices
	Mail     *Mail
	Access   *memory.AccessLog
	Tenancy  *Tenancy // nil unless Options.WithTenancy
	Idem     idempotency.Store
	Verifier *auth.Verifier
}

// SMS is the recording SMS sender of the double. Sent codes are exposed through this Go API only;
// no HTTP route reads them (IC-09).
type SMS struct {
	mu   sync.Mutex
	sent []Message
}

// Message is one sent text.
type Message struct{ To, Text string }

// Send implements service.SMSSender.
func (s *SMS) Send(_ context.Context, to, text string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, Message{To: to, Text: text})
	return nil
}

// Real implements service.SMSSender: the double is never a real sender.
func (s *SMS) Real() bool { return false }

// Sent returns the messages sent so far.
func (s *SMS) Sent() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Message(nil), s.sent...)
}

// Last returns the most recent message to a number.
func (s *SMS) Last(to string) (Message, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.sent) - 1; i >= 0; i-- {
		if s.sent[i].To == to {
			return s.sent[i], true
		}
	}
	return Message{}, false
}

// Mail records emails (vendor setup links). Exposed through this Go API only.
type Mail struct {
	mu   sync.Mutex
	sent []Message
}

// Send implements service.MailSender: To is the address, Text the kind and the link token.
func (m *Mail) Send(_ context.Context, to, kind, link string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, Message{To: to, Text: kind + " " + link})
	return nil
}

// LastLink returns the most recent setup token sent to an address.
func (m *Mail) LastLink(to string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.sent) - 1; i >= 0; i-- {
		if m.sent[i].To == to {
			return strings.Fields(m.sent[i].Text)[1]
		}
	}
	return ""
}

// Notices records notifications.
type Notices struct {
	mu sync.Mutex
	n  []service.Notice
}

// Notify implements service.Notifier.
func (n *Notices) Notify(_ context.Context, x service.Notice) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.n = append(n.n, x)
}

// All returns the notices so far.
func (n *Notices) All() []service.Notice {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]service.Notice(nil), n.n...)
}

// seededReader is a deterministic randomness source for the double (never used outside it).
type seededReader struct {
	mu sync.Mutex
	n  uint64
}

func (r *seededReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range p {
		r.n = r.n*6364136223846793005 + 1442695040888963407
		p[i] = byte(r.n >> 56)
	}
	return len(p), nil
}

var _ io.Reader = (*seededReader)(nil)

// New builds a double.
func New(o Options) *Double {
	clk := testkit.NewClock()
	clk.Set(Start)
	mem := memory.New()
	mem.SetAuditDB(nopsql.DB())
	acc := &memory.AccessLog{}
	var st repository.Store = mem
	var accessSink compose.AccessSink = acc
	var idemStore idempotency.Store = idempotency.NewMemory()
	if o.Store != nil {
		st, accessSink, idemStore, mem = o.Store, o.AccessLog, o.Idem, nil
	}
	rnd := crypto.Random{R: &seededReader{n: 42}}

	cfg := service.DefaultConfig()
	cfg.Environment = "test"
	cfg.MACKey = fixedKey(1, 32)
	cfg.ProofEncKey = fixedKey(2, 32)
	cfg.TOTPKey = fixedKey(3, 32)
	cfg.PinParams = crypto.PinParams{Time: 1, MemoryK: 64}
	cfg.PasswordParams = crypto.PinParams{Time: 1, MemoryK: 64}
	opk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cfg.OpSigning = crypto.ToJWK(&opk.PublicKey)
	if o.Config != nil {
		o.Config(&cfg)
	}

	signer, err := token.NewEphemeral(rnd)
	if err != nil {
		panic(err)
	}
	var issuer service.TokenIssuer = signer
	var assertions service.AssertionVerifier = service.ES256Assertions{}
	if o.ExampleLiterals {
		cfg.ExampleLiterals = true
		cfg.ExtraPermissions = []string{"order.create", "bill.create", "order.read"}
		assertions = literalAssertions{inner: assertions}
	}
	logOut := o.LogOut
	if logOut == nil {
		logOut = io.Discard
	}
	sms, notes, mailer := &SMS{}, &Notices{}, &Mail{}
	var ten *Tenancy
	var tenClient service.Tenancy
	if o.WithTenancy {
		env, cl, err := newTenancy()
		if err != nil {
			panic(err)
		}
		ten, tenClient = env, cl
	}
	reg := authtest.NewServiceRegistry(clk, "sync", "admin")
	res, err := compose.Assemble(compose.Parts{
		Cfg: cfg, Store: st, AccessLog: accessSink, Idem: idemStore, Clock: clk, NewID: clk.IDs().New, Rand: rnd, SMS: sms, Notify: notes, Mail: mailer,
		Signer: signer, Tenancy: tenClient, Tokens: issuer, Assertions: assertions, Services: reg.Verifier("identity"), Log: slog.New(slog.NewJSONHandler(logOut, nil)),
	})
	if err != nil {
		panic(err)
	}
	return &Double{Handler: res.Handler, Service: res.Service, Store: st, Memory: mem, Clock: clk, Signer: signer, Services: reg, SMS: sms, Notices: notes, Mail: mailer, Access: acc, Tenancy: ten, Idem: idemStore, Verifier: res.Verifier}
}

func fixedKey(seed byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = seed*17 + byte(i)
	}
	return b
}

// ServeHTTP lets a Double be used directly as an http.Handler (httptest.NewServer(double.New(..))).
func (d *Double) ServeHTTP(w http.ResponseWriter, r *http.Request) { d.Handler.ServeHTTP(w, r) }

// UserToken mints a strong-session tenant token for a member with the given grants, valid at the
// double's clock. For tests of other services and of this one.
func (d *Double) UserToken(tenant ids.ID, member, device string, grants []auth.Grant, amr ...string) string {
	now := d.Clock.Now()
	if len(amr) == 0 {
		amr = []string{auth.AMROTP}
	}
	t, _ := d.Signer.Access(auth.Claims{Subject: member, Type: auth.TypeUser, TenantID: tenant.String(), DeviceID: device, SessionID: string(d.Clock.IDs().New()), AMR: amr,
		AuthTime: now.Unix(), Grants: grants, IssuedAt: now.Unix(), ExpiresAt: now.Add(15 * time.Minute).Unix(), JTI: string(d.Clock.IDs().New())})
	return t
}

// ServiceToken mints a service token from a caller (sync, admin) for the identity service.
func (d *Double) ServiceToken(caller string, tenant ids.ID) string {
	t, _ := d.Services.Signer(caller).Sign("identity", tenant.String())
	return t
}

var _ = binary.BigEndian
