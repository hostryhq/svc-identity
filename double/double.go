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
	"sync"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/authtest"
	"github.com/hostryhq/go-auth/grantlimit"
	"github.com/hostryhq/go-common/idempotency"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/go-common/testkit"
	"github.com/hostryhq/svc-identity/api"
	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/internal/nopsql"
	"github.com/hostryhq/svc-identity/internal/token"
	"github.com/hostryhq/svc-identity/repository/memory"
	"github.com/hostryhq/svc-identity/service"
)

// Start is the fixed instant of the double's clock: the instant of the spec's examples.
var Start = time.Date(2026, 11, 24, 13, 5, 11, 120_000_000, time.UTC)

// Options configure a double.
type Options struct {
	// LiteralTokens makes the double issue the spec's literal example tokens ("tok_example_access")
	// and accept the literal example assertions and proofs. It exists only for the contract run
	// (the contract requires a double to serve the spec's examples); such a double issues no
	// verifiable token and must not be used by other services' tests.
	LiteralTokens bool
	// Config overrides the default configuration (keys and cheap PIN parameters are filled in).
	Config func(*service.Config)
}

// Double is a running in-memory identity service.
type Double struct {
	Handler  http.Handler
	Service  *service.Service
	Store    *memory.Store
	Clock    *testkit.FakeClock
	Signer   *token.Signer
	Services *authtest.ServiceRegistry
	SMS      *SMS
	Notices  *Notices
	Access   *memory.AccessLog
	Idem     *idempotency.Memory
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
	st := memory.New()
	st.SetAuditDB(nopsql.DB())
	acc := &memory.AccessLog{}
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
	if o.LiteralTokens {
		issuer = token.Literal{Inner: signer}
		assertions = literalAssertions{inner: assertions}
	}
	cat, err := service.NewCatalogue()
	if err != nil {
		panic(err)
	}
	sms := &SMS{}
	notes := &Notices{}
	ids := clk.IDs()
	svc := &service.Service{
		Cfg: cfg, Store: st, Clock: clk, NewID: ids.New, Rand: rnd, SMS: sms, Notify: notes, Tokens: issuer, Cat: cat,
		Grants: grantlimit.Evaluator{Catalogue: cat}, Assertions: assertions, Approvable: api.ApprovableOperation(cat),
	}
	if err := svc.StartupCheck(); err != nil {
		panic(err)
	}
	reg := authtest.NewServiceRegistry(clk, "sync", "admin")
	idem := idempotency.NewMemory()
	verifier := &auth.Verifier{Keys: signer.TenantKeys(), Issuer: token.TenantIssuer, Audience: token.TenantAudience, Realm: auth.RealmTenant, Clock: clk}
	h := api.New(api.Deps{
		Svc: svc, Cat: cat,
		Tenant:    verifier,
		Vendor:    &auth.Verifier{Keys: signer.VendorKeys(), Issuer: token.VendorIssuer, Audience: token.VendorAudience, Realm: auth.RealmVendor, Clock: clk},
		Services:  reg.Verifier("identity"),
		Approvals: &auth.ApprovalChecker{Verifier: &auth.Verifier{Keys: signer.TenantKeys(), Issuer: token.TenantIssuer, Audience: token.TenantAudience, Realm: auth.RealmTenant, Clock: clk}, Used: auth.NewMemorySingleUse(clk)},
		Audit:     acc, Clock: clk, Idem: idem, Log: slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	return &Double{Handler: h, Service: svc, Store: st, Clock: clk, Signer: signer, Services: reg, SMS: sms, Notices: notes, Access: acc, Idem: idem, Verifier: verifier}
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
