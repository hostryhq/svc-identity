// Package compose wires the service and HTTP layers from their ports. The real service (Postgres,
// system clock, configured keys), the test double (in-memory, fake clock) and the integration and
// contract tests all assemble through it, so they run the same code.
package compose

import (
	"log/slog"
	"net/http"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/grantlimit"
	"github.com/hostryhq/go-common/clock"
	"github.com/hostryhq/go-common/health"
	"github.com/hostryhq/go-common/idempotency"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/svc-identity/api"
	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/internal/token"
	"github.com/hostryhq/svc-identity/repository"
	"github.com/hostryhq/svc-identity/service"
)

// AccessSink records vendor access: organisation rows (VendorAuditSink) and organisation-less rows in a
// platform table with no tenant (PlatformAuditSink).
type AccessSink interface {
	auth.VendorAuditSink
	auth.PlatformAuditSink
}

// Parts are the collaborators to assemble.
type Parts struct {
	Cfg        service.Config
	Store      repository.Store
	AccessLog  AccessSink
	Idem       idempotency.Store
	Clock      clock.Clock
	NewID      func() ids.ID
	Rand       crypto.Random
	SMS        service.SMSSender
	Notify     service.Notifier
	Mail       service.MailSender
	Signer     *token.Signer
	Tokens     service.TokenIssuer // defaults to Signer
	Assertions service.AssertionVerifier
	Services   *auth.ServiceVerifier
	// Tenancy issues document-series codes for billing devices (nil: none are issued).
	Tenancy  service.Tenancy
	Log      *slog.Logger
	Health   *health.Handler
	SMSAsync bool
}

// Result is the assembled service.
type Result struct {
	Service  *service.Service
	Handler  http.Handler
	Verifier *auth.Verifier // tenant-realm verifier (this service's own keys)
	Catalog  *auth.Catalogue
}

// Assemble builds the service, runs its start-up check and builds the HTTP handler.
func Assemble(p Parts) (*Result, error) {
	cat, err := service.NewCatalogue(p.Cfg.ExtraPermissions...)
	if err != nil {
		return nil, err
	}
	if p.Tokens == nil {
		p.Tokens = p.Signer
	}
	if p.Assertions == nil {
		p.Assertions = service.ES256Assertions{}
	}
	svc := &service.Service{Cfg: p.Cfg, Store: p.Store, Clock: p.Clock, NewID: p.NewID, Rand: p.Rand, SMS: p.SMS, Notify: p.Notify, Mail: p.Mail,
		Tokens: p.Tokens, Cat: cat, Grants: grantlimit.Evaluator{Catalogue: cat}, Assertions: p.Assertions, Approvable: api.ApprovableOperation(cat), SMSAsync: p.SMSAsync, Tenancy: p.Tenancy}
	if err := svc.StartupCheck(); err != nil {
		return nil, err
	}
	tenant := &auth.Verifier{Keys: p.Signer.TenantKeys(), Issuer: token.TenantIssuer, Audience: token.TenantAudience, Realm: auth.RealmTenant, Clock: p.Clock}
	approvals := &auth.ApprovalChecker{Verifier: &auth.Verifier{Keys: p.Signer.TenantKeys(), Issuer: token.TenantIssuer, Audience: token.TenantAudience, Realm: auth.RealmTenant, Clock: p.Clock},
		Used: auth.NewMemorySingleUse(p.Clock)}
	h := api.New(api.Deps{
		Svc: svc, Cat: cat, Tenant: tenant,
		Vendor:    &auth.Verifier{Keys: p.Signer.VendorKeys(), Issuer: token.VendorIssuer, Audience: token.VendorAudience, Realm: auth.RealmVendor, Clock: p.Clock},
		Services:  p.Services,
		Approvals: approvals, Audit: p.AccessLog, PlatformAudit: p.AccessLog, Clock: p.Clock, Idem: p.Idem, Log: p.Log, Health: p.Health,
	})
	return &Result{Service: svc, Handler: h, Verifier: tenant, Catalog: cat}, nil
}
