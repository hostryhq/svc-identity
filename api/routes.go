// Package api is the controller layer: generated route registration, authentication and
// authorisation wiring (go-auth), request decoding and response mapping. It contains no business
// rules; every decision is made in package service.
package api

import (
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/go-common/clock"
	"github.com/hostryhq/go-common/health"
	"github.com/hostryhq/go-common/httpx"
	"github.com/hostryhq/go-common/idempotency"
	"github.com/hostryhq/go-common/logx"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/service"
)

type routeSpec struct {
	Pattern, Op, Permission string
	StepUp                  bool
	VendorClass             string
	VendorAudit             string
	Callers                 []string
}

// Deps are the collaborators of the HTTP layer.
type Deps struct {
	Svc       *service.Service
	Cat       *auth.Catalogue
	Tenant    *auth.Verifier // tenant-realm access tokens
	Vendor    *auth.Verifier // vendor-realm access tokens
	Services  *auth.ServiceVerifier
	Approvals *auth.ApprovalChecker
	Audit     auth.VendorAuditSink
	Clock     clock.Clock
	Idem      idempotency.Store
	Log       *slog.Logger
	// TrustedProxies are the addresses whose X-Forwarded-For is believed for per-IP limits (IST-06).
	TrustedProxies []netip.Prefix
	Health         *health.Handler
}

// Handler implements gen.ServerInterface.
type Handler struct {
	d Deps
	s *service.Service
}

// New builds the HTTP handler: every route is registered through go-auth's Guard (or one of the
// explicit wrappers for routes the guard has no mode for) and the table is validated at start-up.
func New(d Deps) http.Handler {
	h := &Handler{d: d, s: d.Svc}
	mux := http.NewServeMux()
	g := &auth.Guard{Catalogue: d.Cat, Tenant: d.Tenant, Vendor: d.Vendor, Services: d.Services, Approvals: d.Approvals,
		Audit: d.Audit, Clock: d.Clock, Log: d.Log}
	specs := map[string]routeSpec{}
	for _, r := range routeTable {
		specs[r.Pattern] = r
	}
	gen.HandlerWithOptions(h, gen.StdHTTPServerOptions{
		BaseRouter: &guardRouter{h: h, g: g, mux: mux, specs: specs, seen: map[string]bool{}},
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			apperr.WriteProblem(w, r, apperr.New(apperr.Validation, "validation.failed", "the request is invalid"))
		},
	})
	if d.Health != nil {
		d.Health.Register(mux)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		apperr.WriteProblem(w, r, apperr.New(apperr.NotFound, "resource.not_found", "resource not found"))
	})
	return httpx.Chain(mux, httpx.RequestID, httpx.Recover, h.accessLog)
}

// accessLog logs method, route and status only: no bodies, headers, query strings or numbers
// (IC-26). The path is logged without its query because query strings can carry identifiers.
func (h *Handler) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		if h.d.Log != nil {
			h.d.Log.LogAttrs(r.Context(), slog.LevelInfo, "request", slog.String("method", r.Method), slog.String("path", r.URL.Path),
				slog.Int("status", sw.status), slog.Duration("took", time.Since(start)))
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(c int) { w.status = c; w.ResponseWriter.WriteHeader(c) }

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func init() { // once, at start-up: the global is read by every request
	apperr.RequestIDFunc = func(r *http.Request) string { return logx.RequestID(r.Context()) }
}

// RouteCount is the number of operations the table registers (used by start-up and tests).
func RouteCount() int { return len(routeTable) }

// Operations lists every operationId of the table.
func Operations() []string {
	out := make([]string, 0, len(routeTable))
	for _, r := range routeTable {
		out = append(out, r.Op)
	}
	return out
}

// ApprovableOperation reports whether an operation may be filed for new-device approval: a
// strong_only or step-up operation of the tenant realm (A2.2 item 3).
func ApprovableOperation(cat *auth.Catalogue) func(string) bool {
	set := map[string]bool{}
	for _, r := range routeTable {
		if r.Callers != nil {
			continue
		}
		if p, ok := cat.Get(r.Permission); ok && (p.StrongOnly || r.StepUp) {
			set[r.Op] = true
		}
	}
	return func(op string) bool { return set[op] }
}

// guardRouter satisfies gen.ServeMux: the generated code registers each pattern here and we wrap
// the handler with the policy the spec declares for it.
type guardRouter struct {
	h     *Handler
	g     *auth.Guard
	mux   *http.ServeMux
	specs map[string]routeSpec
	seen  map[string]bool
}

func (gr *guardRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) { gr.mux.ServeHTTP(w, r) }

func (gr *guardRouter) HandleFunc(pattern string, fn func(http.ResponseWriter, *http.Request)) {
	spec, ok := gr.specs[pattern]
	if !ok {
		panic("api: route " + pattern + " has no entry in the generated policy table")
	}
	gr.seen[pattern] = true
	var inner http.Handler = http.HandlerFunc(fn)
	inner = gr.h.idempotent(inner, spec)
	realm := service.PermissionRealm(spec.Permission)
	switch {
	case spec.Permission == "public" && len(spec.Callers) == 0:
		gr.g.Handle(gr.mux, pattern, auth.Policy{Public: true}, inner)
	case spec.Permission == "public": // vendor sign-in and setup: the admin service's token is the credential
		gr.mux.Handle(pattern, gr.h.serviceCaller(spec.Callers, inner))
	case spec.Permission == "authenticated" && len(spec.Callers) == 0:
		types := []auth.TokenType{auth.TypeUser, auth.TypePin, auth.TypeDevice}
		if spec.Op == "getWipeOrder" {
			types = []auth.TokenType{auth.TypeDrain}
		}
		gr.mux.Handle(pattern, gr.h.authenticated(types, inner))
	case spec.Permission == "authenticated": // vendor session end: service token plus the vendor user's token
		gr.mux.Handle(pattern, gr.h.serviceCaller(spec.Callers, gr.h.vendorAuthenticated(inner)))
	case realm == "service":
		gr.g.Handle(gr.mux, pattern, auth.Policy{OperationID: spec.Op, ServiceOnly: true, Internal: true, Callers: spec.Callers, NoTenant: spec.Op == "listRevocations"}, inner)
	case realm == "vendor":
		gr.g.Handle(gr.mux, pattern, auth.Policy{OperationID: spec.Op, Permission: spec.Permission, StepUp: spec.StepUp, Internal: true, Callers: spec.Callers,
			Realm: auth.RealmVendor, VendorAuditNone: spec.VendorAudit == "none", DirectoryClass: spec.VendorClass == "directory"}, inner)
	default:
		gr.g.Handle(gr.mux, pattern, auth.Policy{OperationID: spec.Op, Permission: spec.Permission, StepUp: spec.StepUp}, inner)
	}
}
