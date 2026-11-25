package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/svc-identity/service"
)

const maxBody = 1 << 20

// ---- idempotency ----

type captured struct {
	status int
	header http.Header
	body   bytes.Buffer
}

func (c *captured) Header() http.Header         { return c.header }
func (c *captured) Write(b []byte) (int, error) { return c.body.Write(b) }
func (c *captured) WriteHeader(s int)           { c.status = s }

func copyHeaders(dst, src http.Header) {
	for k, v := range src {
		dst[k] = v
	}
}

// platformAuditOps are the organisation-less vendor routes: their access row goes to the platform
// table with no tenant (go-auth Policy.PlatformAudit). Everything else on a vendor route names its
// organisation, through the path or, for startSupportSession, the body.
var platformAuditOps = map[string]bool{
	"listVendorUsers": true, "createVendorUser": true, "updateVendorUser": true, "resetVendorUserTotp": true,
	"listVendorAuditEntries": true, "lookupOrganisationsByOwnerMobile": true, "endVendorSession": true,
	"createVendorApproval": true, "listVendorApprovals": true, "getVendorApproval": true, "approveVendorApproval": true,
	"claimCodeHalf": true, "cancelVendorApproval": true, "issueVendorApprovalGrant": true,
	"getSupportSession": true, "renewSupportToken": true, "endSupportSession": true,
}

// PlatformAuditOp reports whether an operation is recorded in the platform access log.
func PlatformAuditOp(op string) bool { return platformAuditOps[op] }

// noTenantScope is the idempotency-key scope of routes with no tenant. The key table is not tenant
// data; this is a scope label, not a tenant.
const noTenantScope = "00000000-0000-7000-8000-000000000000"

// auditReplay records the access for a replayed vendor-authority request, which runs no handler:
// the vendor access log is a condition for the response (ADR-0013 V5). It fails closed.
func (h *Handler) auditReplay(r *http.Request, spec routeSpec, body []byte) error {
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok || !p.IsVendorActor() {
		return nil
	}
	if platformAuditOps[spec.Op] {
		return h.s.TouchAudited(r.Context(), "")
	}
	org := r.PathValue("organisation_id")
	if org == "" {
		var b struct {
			Org string `json:"organisation_id"`
		}
		_ = json.Unmarshal(body, &b)
		org = b.Org
	}
	ctx, err := h.s.VendorOrgContext(r.Context(), spec.Permission, org)
	if err != nil {
		return err
	}
	return h.s.TouchAudited(ctx, org)
}

// ---- request and response helpers ----

// decode reads a JSON body strictly: unknown fields and trailing data are refused with 422.
func decode[T any](r *http.Request, v *T) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return apperr.New(apperr.Validation, "validation.failed", "the request body is invalid")
	}
	if dec.More() {
		return apperr.New(apperr.Validation, "validation.failed", "the request body is invalid")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func writeErr(w http.ResponseWriter, r *http.Request, err error) {
	var ra *service.RetryAfterError
	if errors.As(err, &ra) {
		w.Header().Set("Retry-After", strconv.Itoa(int(ra.After.Seconds())+1))
	}
	var nx *service.NotExecutableError
	if errors.As(err, &nx) {
		p := apperr.ToProblem(r, err)
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(p.Status)
		_ = json.NewEncoder(w).Encode(struct {
			apperr.Problem
			Reason string `json:"reason"`
		}{p, nx.Reason})
		return
	}
	apperr.WriteProblem(w, r, err)
}

// do decodes the body into In, calls fn and writes the result with the success status.
func do[In, Out any](w http.ResponseWriter, r *http.Request, status int, fn func(In) (Out, error)) {
	var in In
	if err := decode(r, &in); err != nil {
		writeErr(w, r, err)
		return
	}
	out, err := fn(in)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, status, out)
}

// call runs a bodyless operation that returns a value.
func call[Out any](w http.ResponseWriter, r *http.Request, status int, fn func() (Out, error)) {
	out, err := fn()
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, status, out)
}

// noContent runs an operation that answers 204.
func noContent(w http.ResponseWriter, r *http.Request, fn func() error) {
	if err := fn(); err != nil {
		writeErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func notImplemented(w http.ResponseWriter, r *http.Request) {
	apperr.WriteProblem(w, r, apperr.New(apperr.Unavailable, "not_implemented", "this operation is not implemented yet"))
}

// clientAddr is the address used for per-IP limits. X-Forwarded-For is believed only when the
// connection comes from a trusted proxy (IST-06).
func (h *Handler) clientAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, perr := netip.ParseAddr(host)
	if perr == nil {
		for _, p := range h.d.TrustedProxies {
			if p.Contains(peer) {
				if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
					parts := strings.Split(xff, ",")
					last := strings.TrimSpace(parts[len(parts)-1]) // the address the trusted proxy saw
					if a, err := netip.ParseAddr(last); err == nil {
						return a.String()
					}
				}
			}
		}
	}
	return host
}
