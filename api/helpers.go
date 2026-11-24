package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/go-common/idempotency"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/go-common/tenancy"
	"github.com/hostryhq/svc-identity/service"
)

const maxBody = 1 << 20

// ---- authentication wrappers for the routes go-auth's Guard has no mode for ----

func refuse(w http.ResponseWriter, r *http.Request, why string) {
	apperr.WriteProblem(w, r, apperr.New(apperr.Unauthenticated, "auth.invalid_token", "invalid or missing credentials"))
	_ = why // the reason is for logs; the response never says which check failed
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// authenticated accepts any valid tenant-realm token of the listed types ("x-permission:
// authenticated": the operation has no permission of its own and authorises by who the caller is).
// A drain token is accepted only where listed (IST-24).
func (h *Handler) authenticated(types []auth.TokenType, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := bearerToken(r)
		if tok == "" {
			refuse(w, r, "no bearer")
			return
		}
		c, err := h.d.Tenant.Verify(tok)
		if err != nil || !slices.Contains(types, c.Type) {
			refuse(w, r, "token")
			return
		}
		tid, err := ids.Parse(c.TenantID)
		if err != nil {
			refuse(w, r, "tid")
			return
		}
		p := auth.NewPrincipal(c, tok)
		ctx := service.WithCaller(r.Context(), p)
		ctx = tenancy.With(ctx, tenancy.Context{TenantID: tid, ActorID: c.Subject, DeviceID: c.DeviceID})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// serviceCaller requires a valid service token from one of the callers (internal routes that carry
// no user token, such as the admin service's vendor sign-in).
func (h *Handler) serviceCaller(callers []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.d.Services == nil {
			refuse(w, r, "no registry")
			return
		}
		c, err := h.d.Services.Verify(r.Header.Get(auth.ServiceTokenHeader))
		if err != nil {
			refuse(w, r, "service token")
			return
		}
		if !slices.Contains(callers, c.Issuer) {
			apperr.WriteProblem(w, r, apperr.New(apperr.Forbidden, "auth.caller_not_allowed", "caller not allowed"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// vendorAuthenticated requires a valid vendor-realm user token.
func (h *Handler) vendorAuthenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := bearerToken(r)
		if tok == "" {
			refuse(w, r, "no bearer")
			return
		}
		c, err := h.d.Vendor.Verify(tok)
		if err != nil || c.Type != auth.TypeUser {
			refuse(w, r, "token")
			return
		}
		next.ServeHTTP(w, r.WithContext(service.WithCaller(r.Context(), auth.NewPrincipal(c, tok))))
	})
}

// ---- idempotency ----

type captured struct {
	status int
	header http.Header
	body   bytes.Buffer
}

func (c *captured) Header() http.Header         { return c.header }
func (c *captured) Write(b []byte) (int, error) { return c.body.Write(b) }
func (c *captured) WriteHeader(s int)           { c.status = s }

var errNotStored = errors.New("api: response not stored for replay")

// idempotent implements the Idempotency-Key contract (api-contract-standard): the first request
// with a key runs, a replay with the same request returns the stored response, the same key with a
// different request is 422 idempotency.mismatch. Failed requests (4xx other than validation, 5xx)
// are not stored, so a retry re-runs. The key is scoped per tenant; routes with no tenant use the
// zero scope and a key per caller address is not needed because the fingerprint binds the body.
func (h *Handler) idempotent(next http.Handler, spec routeSpec) http.Handler {
	mutating := !strings.HasPrefix(spec.Pattern, "GET ")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, ok, err := idempotency.KeyFromRequest(r)
		if err != nil {
			apperr.WriteProblem(w, r, err)
			return
		}
		if !mutating || !ok || h.d.Idem == nil {
			next.ServeHTTP(w, r)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil || len(body) > maxBody {
			apperr.WriteProblem(w, r, apperr.New(apperr.Validation, "validation.failed", "the request is invalid"))
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		scope := ids.ID(repoPlatform)
		if tc, ok := tenancy.From(r.Context()); ok {
			scope = tc.TenantID
		}
		var cap *captured
		resp, replayed, err := idempotency.Do(r.Context(), h.d.Idem, scope, key, idempotency.Fingerprint(r.Method, r.URL.Path, body), func() (idempotency.Response, error) {
			cap = &captured{status: http.StatusOK, header: http.Header{}}
			next.ServeHTTP(cap, r)
			if cap.status >= 500 || cap.status == http.StatusUnauthorized || cap.status == http.StatusTooManyRequests {
				return idempotency.Response{}, errNotStored
			}
			return idempotency.Response{Status: cap.status, ContentType: cap.header.Get("Content-Type"), Body: cap.body.Bytes()}, nil
		})
		switch {
		case errors.Is(err, errNotStored):
			copyHeaders(w.Header(), cap.header)
			w.WriteHeader(cap.status)
			_, _ = w.Write(cap.body.Bytes())
		case err != nil:
			apperr.WriteProblem(w, r, err)
		default:
			if replayed {
				h.auditReplay(w, r)
			}
			if resp.ContentType != "" {
				w.Header().Set("Content-Type", resp.ContentType)
			}
			if cap != nil && !replayed {
				copyHeaders(w.Header(), cap.header)
			}
			w.WriteHeader(resp.Status)
			_, _ = w.Write(resp.Body)
		}
	})
}

func copyHeaders(dst, src http.Header) {
	for k, v := range src {
		dst[k] = v
	}
}

// auditReplay records the access for a replayed vendor-authority request, which runs no handler:
// the vendor access log is a condition for the response (ADR-0013 V5).
func (h *Handler) auditReplay(_ http.ResponseWriter, r *http.Request) {
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok || !p.IsVendorActor() {
		return
	}
	tc, _ := tenancy.From(r.Context())
	_ = h.s.TouchAudited(r.Context(), tc.TenantID.String())
}

const repoPlatform = "00000000-0000-7000-8000-000000000000"

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
