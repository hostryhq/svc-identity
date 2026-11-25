package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/go-common/idempotency"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/go-common/tenancy"
)

// TxIdempotency is implemented by a store that can claim the key, run the business writes and store
// the result in ONE database transaction (go-common idempotency.DoTx): a crash cannot leave a key
// stuck, and a failed request leaves nothing behind. The context passed to fn carries that
// transaction; the repository joins it. Other stores use Begin, Complete and Release.
type TxIdempotency interface {
	RunTx(ctx context.Context, tenant ids.ID, key, fingerprint string, fn func(ctx context.Context) (idempotency.TxResult, error)) (idempotency.Response, bool, error)
}

// notStored says the response is not kept for replay. keepWork distinguishes a refused attempt (401,
// 429), whose failure counters must still commit, from a server error, which rolls the request back.
type notStored struct{ keepWork bool }

func (e *notStored) Error() string   { return "api: response not stored for replay" }
func (e *notStored) KeepsWork() bool { return e.keepWork }

// ErrReplaySecret is the answer to a replay whose original response carried a secret: the secret is
// never stored, so it cannot be returned again (SR-H4). The client starts the operation afresh.
var errReplaySecret = apperr.New(apperr.Conflict, "idempotency.replay_secret",
	"this request already succeeded and its response carried a one-time secret that is not kept; repeat the operation with a new Idempotency-Key")

// omittedMarker prefixes the stored content type of a response whose body was deliberately not kept.
const omittedMarker = "x-omitted;"

// rerunOps never store a response: a replay runs the handler again, so a replayed refresh goes through
// reuse detection and a replayed sign-in is refused (its challenge, code or assertion is spent). These
// are the token-issuing operations.
var rerunOps = map[string]bool{
	"createSession": true, "refreshSession": true, "createDeviceToken": true, "createDrainToken": true,
	"createVendorSession": true, "renewVendorSession": true,
}

var secretKeyRE = regexp.MustCompile(`(?i)token|secret|half|grant|handle|offline_pack|provisioning|password|verifier|setup|^code$`)

// carriesSecret reports whether a successful response body holds a token, code, half, handle, grant,
// pack or other one-time secret, judged by the JSON member names. It is a safety net on top of
// rerunOps: any new operation that returns such a member is withheld without being listed.
func carriesSecret(status int, body []byte) bool {
	if status >= 400 || len(body) == 0 {
		return false
	}
	var v any
	if json.Unmarshal(body, &v) != nil {
		return true // not JSON we can inspect: keep nothing
	}
	return hasSecretKey(v)
}

func hasSecretKey(v any) bool {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if secretKeyRE.MatchString(k) || hasSecretKey(x) {
				return true
			}
		}
	case []any:
		for _, x := range t {
			if hasSecretKey(x) {
				return true
			}
		}
	}
	return false
}

// idempotent implements the Idempotency-Key contract (api-contract-standard): the first request with
// a key runs, a replay with the same request returns the stored response, the same key with a
// different request is 422 idempotency.mismatch. Rules (SR-H4, M1):
//   - responses that carry a token, refresh token, code, half, grant or pack are never stored: the
//     record keeps only status, content type and a body fingerprint, and a replay is 409
//     idempotency.replay_secret;
//   - token-issuing operations are not recorded at all, so a replay re-runs them;
//   - records expire after 24 hours;
//   - with a transactional store the claim, the business writes and the result commit together.
//
// Failed requests (401, 429, 5xx) are not stored, so a retry re-runs. 5xx rolls the whole request
// back; 401 and 429 keep their failure counters. The key is scoped per tenant.
func (h *Handler) idempotent(next http.Handler, spec routeSpec) http.Handler {
	mutating := !strings.HasPrefix(spec.Pattern, "GET ")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, ok, err := idempotency.KeyFromRequest(r)
		if err != nil {
			apperr.WriteProblem(w, r, err)
			return
		}
		if !mutating || !ok || h.d.Idem == nil || rerunOps[spec.Op] {
			next.ServeHTTP(w, r)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil || len(body) > maxBody {
			apperr.WriteProblem(w, r, apperr.New(apperr.Validation, "validation.failed", "the request is invalid"))
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		scope := ids.ID(noTenantScope)
		if tc, ok := tenancy.From(r.Context()); ok {
			scope = tc.TenantID
		}
		fp := idempotency.Fingerprint(r.Method, r.URL.Path, body)
		var cap *captured
		run := func(ctx context.Context) (idempotency.TxResult, error) {
			cap = &captured{status: http.StatusOK, header: http.Header{}}
			next.ServeHTTP(cap, r.WithContext(ctx))
			switch {
			case cap.status >= 500:
				return idempotency.TxResult{}, &notStored{}
			case cap.status == http.StatusUnauthorized || cap.status == http.StatusTooManyRequests:
				return idempotency.TxResult{}, &notStored{keepWork: true}
			}
			return idempotency.TxResult{
				Response: idempotency.Response{Status: cap.status, ContentType: cap.header.Get("Content-Type"), Body: cap.body.Bytes()},
				OmitBody: carriesSecret(cap.status, cap.body.Bytes()),
			}, nil
		}
		var resp idempotency.Response
		var replayed bool
		// The transactional store is used for requests that run in the caller's own transaction.
		// Requests on a vendor user's authority and internal routes run in go-auth's audited
		// transaction and use the claim-and-complete form.
		p, _ := auth.PrincipalFrom(r.Context())
		if ts, ok := h.d.Idem.(TxIdempotency); ok && len(spec.Callers) == 0 && !p.IsVendorActor() {
			resp, replayed, err = ts.RunTx(r.Context(), scope, key, fp, run)
		} else {
			resp, replayed, err = h.claimAndComplete(r.Context(), scope, key, fp, run)
		}
		var ns *notStored
		switch {
		case errors.As(err, &ns) || (err == nil && !replayed && cap != nil && resp.Status == 0):
			copyHeaders(w.Header(), cap.header)
			w.WriteHeader(cap.status)
			_, _ = w.Write(cap.body.Bytes())
		case err != nil && !errors.Is(err, idempotency.ErrBodyOmitted):
			apperr.WriteProblem(w, r, err)
		default:
			if replayed {
				if aerr := h.auditReplay(r, spec, body); aerr != nil {
					writeErr(w, r, aerr)
					return
				}
			}
			if errors.Is(err, idempotency.ErrBodyOmitted) {
				apperr.WriteProblem(w, r, errReplaySecret)
				return
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

// claimAndComplete is the generic form over idempotency.Store: claim, run, store. A body that must
// not be kept is stored as status and content type only, marked omitted. The store expires records
// and takes over stale claims.
func (h *Handler) claimAndComplete(ctx context.Context, scope ids.ID, key, fp string, run func(context.Context) (idempotency.TxResult, error)) (idempotency.Response, bool, error) {
	prev, started, err := h.d.Idem.Begin(ctx, scope, key, fp)
	if err != nil {
		return idempotency.Response{}, false, err
	}
	if !started {
		if strings.HasPrefix(prev.ContentType, omittedMarker) {
			return idempotency.Response{Status: prev.Status}, true, idempotency.ErrBodyOmitted
		}
		return *prev, true, nil
	}
	res, err := run(ctx)
	if err != nil {
		_ = h.d.Idem.Release(ctx, scope, key)
		return idempotency.Response{}, false, err
	}
	stored := res.Response
	if res.OmitBody {
		stored = idempotency.Response{Status: stored.Status, ContentType: omittedMarker + stored.ContentType}
	}
	if err := h.d.Idem.Complete(ctx, scope, key, stored); err != nil {
		return idempotency.Response{}, false, err
	}
	return res.Response, false, nil
}
