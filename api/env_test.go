package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/authtest"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/go-common/testkit"
	"github.com/hostryhq/svc-identity/double"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/service"
)

var otpRE = regexp.MustCompile(`[0-9]{6}`)

// env is a double plus helpers for driving it over HTTP like a client would.
type env struct {
	t   *testing.T
	d   *double.Double
	ctx context.Context
	n   int
}

const (
	ownerMobile = "+919876543210"
	org         = testkit.TenantA
)

func newEnv(t *testing.T) *env {
	t.Helper()
	return &env{t: t, d: double.New(double.Options{}), ctx: context.Background()}
}

func (e *env) jti() string { e.n++; return fmt.Sprintf("jti-%d", e.n) }

// do sends a JSON request to the double and returns status and raw body.
func (e *env) do(method, path, token string, body any, hdr ...string) (int, []byte, http.Header) {
	e.t.Helper()
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
		e.n++
		req.Header.Set("Idempotency-Key", fmt.Sprintf("test-key-%d", e.n))
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	e.d.Handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes(), rec.Header()
}

func (e *env) mustJSON(status int, method, path, token string, body any, out any, hdr ...string) {
	e.t.Helper()
	code, b, _ := e.do(method, path, token, body, hdr...)
	if code != status {
		e.t.Fatalf("%s %s: status %d, want %d: %s", method, path, code, status, b)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			e.t.Fatalf("decode %s: %v (%s)", path, err, b)
		}
	}
}

func problemCode(b []byte) string {
	var p struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(b, &p)
	return p.Code
}

// expect asserts status and problem code.
func (e *env) expect(status int, code, method, path, token string, body any, hdr ...string) {
	e.t.Helper()
	got, b, _ := e.do(method, path, token, body, hdr...)
	if got != status || (code != "" && problemCode(b) != code) {
		e.t.Fatalf("%s %s: got %d %q, want %d %q (%s)", method, path, got, problemCode(b), status, code, b)
	}
}

func pub(d *double.Device) gen.PublicJwk {
	k := d.JWK()
	return gen.PublicJwk{Kty: gen.PublicJwkKtyEC, Crv: gen.PublicJwkCrvP256, X: k.X, Y: k.Y}
}

// signIn runs the whole OTP sign-in for a number on a device and returns the session.
func (e *env) signIn(mobile string, dev *double.Device) gen.Session {
	e.t.Helper()
	var ch gen.OtpChallenge
	e.mustJSON(202, "POST", "/v1/otp-challenges", "", gen.CreateOtpChallenge{MobileE164: mobile, DeviceId: dev.ID, DevicePublicKey: pub(dev)}, &ch)
	msg, ok := e.d.SMS.Last(mobile)
	if !ok {
		e.t.Fatalf("no SMS sent to %s", mobile)
	}
	code := otpRE.FindString(msg.Text)
	var s gen.Session
	e.mustJSON(201, "POST", "/v1/sessions", "", gen.CreateSession{GrantType: gen.CreateSessionGrantTypeOtp, ChallengeId: ch.Id, Code: code, DeviceId: dev.ID,
		DeviceAssertion: dev.Assert(e.d.Clock.Now(), e.jti(), service.AssertionClaims{Cid: ch.Id})}, &s)
	return s
}

// ownerSession seeds an invitation for the owner number and signs in on a fresh device.
func (e *env) ownerSession() (gen.Session, *double.Device) {
	e.t.Helper()
	if _, _, err := e.d.Service.Seed().OwnerInvitation(e.ctx, org.String(), ownerMobile, "Asha"); err != nil {
		e.t.Fatal(err)
	}
	dev := double.NewDevice(string(ids.New()))
	return e.signIn(ownerMobile, dev), dev
}

func mustUnmarshal(t *testing.T, b []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("decode: %v (%s)", err, b)
	}
}

func seedMember(id, name, roleID string) service.SeedMember {
	return service.SeedMember{ID: id, Name: name, Assignments: []service.SeedAssignment{{ID: newID(), RoleID: roleID}}}
}

func grantsAll() []auth.Grant { return authtest.OwnerGrants() }
