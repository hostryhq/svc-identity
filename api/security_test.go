package api_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hostryhq/svc-identity/double"
	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/service"
)

// IST-38: drive endpoints with synthetic secrets and a synthetic number; captured logs hold none of them.
func TestLogsHoldNoSecretsOrNumbers(t *testing.T) {
	var buf bytes.Buffer
	e := &env{t: t, d: double.New(double.Options{LogOut: &buf}), ctx: ctxBackground()}
	owner, dev := e.ownerSession()
	const synthPIN, synthPhone = "973246", "+919000000000"
	staff, roleID := newID(), newID()
	_ = e.d.Service.Seed().Role(e.ctx, org.String(), roleID, "Cashier", []string{"member.read"})
	e.mustJSON(201, "POST", "/v1/members", owner.Tokens.AccessToken, gen.CreateMember{Id: staff, DisplayName: "Ravi", MobileE164: strPtr(synthPhone)}, nil)
	var auth gen.PinResetAuthorisation
	e.mustJSON(201, "POST", "/v1/members/"+staff+"/pin-reset-authorisations", owner.Tokens.AccessToken, nil, &auth)
	_ = dev
	e.do("PUT", "/v1/members/"+staff+"/pin", owner.Tokens.AccessToken, gen.SetPin{DeviceId: newID(), Pin: synthPIN, PinResetAuthorisationId: &auth.Id})
	e.do("POST", "/v1/otp-challenges", "", map[string]any{"mobile_e164": synthPhone})
	logs := buf.String()
	if logs == "" {
		t.Fatal("expected request logs")
	}
	for _, secret := range []string{synthPIN, synthPhone, "9000000000", owner.Tokens.AccessToken, *owner.Tokens.RefreshToken} {
		if strings.Contains(logs, secret) {
			t.Fatalf("logs contain a secret or number: %q", secret)
		}
	}
}

// IST-06: X-Forwarded-For is believed only from a trusted proxy; a direct client cannot dodge per-IP limits.
func TestForwardedForIgnoredFromUntrustedPeer(t *testing.T) {
	e := newEnv(t)
	dev := double.NewDevice(newID())
	// The per-IP cap is 40 per day; spoofing a new address per request must not reset it.
	for i := 0; i < 40; i++ {
		e.d.Clock.Advance(16 * time.Minute)
		code, _, _ := e.do("POST", "/v1/otp-challenges", "", gen.CreateOtpChallenge{MobileE164: fmt.Sprintf("+9198765%05d", i), DeviceId: newID(), DevicePublicKey: pub(dev)},
			"X-Forwarded-For", "10.9.9."+string(rune('0'+i%10)))
		_ = code
	}
	// The 41st request from the same peer is refused whatever header it carries.
	e.d.Clock.Advance(16 * time.Minute)
	code, _, _ := e.do("POST", "/v1/otp-challenges", "", gen.CreateOtpChallenge{MobileE164: "+919876511111", DeviceId: newID(), DevicePublicKey: pub(dev)}, "X-Forwarded-For", "10.8.8.8")
	if code != 429 {
		t.Fatalf("per-IP limit dodged with X-Forwarded-For: %d", code)
	}
}

// IST-15: owner recovery. Off by default; two vendor users; 24-hour delay on identity's clock; the number
// changes only at completion, all sessions end, and no session is ever issued by recovery.
func TestOwnerRecoveryDelayAndCompletion(t *testing.T) {
	e := &env{t: t, d: double.New(double.Options{Config: func(c *service.Config) { c.RecoveryEnabled = true }}), ctx: ctxBackground()}
	admin := e.bootstrapAdmin("root@hostry.test")
	owner, devOwner := e.ownerSession()
	second := e.newVendorUser(admin, "second@hostry.test", gen.PlatformAdmin)
	e.d.Clock.Advance(8 * 24 * time.Hour)
	e.signInVendor(admin)
	e.signInVendor(second)
	newMobile := "+919876500777"
	var ap gen.VendorApproval
	req := gen.CreateVendorApproval{Kind: gen.ApprovalKindOwnerRecovery, OrganisationId: org.String(), MobileE164: strPtr(ownerMobile), NewMobileE164: strPtr(newMobile), Reason: "Owner lost the SIM card",
		TicketReference: "ONB-9", VerificationMethod: gen.RequesterVerificationCallbackToRegisteredNumber}
	e.mustJSON(201, "POST", "/internal/v1/vendor/approvals", admin.tok, req, &ap, admin.h(e)...)
	e.d.Clock.Advance(31 * time.Second)
	var dec gen.ApprovalDecision
	e.mustJSON(200, "PUT", "/internal/v1/vendor/approvals/"+ap.Id+"/decision", second.tok, gen.ApproveVendorApproval{TotpCode: crypto.TOTP(second.secret, e.d.Clock.Now())}, &dec, second.h(e)...)
	if dec.Approval.CompletesAt == nil || dec.Approval.CompletesAt.Sub(e.d.Clock.Now()) != 24*time.Hour {
		t.Fatalf("delay: %+v", dec.Approval)
	}
	// Nothing happens early.
	e.d.Clock.Advance(23 * time.Hour)
	if n, _ := e.d.Service.CompleteDueRecoveries(e.ctx); n != 0 {
		t.Fatal("recovery completed before its delay")
	}
	// The number is unchanged: the old number still gets an OTP, the new one does not.
	nd := double.NewDevice(newID())
	e.mustJSON(202, "POST", "/v1/otp-challenges", "", gen.CreateOtpChallenge{MobileE164: newMobile, DeviceId: nd.ID, DevicePublicKey: pub(nd)}, nil)
	if _, ok := e.d.SMS.Last(newMobile); ok {
		t.Fatal("SMS to the new number before completion")
	}
	e.d.Clock.Advance(61 * time.Minute)
	if n, err := e.d.Service.CompleteDueRecoveries(e.ctx); err != nil || n != 1 {
		t.Fatalf("completion: %d %v", n, err)
	}
	// Recovery never issues a session: the old refresh token is revoked, the person signs in on the new number with a normal OTP (and is under caution).
	e.expect(401, "", "POST", "/v1/tokens/refresh", "", gen.RefreshSession{RefreshToken: *owner.Tokens.RefreshToken, DeviceId: devOwner.ID,
		Proof: devOwner.Assert(e.d.Clock.Now(), e.jti(), service.AssertionClaims{Rth: service.RefreshHash(*owner.Tokens.RefreshToken)})})
	e.d.Clock.Advance(40 * time.Second)
	s := e.signIn(newMobile, double.NewDevice(newID()))
	if s.CautionUntil == nil {
		t.Fatal("first sign-in on the new number must be under caution")
	}
}
