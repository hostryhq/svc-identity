package api_test

import (
	"context"
	"testing"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/authtest"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/svc-identity/double"
	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/service"
)

// ownerCtx is a service-level context of a member with the given grants (there is no HTTP route for
// RevokeActivationCode yet).
func (e *env) ownerCtx(tenant ids.ID, member string, grants []auth.Grant) context.Context {
	e.t.Helper()
	p := auth.NewPrincipal(&auth.Claims{Subject: member, Type: auth.TypeUser, Realm: auth.RealmTenant, TenantID: tenant.String(), Grants: grants}, "")
	return authtest.Context(e.ctx, e.d.Service.Cat, e.d.Clock, p)
}

// Security re-review, idempotency.replay_secret (a): a code whose reply was lost is orphaned, and it
// does not stay live. It expires in 10 minutes, and the owner can withdraw it by id at once. A used
// code cannot be withdrawn, and another organisation cannot touch it.
func TestOrphanedActivationCodeExpiresAndCanBeRevoked(t *testing.T) {
	e := newEnv(t)
	owner, _ := e.ownerSession()
	tok := owner.Tokens.AccessToken
	redeem := func(code string) int {
		var n gen.DeviceNonce
		e.mustJSON(201, "POST", "/v1/device-nonces", "", nil, &n)
		d := double.NewDevice(newID())
		c, _, _ := e.do("POST", "/v1/device-activations", "", gen.ActivateDevice{ActivationCode: code, Id: d.ID, Name: "Till", PublicKey: pub(d), KeyProtection: gen.Hardware, Nonce: n.Nonce, NonceSignature: d.SignNonce(n.Nonce)})
		return c
	}
	mk := func(key string) gen.ActivationCode {
		var c gen.ActivationCode
		e.mustJSON(201, "POST", "/v1/activation-codes", tok, gen.CreateActivationCode{OutletId: outletA, Kind: gen.Pos}, &c, "Idempotency-Key", key)
		return c
	}

	// Lost reply: the retry is refused with replay_secret, so nobody holds the code. It lapses by itself.
	lapsing := mk("orphan-1")
	e.expect(409, "idempotency.replay_secret", "POST", "/v1/activation-codes", tok, gen.CreateActivationCode{OutletId: outletA, Kind: gen.Pos}, "Idempotency-Key", "orphan-1")
	e.d.Clock.Advance(11 * time.Minute)
	if c := redeem(lapsing.Code); c != 422 {
		t.Fatalf("an orphaned code must lapse after 10 minutes: %d", c)
	}

	// The owner withdraws a fresh orphan by id before that.
	revoked := mk("orphan-2")
	oc := e.ownerCtx(org, owner.MemberId, grantsAll())
	if _, err := e.d.Service.RevokeActivationCode(oc, revoked.Id); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := e.d.Service.RevokeActivationCode(oc, revoked.Id); err != nil {
		t.Fatalf("revoking twice is a no-op: %v", err)
	}
	if c := redeem(revoked.Code); c != 422 {
		t.Fatalf("a revoked code must not redeem: %d", c)
	}

	// A redeemed code cannot be withdrawn (revoke the device); an unknown id and another tenant's id are 404.
	used := mk("orphan-3")
	if c := redeem(used.Code); c != 201 {
		t.Fatalf("redeem: %d", c)
	}
	if _, err := e.d.Service.RevokeActivationCode(oc, used.Id); err == nil {
		t.Fatal("a used code must not be revoked")
	}
	other := e.ownerCtx(ids.ID("0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a99"), "someone", grantsAll())
	live := mk("orphan-4")
	if _, err := e.d.Service.RevokeActivationCode(other, live.Id); err == nil {
		t.Fatal("another organisation must not revoke the code")
	}
	if _, err := e.d.Service.RevokeActivationCode(oc, newID()); err == nil {
		t.Fatal("an unknown id must be refused")
	}
	// A member without the create permission for the outlet cannot withdraw it either.
	weak := e.ownerCtx(org, "staff", authtest.Grants([]string{outletA}, "member.read"))
	if _, err := e.d.Service.RevokeActivationCode(weak, live.Id); err == nil {
		t.Fatal("a member without device.activation_code.create must not revoke")
	}
	if c := redeem(live.Code); c != 201 {
		t.Fatalf("the refused revokes must leave the code live: %d", c)
	}
}

// Security re-review, idempotency.replay_secret (b): the activation reply is lost (the retry gets
// replay_secret and H3 forbids reusing the device id with other data). The device is not stranded:
//  1. it asks for a device token with its own key (assertion) and fetches the pack: no code needed;
//  2. or it repeats the same activation (same id, key and code) with a new Idempotency-Key and gets
//     the pack of that activation back;
//  3. a different key on that code or id is refused, and re-registering under a new id needs a new
//     code, after the owner revokes the old device if its key is to be reused.
func TestActivationReplySecretLostDeviceRecovers(t *testing.T) {
	e := newEnv(t)
	owner, _ := e.ownerSession()
	tok := owner.Tokens.AccessToken
	dev := double.NewDevice(newID())
	var code gen.ActivationCode
	e.mustJSON(201, "POST", "/v1/activation-codes", tok, gen.CreateActivationCode{OutletId: outletA, Kind: gen.Pos}, &code)
	var n gen.DeviceNonce
	e.mustJSON(201, "POST", "/v1/device-nonces", "", nil, &n)
	req := gen.ActivateDevice{ActivationCode: code.Code, Id: dev.ID, Name: "Counter 1", PublicKey: pub(dev), KeyProtection: gen.OsSoftware, Nonce: n.Nonce, NonceSignature: dev.SignNonce(n.Nonce)}
	var first gen.DeviceActivation
	e.mustJSON(201, "POST", "/v1/device-activations", "", req, &first, "Idempotency-Key", "act-1") // the reply never arrives
	e.expect(409, "idempotency.replay_secret", "POST", "/v1/device-activations", "", req, "Idempotency-Key", "act-1")

	// 1. Recovery with a device token: the pack is fetched, not re-activated.
	var dtok gen.DeviceToken
	e.mustJSON(200, "POST", "/v1/tokens/device", "", gen.DeviceGrant{GrantType: gen.DeviceGrantGrantTypeDevice, DeviceId: dev.ID, Assertion: dev.Assert(e.d.Clock.Now(), e.jti(), service.AssertionClaims{})}, &dtok)
	var pack gen.OfflinePack
	e.mustJSON(200, "GET", "/v1/devices/"+dev.ID+"/offline-packs/latest", dtok.AccessToken, nil, &pack)
	if packClaims(pack).Device.DeviceId != dev.ID || pack.PackV < first.OfflinePack.PackV {
		t.Fatalf("recovered pack: %+v", packClaims(pack).Device)
	}

	// 2. The same activation with a fresh key returns the pack again, and only to the same id and key.
	var again gen.DeviceActivation
	e.mustJSON(201, "POST", "/v1/device-activations", "", req, &again, "Idempotency-Key", "act-2")
	if again.Device.Id != dev.ID {
		t.Fatalf("re-activation: %+v", again.Device)
	}
	stranger := double.NewDevice(dev.ID)
	var n2 gen.DeviceNonce
	e.mustJSON(201, "POST", "/v1/device-nonces", "", nil, &n2)
	bad := req
	bad.PublicKey, bad.Nonce, bad.NonceSignature = pub(stranger), n2.Nonce, stranger.SignNonce(n2.Nonce)
	if c, _, _ := e.do("POST", "/v1/device-activations", "", bad); c != 409 {
		t.Fatalf("the same id with another key must be refused: %d", c)
	}

	// 3. Under a new id the old device is revoked first, so its key is free again.
	e.mustJSON(200, "PUT", "/v1/devices/"+dev.ID+"/revocation", tok, gen.RevokeDevice{Reason: gen.RevokeDeviceReasonOther}, &gen.Device{})
	e.d.Clock.Advance(time.Second)
	replacement := double.NewDevice(newID())
	if act := e.activate(tok, gen.Pos, replacement); act.Device.Id != replacement.ID {
		t.Fatalf("replacement device: %+v", act.Device)
	}
}

// Security re-review, idempotency.replay_secret (a): approveVendorApproval has a re-issue path. When
// the approval reply carrying the second half of a sign-in code is lost, the same approver approves
// again and gets a fresh code; the lost one stops working. A grant kind re-issues the grant the same way.
func TestVendorApprovalReplyLostCanBeReissued(t *testing.T) {
	e := &env{t: t, d: double.New(double.Options{Config: func(c *service.Config) { c.SignInCodeEnabled = true }}), ctx: context.Background()}
	admin := e.bootstrapAdmin("root@hostry.test")
	second := e.newVendorUser(admin, "second@hostry.test", gen.PlatformAdmin)
	e.d.Clock.Advance(8 * 24 * time.Hour)
	e.signInVendor(admin)
	e.signInVendor(second)
	if _, _, err := e.d.Service.Seed().OwnerInvitation(e.ctx, org.String(), ownerMobile, "Asha"); err != nil {
		t.Fatal(err)
	}
	var ap gen.VendorApproval
	e.mustJSON(201, "POST", "/internal/v1/vendor/approvals", admin.tok, gen.CreateVendorApproval{Kind: gen.ApprovalKindSignInCode, OrganisationId: strPtr(org.String()), MobileE164: strPtr(ownerMobile),
		Reason: "Owner has no SMS in the hills", TicketReference: "ONB-7", VerificationMethod: gen.RequesterVerificationOwnerRequestInApp}, &ap, admin.h(e)...)
	decide := func() (int, gen.ApprovalDecision) {
		e.d.Clock.Advance(31 * time.Second)
		var d gen.ApprovalDecision
		c, b, _ := e.do("PUT", "/internal/v1/vendor/approvals/"+ap.Id+"/decision", second.tok, gen.ApproveVendorApproval{TotpCode: crypto.TOTP(second.secret, e.d.Clock.Now())}, second.h(e)...)
		mustUnmarshal(t, b, &d)
		return c, d
	}
	c1, d1 := decide()
	if c1 != 200 || d1.CodeHalf == nil {
		t.Fatalf("first approval: %d %+v", c1, d1)
	}
	c2, d2 := decide() // the reply was lost; the approver asks again
	if c2 != 200 || d2.CodeHalf == nil || d2.CodeHalf.Half == d1.CodeHalf.Half {
		t.Fatalf("re-issue: %d %+v", c2, d2.CodeHalf)
	}
	// Another vendor user is not the approver and cannot re-issue.
	third := e.newVendorUser(admin, "third@hostry.test", gen.PlatformAdmin)
	e.d.Clock.Advance(8 * 24 * time.Hour)
	e.signInVendor(third)
	if c, _, _ := e.do("PUT", "/internal/v1/vendor/approvals/"+ap.Id+"/decision", third.tok, gen.ApproveVendorApproval{TotpCode: crypto.TOTP(third.secret, e.d.Clock.Now())}, third.h(e)...); c != 409 {
		t.Fatalf("a different approver must not re-issue: %d", c)
	}
}
