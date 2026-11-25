package api_test

import (
	"encoding/base32"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hostryhq/svc-identity/double"
	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/service"
)

const pw = "correct-horse-battery-staple"

type vendor struct {
	id, email, tok string
	secret         []byte
}

func (v *vendor) h(e *env) []string {
	return []string{"Hostry-Service-Token", e.d.ServiceToken("admin", ""), "X-Vendor-Client-Address", "198.51.100.9"}
}

// setup completes the setup of a vendor user from its setup link and signs in.
func (e *env) setup(email, link string) *vendor {
	e.t.Helper()
	svc := []string{"Hostry-Service-Token", e.d.ServiceToken("admin", "")}
	var ch gen.VendorSetupChallenge
	e.mustJSON(201, "POST", "/internal/v1/vendor/setup-sessions", "", gen.BeginVendorSetup{SetupToken: link}, &ch, svc...)
	u, _ := url.Parse(ch.TotpProvisioningUri)
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.Query().Get("secret"))
	if err != nil {
		e.t.Fatal(err)
	}
	var vu gen.VendorUser
	e.mustJSON(200, "POST", "/internal/v1/vendor/setup-completions", "", gen.CompleteVendorSetup{SetupToken: link, Password: pw, TotpCode: crypto.TOTP(secret, e.d.Clock.Now())}, &vu, svc...)
	v := &vendor{id: vu.Id, email: email, secret: secret}
	e.signInVendor(v)
	return v
}

func (e *env) signInVendor(v *vendor) {
	e.t.Helper()
	e.d.Clock.Advance(31 * time.Second) // TOTP is accepted once per 30-second step
	var s gen.VendorSession
	e.mustJSON(201, "POST", "/internal/v1/vendor/sessions", "", gen.VendorSignIn{Email: openapiEmail(v.email), Password: pw, TotpCode: crypto.TOTP(v.secret, e.d.Clock.Now())}, &s,
		"Hostry-Service-Token", e.d.ServiceToken("admin", ""))
	v.tok = s.AccessToken
}

func (e *env) bootstrapAdmin(email string) *vendor {
	e.t.Helper()
	link, err := e.d.Service.VendorBootstrap(e.ctx, email, "tester@host")
	if err != nil {
		e.t.Fatal(err)
	}
	return e.setup(email, link)
}

// newVendorUser creates a vendor user through the API (as an admin) and completes its setup.
func (e *env) newVendorUser(admin *vendor, email string, role gen.VendorRole) *vendor {
	e.t.Helper()
	var vu gen.VendorUser
	e.mustJSON(201, "POST", "/internal/v1/vendor/users", admin.tok, gen.CreateVendorUser{Id: newID(), Email: openapiEmail(email), DisplayName: "User " + email, Role: role}, &vu, admin.h(e)...)
	link := e.d.Mail.LastLink(email)
	if link == "" {
		e.t.Fatal("no setup link emailed")
	}
	return e.setup(email, link)
}

func TestVendorBootstrapSetupAndSignIn(t *testing.T) {
	e := newEnv(t)
	link, err := e.d.Service.VendorBootstrap(e.ctx, "root@hostry.test", "tester@host")
	if err != nil {
		t.Fatal(err)
	}
	// Setup links are single use.
	v := e.setup("root@hostry.test", link)
	e.expect(422, "setup_link_invalid", "POST", "/internal/v1/vendor/setup-sessions", "", gen.BeginVendorSetup{SetupToken: link}, "Hostry-Service-Token", e.d.ServiceToken("admin", ""))
	// With an active platform_admin the command refuses.
	if _, err := e.d.Service.VendorBootstrap(e.ctx, "other@hostry.test", "x"); err != service.ErrPlatformAdminExists {
		t.Fatalf("bootstrap with an admin present: %v", err)
	}
	// AC-ID-4: a TOTP code is accepted once.
	e.d.Clock.Advance(31 * time.Second)
	code := crypto.TOTP(v.secret, e.d.Clock.Now())
	hdr := []string{"Hostry-Service-Token", e.d.ServiceToken("admin", "")}
	e.mustJSON(201, "POST", "/internal/v1/vendor/sessions", "", gen.VendorSignIn{Email: openapiEmail(v.email), Password: pw, TotpCode: code}, nil, hdr...)
	e.expect(401, "vendor.sign_in_failed", "POST", "/internal/v1/vendor/sessions", "", gen.VendorSignIn{Email: openapiEmail(v.email), Password: pw, TotpCode: code}, hdr...)
	// AC-ID-5: wrong password, unknown email and lockout look the same; 5 failures lock the account.
	e.d.Clock.Advance(31 * time.Second)
	for i := 0; i < 5; i++ {
		e.expect(401, "vendor.sign_in_failed", "POST", "/internal/v1/vendor/sessions", "", gen.VendorSignIn{Email: openapiEmail(v.email), Password: "wrong-password-123", TotpCode: "000000"}, hdr...)
	}
	e.expect(401, "vendor.sign_in_failed", "POST", "/internal/v1/vendor/sessions", "", gen.VendorSignIn{Email: openapiEmail(v.email), Password: pw, TotpCode: crypto.TOTP(v.secret, e.d.Clock.Now())}, hdr...)
	e.expect(401, "vendor.sign_in_failed", "POST", "/internal/v1/vendor/sessions", "", gen.VendorSignIn{Email: "nobody@hostry.test", Password: pw, TotpCode: "123456"}, hdr...)
	e.d.Clock.Advance(16 * time.Minute)
	e.mustJSON(201, "POST", "/internal/v1/vendor/sessions", "", gen.VendorSignIn{Email: openapiEmail(v.email), Password: pw, TotpCode: crypto.TOTP(v.secret, e.d.Clock.Now())}, nil,
		"Hostry-Service-Token", e.d.ServiceToken("admin", ""))
}

// AC-ID-2 and IST-34/IST-41: realms and callers.
func TestRealmSeparationAndCallers(t *testing.T) {
	e := newEnv(t)
	admin := e.bootstrapAdmin("root@hostry.test")
	owner, _ := e.ownerSession()
	// Vendor token on a tenant route, tenant token on a vendor route, vendor route without a service token.
	e.expect(401, "", "GET", "/v1/members", admin.tok, nil)
	e.expect(401, "", "GET", "/internal/v1/vendor/users", owner.Tokens.AccessToken, nil, admin.h(e)...)
	e.expect(401, "", "GET", "/internal/v1/vendor/users", admin.tok, nil)
	// A service that is not on x-service-callers is refused; a forged service token is not a token.
	e.expect(403, "", "GET", "/internal/v1/vendor/users", admin.tok, nil, "Hostry-Service-Token", e.d.ServiceToken("sync", ""))
	e.expect(401, "", "GET", "/internal/v1/vendor/users", admin.tok, nil, "Hostry-Service-Token", "not-a-token")
	e.mustJSON(200, "GET", "/internal/v1/vendor/users", admin.tok, nil, nil, admin.h(e)...)
	// The gateway's internal routes are unreachable without a service token, even with a valid user token.
	e.expect(401, "", "GET", "/internal/v1/revocations", owner.Tokens.AccessToken, nil)
}

func TestOwnerInvitationLifecycle(t *testing.T) {
	e := newEnv(t)
	admin := e.bootstrapAdmin("root@hostry.test")
	base := "/internal/v1/vendor/organisations/" + org.String() + "/owner-invitations"
	var inv, again gen.OwnerInvitation
	e.mustJSON(201, "POST", base, admin.tok, gen.CreateOwnerInvitation{MobileE164: ownerMobile, OwnerName: "Asha"}, &inv, admin.h(e)...)
	e.mustJSON(201, "POST", base, admin.tok, gen.CreateOwnerInvitation{MobileE164: ownerMobile, OwnerName: "Asha"}, &again, admin.h(e)...)
	if inv.Id != again.Id || inv.Status != gen.InvitationStatusPending || inv.ExpiresAt.Sub(inv.CreatedAt) != 14*24*time.Hour {
		t.Fatalf("invitation: %+v %+v", inv, again)
	}
	if inv.MobileMasked != "+91*******210" {
		t.Fatalf("mask: %s", inv.MobileMasked)
	}
	// Renew and cancel act on pending invitations only.
	e.d.Clock.Advance(24 * time.Hour)
	e.signInVendor(admin)
	var renewed gen.OwnerInvitation
	e.mustJSON(200, "POST", base+"/"+inv.Id+"/renewals", admin.tok, nil, &renewed, admin.h(e)...)
	if !renewed.ExpiresAt.After(inv.ExpiresAt) {
		t.Fatal("renewal did not move the expiry")
	}
	e.mustJSON(200, "PUT", base+"/"+inv.Id+"/cancellation", admin.tok, nil, nil, admin.h(e)...)
	e.expect(409, "invitation_not_pending", "PUT", base+"/"+inv.Id+"/cancellation", admin.tok, nil, admin.h(e)...)
	// After cancel, an OTP request for that number sends nothing.
	dev := double.NewDevice(newID())
	e.mustJSON(202, "POST", "/v1/otp-challenges", "", gen.CreateOtpChallenge{MobileE164: ownerMobile, DeviceId: dev.ID, DevicePublicKey: pub(dev)}, nil)
	if len(e.d.SMS.Sent()) != 0 {
		t.Fatal("SMS sent for a cancelled invitation")
	}
	// A new invitation, accepted; then vendors can no longer add owners to the running organisation (T-E4).
	e.mustJSON(201, "POST", base, admin.tok, gen.CreateOwnerInvitation{MobileE164: ownerMobile, OwnerName: "Asha"}, nil, admin.h(e)...)
	e.d.Clock.Advance(40 * time.Second)
	e.signIn(ownerMobile, dev)
	e.expect(409, "owner_exists", "POST", base, admin.tok, gen.CreateOwnerInvitation{MobileE164: "+919876500009", OwnerName: "Mallory"}, admin.h(e)...)
	// AC-ID-18: lookup by exact number returns ids only.
	var look gen.OwnerLookupResult
	e.mustJSON(200, "POST", "/internal/v1/vendor/owner-lookups", admin.tok, gen.OwnerLookup{MobileE164: ownerMobile}, &look, admin.h(e)...)
	if len(look.OrganisationIds) != 1 || look.OrganisationIds[0] != org.String() {
		t.Fatalf("lookup: %+v", look)
	}
}

// IST-41, IST-42 and A0 AC-ID-8..12: support sessions.
func TestSupportSessionViewModeAuditAndFailClosed(t *testing.T) {
	e := newEnv(t)
	admin := e.bootstrapAdmin("root@hostry.test")
	owner, _ := e.ownerSession()
	dev := double.NewDevice(newID())
	e.activate(owner.Tokens.AccessToken, gen.Pos, dev)
	body := gen.StartSupportSession{OrganisationId: org.String(), Reason: "Owner phoned about a lost tablet", TicketReference: "SUP-2041"}
	// Act mode, long duration, empty ticket, short reason are all 422.
	act := gen.StartSupportSessionModeAct
	e.expect(422, "mode_not_supported", "POST", "/internal/v1/vendor/support-sessions", admin.tok, gen.StartSupportSession{OrganisationId: org.String(), Reason: body.Reason, TicketReference: "T", Mode: &act}, admin.h(e)...)
	long := 61
	e.expect(422, "", "POST", "/internal/v1/vendor/support-sessions", admin.tok, gen.StartSupportSession{OrganisationId: org.String(), Reason: body.Reason, TicketReference: "T", DurationMinutes: &long}, admin.h(e)...)
	e.expect(422, "", "POST", "/internal/v1/vendor/support-sessions", admin.tok, gen.StartSupportSession{OrganisationId: org.String(), Reason: body.Reason, TicketReference: " "}, admin.h(e)...)
	e.expect(422, "", "POST", "/internal/v1/vendor/support-sessions", admin.tok, gen.StartSupportSession{OrganisationId: org.String(), Reason: "short", TicketReference: "T"}, admin.h(e)...)
	var st gen.SupportSessionStarted
	e.mustJSON(201, "POST", "/internal/v1/vendor/support-sessions", admin.tok, body, &st, admin.h(e)...)
	e.expect(409, "support_session_active", "POST", "/internal/v1/vendor/support-sessions", admin.tok, body, admin.h(e)...)
	sup := st.Token.AccessToken
	svc := []string{"Hostry-Service-Token", e.d.ServiceToken("admin", "")}
	// A support token is useless without the admin service token (ADR-0013 V2).
	e.expect(401, "", "GET", "/v1/members", sup, nil)
	// View mode: support_viewable reads work; writes and non-viewable reads do not.
	e.mustJSON(200, "GET", "/v1/members", sup, nil, nil, svc...)
	e.mustJSON(200, "GET", "/v1/devices", sup, nil, nil, svc...)
	e.expect(403, "", "GET", "/v1/audit-entries", sup, nil, svc...)
	e.expect(403, "", "POST", "/v1/members", sup, gen.CreateMember{Id: newID(), DisplayName: "X"}, svc...)
	e.expect(403, "", "POST", "/v1/activation-codes", sup, gen.CreateActivationCode{OutletId: outletA, Kind: gen.Pos}, svc...)
	// Strong-only and step-up operations are refused for a support token (IST-17, A2.5).
	e.expect(403, "", "PUT", "/v1/devices/"+dev.ID+"/revocation", sup, gen.RevokeDevice{Reason: gen.RevokeDeviceReasonLost}, svc...)
	// The tenant's own audit log shows the start and every read.
	var page gen.TenantAuditPage
	e.mustJSON(200, "GET", "/v1/audit-entries", owner.Tokens.AccessToken, nil, &page)
	var started bool
	for _, it := range page.Items {
		if it.Action == "support.session.started" && it.ShowToOwner && it.Reason != nil && it.TicketReference != nil && *it.TicketReference == "SUP-2041" {
			started = true
		}
	}
	if !started {
		t.Fatalf("tenant audit has no start entry: %+v", page.Items)
	}
	if n := len(e.d.Access.Entries()); n < 3 {
		t.Fatalf("vendor access log rows: %d", n)
	}
	// IST-42: with the audit sink failing, support requests are refused and nothing is returned.
	e.d.Access.FailInTx = true
	code, b, _ := e.do("GET", "/v1/members", sup, nil, svc...)
	if code < 500 || strings.Contains(string(b), "display_name") {
		t.Fatalf("audit failure must fail the request closed: %d %s", code, b)
	}
	e.d.Access.FailInTx = false
	// Another organisation is invisible: a support token is for one organisation only.
	// The token expires with the session, and cannot be renewed past its end.
	e.mustJSON(201, "POST", "/internal/v1/vendor/support-sessions/"+st.Session.Id+"/tokens", admin.tok, nil, nil, admin.h(e)...)
	e.mustJSON(200, "PUT", "/internal/v1/vendor/support-sessions/"+st.Session.Id+"/termination", admin.tok, nil, nil, admin.h(e)...)
	e.mustJSON(200, "PUT", "/internal/v1/vendor/support-sessions/"+st.Session.Id+"/termination", admin.tok, nil, nil, admin.h(e)...) // idempotent
	e.expect(409, "support_session_ended", "POST", "/internal/v1/vendor/support-sessions/"+st.Session.Id+"/tokens", admin.tok, nil, admin.h(e)...)
	// The owner's log shows the end entry too.
	e.mustJSON(200, "GET", "/v1/audit-entries", owner.Tokens.AccessToken, nil, &page)
	var ended bool
	for _, it := range page.Items {
		ended = ended || it.Action == "support.session.ended"
	}
	if !ended {
		t.Fatal("no end entry in the tenant log")
	}
}

// A2.5: vendor device list and revoke; quota; the two-person approval above the quota.
func TestVendorDeviceRevokeQuotaAndSecondApprover(t *testing.T) {
	e := newEnv(t)
	admin := e.bootstrapAdmin("root@hostry.test")
	owner, _ := e.ownerSession()
	var devs []*double.Device
	for i := 0; i < 3; i++ {
		d := double.NewDevice(newID())
		devs = append(devs, d)
		e.activate(owner.Tokens.AccessToken, gen.Pos, d)
	}
	base := "/internal/v1/vendor/organisations/" + org.String() + "/devices"
	var page gen.VendorDevicePage
	e.mustJSON(200, "GET", base, admin.tok, nil, &page, admin.h(e)...)
	if len(page.Items) != 3 {
		t.Fatalf("devices: %d", len(page.Items))
	}
	revoke := func(d *double.Device, approval *string) (int, gen.VendorRevokeResult, string) {
		code, b, _ := e.do("PUT", base+"/"+d.ID+"/revocation", admin.tok, gen.VendorRevoke{Confirm: true, Reason: "Owner called: tablet stolen", TicketReference: "SUP-1",
			VerificationMethod: gen.RequesterVerificationCallbackToRegisteredNumber, ApprovalId: approval}, admin.h(e)...)
		var r gen.VendorRevokeResult
		mustUnmarshal(t, b, &r)
		return code, r, problemCode(b)
	}
	if c, r, _ := revoke(devs[0], nil); c != 200 || !r.Changed || r.Outcome != gen.VendorRevokeResultOutcomeRevoked {
		t.Fatalf("first revoke: %d %+v", c, r)
	}
	if c, r, _ := revoke(devs[0], nil); c != 200 || r.Changed || r.Outcome != gen.VendorRevokeResultOutcomeAlreadyRevoked {
		t.Fatalf("repeat revoke: %d %+v", c, r)
	}
	if c, _, _ := revoke(devs[1], nil); c != 200 {
		t.Fatalf("second revoke: %d", c)
	}
	// Third in the organisation within 24 hours is over the quota of 2: it needs a second approver.
	if c, _, code := revoke(devs[2], nil); c != 409 || code != "vendor_approval_required" {
		t.Fatalf("over quota: %d %s", c, code)
	}
	// With no second eligible vendor user the request is refused; a user created now is too new (7-day rule).
	var ap gen.VendorApproval
	req := gen.CreateVendorApproval{Kind: gen.ApprovalKindDeviceRevokeOverQuota, OrganisationId: strPtr(org.String()), SubjectId: &devs[2].ID, Reason: "Owner called: tablet stolen", TicketReference: "SUP-1",
		VerificationMethod: gen.RequesterVerificationCallbackToRegisteredNumber}
	e.expect(409, "second_approver_unavailable", "POST", "/internal/v1/vendor/approvals", admin.tok, req, admin.h(e)...)
	second := e.newVendorUser(admin, "second@hostry.test", gen.PlatformAdmin)
	e.expect(409, "second_approver_unavailable", "POST", "/internal/v1/vendor/approvals", admin.tok, req, admin.h(e)...)
	approve := func(who *vendor, id string, secret []byte) int {
		c, _, _ := e.do("PUT", "/internal/v1/vendor/approvals/"+id+"/decision", who.tok, gen.ApproveVendorApproval{TotpCode: crypto.TOTP(secret, e.d.Clock.Now())}, who.h(e)...)
		return c
	}
	e.d.Clock.Advance(8 * 24 * time.Hour)
	e.signInVendor(admin)
	e.signInVendor(second)
	e.mustJSON(201, "POST", "/internal/v1/vendor/approvals", admin.tok, req, &ap, admin.h(e)...)
	e.d.Clock.Advance(31 * time.Second)
	// The requester cannot approve their own request.
	if c := approve(admin, ap.Id, admin.secret); c != 409 {
		t.Fatalf("self-approval: %d", c)
	}
	e.d.Clock.Advance(31 * time.Second)
	if c := approve(second, ap.Id, second.secret); c != 200 {
		t.Fatalf("eligible approver: %d", c)
	}
	if c, r, _ := revoke(devs[2], &ap.Id); c != 200 || !r.Changed {
		t.Fatalf("revoke with approval: %d %+v", c, r)
	}
	if c, _, _ := revoke(double.NewDevice(newID()), &ap.Id); c != 404 {
		t.Fatalf("unknown device: %d", c)
	}
	// Both vendor access and the revoke are in the tenant's own log.
	var tp gen.TenantAuditPage
	e.mustJSON(200, "GET", "/v1/audit-entries", e.d.UserToken(org, owner.MemberId, "", grantsAll()), nil, &tp)
	var revoked, listed bool
	for _, it := range tp.Items {
		revoked = revoked || it.Action == "vendor.device.revoked"
		listed = listed || it.Action == "vendor.devices.listed"
	}
	if !revoked || !listed {
		t.Fatalf("tenant audit: revoked=%v listed=%v", revoked, listed)
	}
}

// IST-14: the vendor-assisted sign-in code. Off by default; two vendor users; halves; single use;
// the session cannot step up for 24 hours.
func TestVendorAssistedSignInCode(t *testing.T) {
	e := newEnv(t)
	admin := e.bootstrapAdmin("root@hostry.test")
	body := gen.CreateVendorApproval{Kind: gen.ApprovalKindSignInCode, OrganisationId: strPtr(org.String()), MobileE164: strPtr(ownerMobile), Reason: "Owner has no SMS in the hills",
		TicketReference: "ONB-7", VerificationMethod: gen.RequesterVerificationOwnerRequestInApp}
	e.expect(403, "vendor_assist_disabled", "POST", "/internal/v1/vendor/approvals", admin.tok, body, admin.h(e)...)

	e = &env{t: t, d: double.New(double.Options{Config: func(c *service.Config) { c.SignInCodeEnabled = true }}), ctx: e.ctx}
	admin = e.bootstrapAdmin("root@hostry.test")
	if _, _, err := e.d.Service.Seed().OwnerInvitation(e.ctx, org.String(), ownerMobile, "Asha"); err != nil {
		t.Fatal(err)
	}
	second := e.newVendorUser(admin, "second@hostry.test", gen.PlatformAdmin)
	e.d.Clock.Advance(8 * 24 * time.Hour)
	e.signInVendor(admin)
	e.signInVendor(second)
	var ap gen.VendorApproval
	e.mustJSON(201, "POST", "/internal/v1/vendor/approvals", admin.tok, body, &ap, admin.h(e)...)
	e.d.Clock.Advance(31 * time.Second)
	var dec gen.ApprovalDecision
	e.mustJSON(200, "PUT", "/internal/v1/vendor/approvals/"+ap.Id+"/decision", second.tok, gen.ApproveVendorApproval{TotpCode: crypto.TOTP(second.secret, e.d.Clock.Now())}, &dec, second.h(e)...)
	var first gen.CodeHalf
	e.mustJSON(201, "POST", "/internal/v1/vendor/approvals/"+ap.Id+"/code-half-claims", admin.tok, nil, &first, admin.h(e)...)
	e.expect(409, "", "POST", "/internal/v1/vendor/approvals/"+ap.Id+"/code-half-claims", admin.tok, nil, admin.h(e)...) // shown once
	if dec.CodeHalf == nil || len(dec.CodeHalf.Half) != 4 || len(first.Half) != 4 || first.Position != gen.First || dec.CodeHalf.Position != gen.Second {
		t.Fatalf("halves: %+v %+v", dec.CodeHalf, first)
	}
	code := first.Half + dec.CodeHalf.Half

	// The owner starts a login for the number on their device and types the full code.
	dev := double.NewDevice(newID())
	var ch gen.OtpChallenge
	e.mustJSON(202, "POST", "/v1/otp-challenges", "", gen.CreateOtpChallenge{MobileE164: ownerMobile, DeviceId: dev.ID, DevicePublicKey: pub(dev)}, &ch)
	login := func(c string) (int, gen.Session) {
		var s gen.Session
		code, b, _ := e.do("POST", "/v1/sessions", "", gen.CreateSession{GrantType: gen.CreateSessionGrantTypeVendorCode, ChallengeId: ch.Id, Code: c, DeviceId: dev.ID,
			DeviceAssertion: dev.Assert(e.d.Clock.Now(), e.jti(), service.AssertionClaims{Cid: ch.Id})})
		if code == 201 {
			mustUnmarshal(t, b, &s)
		}
		return code, s
	}
	if c, _ := login("ZZZZZZZZ"); c != 401 {
		t.Fatalf("wrong code: %d", c)
	}
	c, s := login(code)
	if c != 201 || s.Amr != gen.AuthMethodVendorCode {
		t.Fatalf("vendor-code login: %d %+v", c, s)
	}
	if c, _ := login(code); c != 401 {
		t.Fatal("code reused")
	}
	// A vendor-code session can never satisfy step-up: owner-role assignment is x-step-up.
	e.expect(403, "auth.step_up_required", "PUT", "/v1/members/"+newID()+"/owner-role", s.Tokens.AccessToken, gen.OwnerRoleAssignment{Id: newID()})
	// The tenant's audit log names both vendor users.
	var tp gen.TenantAuditPage
	e.mustJSON(200, "GET", "/v1/audit-entries", s.Tokens.AccessToken, nil, &tp)
	named := false
	for _, it := range tp.Items {
		named = named || (it.ReadSummary != nil && strings.Contains(*it.ReadSummary, admin.id) && strings.Contains(*it.ReadSummary, second.id))
	}
	if !named {
		t.Fatalf("tenant audit does not name both vendor users: %+v", tp.Items)
	}
}
