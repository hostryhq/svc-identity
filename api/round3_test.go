package api_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hostryhq/go-auth/authtest"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/svc-identity/double"
	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/repository"
)

// listActivationCodes and revokeActivationCode (O2-13): the owner finds and withdraws a code nobody holds.
func TestOwnerListsAndRevokesActivationCodes(t *testing.T) {
	e := newEnv(t)
	owner, _ := e.ownerSession()
	tok := owner.Tokens.AccessToken
	mk := func(key string) gen.ActivationCode {
		var c gen.ActivationCode
		e.mustJSON(201, "POST", "/v1/activation-codes", tok, gen.CreateActivationCode{OutletId: outletA, Kind: gen.Pos}, &c, "Idempotency-Key", key)
		e.d.Clock.Advance(time.Second) // ids are time-sortable: newest first needs distinct instants
		return c
	}
	redeem := func(code string) int {
		var n gen.DeviceNonce
		e.mustJSON(201, "POST", "/v1/device-nonces", "", nil, &n)
		d := double.NewDevice(newID())
		c, _, _ := e.do("POST", "/v1/device-activations", "", gen.ActivateDevice{ActivationCode: code, Id: d.ID, Name: "Till", PublicKey: pub(d), KeyProtection: gen.Hardware, Nonce: n.Nonce, NonceSignature: d.SignNonce(n.Nonce)})
		return c
	}
	first, second := mk("c-1"), mk("c-2")

	// Newest first, no code value, paged by cursor.
	code, raw, _ := e.do("GET", "/v1/activation-codes", tok, nil)
	var page gen.ActivationCodePage
	mustUnmarshal(t, raw, &page)
	if code != 200 || len(page.Items) != 2 || page.Items[0].Id != second.Id || page.Items[1].Id != first.Id || page.Items[0].State != gen.ActivationCodeSummaryStatePending {
		t.Fatalf("list: %d %s", code, raw)
	}
	if strings.Contains(string(raw), first.Code) || strings.Contains(string(raw), `"code"`) {
		t.Fatalf("the list must never return a code value: %s", raw)
	}
	var p1, p2 gen.ActivationCodePage
	e.mustJSON(200, "GET", "/v1/activation-codes?limit=1", tok, nil, &p1)
	if len(p1.Items) != 1 || p1.NextCursor == nil || p1.Items[0].Id != second.Id {
		t.Fatalf("page 1: %+v", p1)
	}
	e.mustJSON(200, "GET", "/v1/activation-codes?limit=1&cursor="+*p1.NextCursor, tok, nil, &p2)
	if len(p2.Items) != 1 || p2.Items[0].Id != first.Id || p2.NextCursor != nil {
		t.Fatalf("page 2: %+v", p2)
	}

	// Revoke: the code leaves the list, cannot be redeemed, and revoking again changes nothing.
	var rv gen.ActivationCodeSummary
	e.mustJSON(200, "DELETE", "/v1/activation-codes/"+first.Id, tok, nil, &rv, "Idempotency-Key", "r-1")
	if rv.State != gen.ActivationCodeSummaryStateRevoked || rv.Id != first.Id || !rv.ExpiresAt.Equal(first.ExpiresAt) {
		t.Fatalf("revoked summary: %+v", rv)
	}
	e.mustJSON(200, "DELETE", "/v1/activation-codes/"+first.Id, tok, nil, &rv, "Idempotency-Key", "r-2")
	if rv.State != gen.ActivationCodeSummaryStateRevoked {
		t.Fatalf("second revoke: %+v", rv)
	}
	if c := redeem(first.Code); c != 422 {
		t.Fatalf("a revoked code must not redeem: %d", c)
	}
	e.mustJSON(200, "GET", "/v1/activation-codes", tok, nil, &page)
	if len(page.Items) != 1 || page.Items[0].Id != second.Id {
		t.Fatalf("list after revoke: %+v", page)
	}

	// A redeemed code is 409 activation_code_redeemed and is not listed; another organisation sees nothing and cannot revoke.
	if c := redeem(second.Code); c != 201 {
		t.Fatalf("redeem: %d", c)
	}
	e.expect(409, "activation_code_redeemed", "DELETE", "/v1/activation-codes/"+second.Id, tok, nil, "Idempotency-Key", "r-3")
	e.mustJSON(200, "GET", "/v1/activation-codes", tok, nil, &page)
	if len(page.Items) != 0 {
		t.Fatalf("a redeemed code is not listed: %+v", page)
	}
	live := mk("c-3")
	other := e.ownerCtx(ids.ID("0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a99"), "someone", grantsAll())
	if got, err := e.d.Service.ListActivationCodes(other, gen.ListActivationCodesParams{}); err != nil || len(got.Items) != 0 {
		t.Fatalf("tenant isolation of the list: %+v %v", got, err)
	}
	if _, err := e.d.Service.RevokeActivationCode(other, live.Id); err == nil {
		t.Fatal("another organisation must not revoke the code")
	}
	// Outlet scope: a member without device.activation_code.create for the outlet is refused.
	weak := e.ownerCtx(org, "staff", authtest.Grants([]string{outletA}, "member.read"))
	if _, err := e.d.Service.ListActivationCodes(weak, gen.ListActivationCodesParams{}); err == nil {
		t.Fatal("a member without device.activation_code.create must not list")
	}

	// A lapsed code leaves the list; revoking it answers 200 with state lapsed and changes nothing.
	e.d.Clock.Advance(11 * time.Minute)
	e.mustJSON(200, "GET", "/v1/activation-codes", tok, nil, &page)
	if len(page.Items) != 0 {
		t.Fatalf("a lapsed code is not listed: %+v", page)
	}
	e.mustJSON(200, "DELETE", "/v1/activation-codes/"+live.Id, tok, nil, &rv, "Idempotency-Key", "r-4")
	if rv.State != gen.ActivationCodeSummaryStateLapsed {
		t.Fatalf("lapsed code: %+v", rv)
	}
}

// issueVendorApprovalGrant: a fresh grant for an approval that stays approved, for its approver only.
func TestApproverGetsAFreshVendorGrant(t *testing.T) {
	e := newEnv(t)
	admin := e.bootstrapAdmin("root@hostry.test")
	second := e.newVendorUser(admin, "second@hostry.test", gen.PlatformAdmin)
	third := e.newVendorUser(admin, "third@hostry.test", gen.PlatformAdmin)
	e.d.Clock.Advance(8 * 24 * time.Hour)
	e.signInVendor(admin)
	e.signInVendor(second)
	e.signInVendor(third)
	grants := func(who *vendor, id string, hdr ...string) (int, []byte) {
		c, b, _ := e.do("POST", "/internal/v1/vendor/approvals/"+id+"/grants", who.tok, nil, append(who.h(e), hdr...)...)
		return c, b
	}
	file := func(kind gen.ApprovalKind) gen.VendorApproval {
		var ap gen.VendorApproval
		e.mustJSON(201, "POST", "/internal/v1/vendor/approvals", admin.tok, gen.CreateVendorApproval{Kind: kind, OrganisationId: strPtr(org.String()),
			Reason: "Owner asked to pause the account", TicketReference: "ONB-11", VerificationMethod: gen.RequesterVerificationCallbackToRegisteredNumber}, &ap, admin.h(e)...)
		return ap
	}
	approve := func(who *vendor, id string) {
		e.d.Clock.Advance(31 * time.Second)
		e.mustJSON(200, "PUT", "/internal/v1/vendor/approvals/"+id+"/decision", who.tok, gen.ApproveVendorApproval{TotpCode: crypto.TOTP(who.secret, e.d.Clock.Now())}, nil, who.h(e)...)
	}
	refused := func(c int, b []byte, reason string) {
		t.Helper()
		var p struct{ Code, Reason string }
		_ = json.Unmarshal(b, &p)
		if c != 409 || p.Code != "approval_not_executable" || p.Reason != reason {
			t.Fatalf("want 409 approval_not_executable/%s, got %d %s", reason, c, b)
		}
	}

	ap := file(gen.ApprovalKindOrgSuspend)
	c, b := grants(second, ap.Id)
	refused(c, b, "not_approved") // still pending
	approve(second, ap.Id)

	// The approver gets a new grant bound to the same approval and subject; the audit names its jti.
	c, b = grants(second, ap.Id, "Idempotency-Key", "g-1")
	var g gen.VendorApprovalGrant
	mustUnmarshal(t, b, &g)
	claims := jwtPayload(t, g.Token)
	if c != 201 || claims["approval_id"] != ap.Id || claims["kind"] != "org_suspend" || claims["org"] != org.String() || claims["approver"] != second.id ||
		claims["aud"] != "tenancy" || !subjectHashRE.MatchString(claims["subject_hash"].(string)) || g.ExpiresAt.Sub(e.d.Clock.Now()) != 5*time.Minute {
		t.Fatalf("fresh grant: %d %s", c, b)
	}
	c, b = grants(second, ap.Id)
	var g2 gen.VendorApprovalGrant
	mustUnmarshal(t, b, &g2)
	if c != 201 || jwtPayload(t, g2.Token)["jti"] == claims["jti"] {
		t.Fatalf("every call issues a new grant: %d %s", c, b)
	}
	found := false
	_ = e.d.Store.Tx(e.ctx, repository.Global, func(tx repository.Tx) error {
		rs, err := tx.ListAudit(repository.Platform, "", 500)
		for _, r := range rs {
			var a struct{ Action, Target, Summary string }
			_ = json.Unmarshal(r.Doc, &a)
			if a.Action == "vendor.approval.grant_issued" && a.Target == ap.Id && strings.Contains(a.Summary, claims["jti"].(string)) {
				found = true
			}
		}
		return err
	})
	if !found {
		t.Fatal("the issue is not in the vendor audit with the grant's jti")
	}
	// A replay with the same key never returns the secret again (SR-H4).
	c, b = grants(second, ap.Id, "Idempotency-Key", "g-1")
	if c != 409 || strings.Contains(string(b), g.Token) {
		t.Fatalf("replay: %d %s", c, b)
	}

	// Only the approver: the requester and another eligible approver are refused.
	c, b = grants(admin, ap.Id)
	refused(c, b, "not_approver")
	c, b = grants(third, ap.Id)
	refused(c, b, "not_approver")
	// An unknown id is 404.
	e.expect(404, "", "POST", "/internal/v1/vendor/approvals/"+newID()+"/grants", second.tok, nil, second.h(e)...)
	// Lapsed: after the approval's own 24 hours.
	e.d.Clock.Advance(24 * time.Hour)
	e.signInVendor(second)
	c, b = grants(second, ap.Id)
	refused(c, b, "lapsed")
}

// Approval records show the requester's reason and a statement built by identity, the rule set of a
// tax_rule_set_publish, and, on org_close, whether the owner was offered an export.
func TestVendorApprovalCarriesReasonSubjectRuleSetAndExportFlag(t *testing.T) {
	e := newEnv(t)
	admin := e.bootstrapAdmin("root@hostry.test")
	e.newVendorUser(admin, "second@hostry.test", gen.PlatformAdmin)
	e.d.Clock.Advance(8 * 24 * time.Hour)
	e.signInVendor(admin)
	create := func(in gen.CreateVendorApproval) gen.VendorApproval {
		var ap gen.VendorApproval
		e.mustJSON(201, "POST", "/internal/v1/vendor/approvals", admin.tok, in, &ap, admin.h(e)...)
		var got gen.VendorApproval
		e.mustJSON(200, "GET", "/internal/v1/vendor/approvals/"+ap.Id, admin.tok, nil, &got, admin.h(e)...)
		return got
	}
	base := gen.CreateVendorApproval{Reason: "Owner asked to close the account", TicketReference: "ONB-12", VerificationMethod: gen.RequesterVerificationCallbackToRegisteredNumber, OrganisationId: strPtr(org.String())}

	closeIt := base
	closeIt.Kind, closeIt.OwnerExportOffered = gen.ApprovalKindOrgClose, boolPtr(true)
	got := create(closeIt)
	if got.Reason == nil || *got.Reason != base.Reason || got.OwnerExportOffered == nil || !*got.OwnerExportOffered || got.RuleSetId != nil ||
		got.Subject == nil || *got.Subject != "Close organisation "+org.String() {
		t.Fatalf("org_close: %+v", got)
	}
	notOffered := base
	notOffered.Kind = gen.ApprovalKindOrgClose
	if got = create(notOffered); got.OwnerExportOffered == nil || *got.OwnerExportOffered {
		t.Fatalf("org_close without the flag must say false: %+v", got)
	}
	suspend := base
	suspend.Kind, suspend.OwnerExportOffered = gen.ApprovalKindOrgSuspend, boolPtr(true) // not meaningful for this kind: not recorded
	if got = create(suspend); got.OwnerExportOffered != nil || got.RuleSetId != nil {
		t.Fatalf("org_suspend: %+v", got)
	}

	rule := gen.CreateVendorApproval{Kind: gen.ApprovalKindTaxRuleSetPublish, Reason: "Quarterly rule set update", TicketReference: "TAX-3",
		VerificationMethod: gen.RequesterVerificationCallbackToRegisteredNumber, RuleSetId: strPtr(newID()), RuleSetContentHash: strPtr("sha256:" + strings.Repeat("ab", 32))}
	d := dateOf(2026, 12, 1)
	rule.EffectiveDate = &d
	got = create(rule)
	if got.RuleSetId == nil || *got.RuleSetId != *rule.RuleSetId || got.OwnerExportOffered != nil || got.OrganisationId != nil ||
		got.Subject == nil || !strings.Contains(*got.Subject, *rule.RuleSetId) {
		t.Fatalf("tax_rule_set_publish: %+v", got)
	}
}

func boolPtr(b bool) *bool { return &b }

// The vendor principal shows when the user last signed in and from when they may approve.
func TestVendorPrincipalShowsLastSignInAndApproverEligibility(t *testing.T) {
	e := newEnv(t)
	admin := e.bootstrapAdmin("root@hostry.test")
	second := e.newVendorUser(admin, "second@hostry.test", gen.PlatformAdmin)
	e.d.Clock.Advance(time.Hour)
	var s gen.VendorSession
	e.mustJSON(201, "POST", "/internal/v1/vendor/sessions", "", gen.VendorSignIn{Email: openapiEmail(second.email), Password: pw, TotpCode: crypto.TOTP(second.secret, e.d.Clock.Now())}, &s,
		"Hostry-Service-Token", e.d.ServiceToken("admin", ""))
	if s.User.LastSignInAt == nil || !s.User.LastSignInAt.Equal(e.d.Clock.Now()) {
		t.Fatalf("last_sign_in_at: %+v", s.User)
	}
	if s.User.CanApproveFrom == nil || s.User.CanApproveFrom.Sub(e.d.Clock.Now()) <= 6*24*time.Hour || s.User.CanApproveFrom.Sub(e.d.Clock.Now()) > 7*24*time.Hour {
		t.Fatalf("can_approve_from: %+v", s.User)
	}
}

// new_device_caution: a member who signed in from a new device is shown as under caution for 24 hours.
func TestMemberShowsNewDeviceCaution(t *testing.T) {
	e := newEnv(t)
	owner, dev := e.ownerSession()
	tok := owner.Tokens.AccessToken
	var m gen.Member
	e.mustJSON(200, "GET", "/v1/members/"+owner.MemberId, tok, nil, &m)
	if m.NewDeviceCaution != nil {
		t.Fatalf("the first device is not under caution: %+v", m)
	}
	e.d.Clock.Advance(10 * time.Minute)              // past the OTP resend limit
	e.signIn(ownerMobile, double.NewDevice(newID())) // a second device: its binding is under caution
	e.mustJSON(200, "GET", "/v1/members/"+owner.MemberId, tok, nil, &m)
	if m.NewDeviceCaution == nil || !*m.NewDeviceCaution {
		t.Fatalf("the new device must show caution: %+v", m)
	}
	var page gen.MemberPage
	e.mustJSON(200, "GET", "/v1/members", tok, nil, &page)
	if len(page.Items) != 1 || page.Items[0].NewDeviceCaution == nil || !*page.Items[0].NewDeviceCaution {
		t.Fatalf("the list must show it too: %+v", page)
	}
	e.d.Clock.Advance(25 * time.Hour)
	tok = e.signIn(ownerMobile, dev).Tokens.AccessToken // the old token has expired
	m = gen.Member{}                                    // decoding into a used value would keep the old pointer
	e.mustJSON(200, "GET", "/v1/members/"+owner.MemberId, tok, nil, &m)
	if m.NewDeviceCaution != nil {
		t.Fatalf("caution ends after 24 hours: %+v", m)
	}
}

// identity.device.drained is published once, in the transaction that records the drain.
func TestDrainedDeviceEmitsOneEvent(t *testing.T) {
	e := newEnv(t)
	owner, _ := e.ownerSession()
	tok := owner.Tokens.AccessToken
	dev := double.NewDevice(newID())
	e.activate(tok, gen.Pos, dev)
	e.mustJSON(200, "PUT", "/v1/devices/"+dev.ID+"/revocation", tok, gen.RevokeDevice{Reason: gen.RevokeDeviceReasonLost}, &gen.Device{})
	report := func() {
		e.mustJSON(200, "PUT", "/internal/v1/devices/"+dev.ID+"/drain", "", gen.RecordDrain{DrainedThrough: []gen.StreamSequence{{Stream: "device-ops", Seq: 40}}}, nil,
			"Hostry-Service-Token", e.d.ServiceToken("sync", org))
	}
	report()
	report() // a repeated report adds no second event
	n := 0
	for _, ev := range e.d.Memory.Events() {
		if ev.Type != "identity.device.drained" {
			continue
		}
		n++
		var data struct {
			DeviceID  string           `json:"device_id"`
			DrainedAt time.Time        `json:"drained_at"`
			Series    []map[string]any `json:"series"`
		}
		if err := json.Unmarshal(ev.Data, &data); err != nil || data.DeviceID != dev.ID || !data.DrainedAt.Equal(e.d.Clock.Now()) || data.Series == nil || ev.Key != dev.ID || ev.TenantID != org {
			t.Fatalf("event: %s (%v)", ev.Data, err)
		}
	}
	if n != 1 {
		t.Fatalf("identity.device.drained events: %d, want 1", n)
	}
}
