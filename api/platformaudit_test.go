package api_test

import (
	"encoding/base64"
	"encoding/json"
	"regexp"

	"github.com/hostryhq/svc-identity/service"
	"strings"
	"testing"
	"time"

	"github.com/hostryhq/svc-identity/double"
	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/repository"
	openapi_types "github.com/oapi-codegen/runtime/types"
)

// ADR-0013 V5 item 3: an organisation-less vendor route writes its access row to the platform table with
// no tenant; a route that names an organisation writes a tenant row. No pseudo-tenant exists on either.
func TestVendorAccessRowsAreTenantlessOnOrganisationLessRoutes(t *testing.T) {
	e := newEnv(t)
	admin := e.bootstrapAdmin("root@hostry.test")
	owner, _ := e.ownerSession()
	e.activate(owner.Tokens.AccessToken, gen.Pos, double.NewDevice(newID()))

	e.mustJSON(200, "GET", "/internal/v1/vendor/users", admin.tok, nil, nil, admin.h(e)...)
	plat := e.d.Access.PlatformEntries()
	if len(plat) == 0 || plat[len(plat)-1].ActionKey != "listVendorUsers" || plat[len(plat)-1].TenantID != "" {
		t.Fatalf("platform rows: %+v", plat)
	}
	e.mustJSON(200, "GET", "/internal/v1/vendor/organisations/"+org.String()+"/devices", admin.tok, nil, nil, admin.h(e)...)
	rows := e.d.Access.Entries()
	if len(rows) != 1 || rows[0].ActionKey != "listOrganisationDevices" || rows[0].TenantID != org.String() {
		t.Fatalf("tenant rows: %+v", rows)
	}
	for _, r := range append(rows, e.d.Access.PlatformEntries()...) {
		if r.TenantID == repository.Platform {
			t.Fatalf("pseudo-tenant row: %+v", r)
		}
	}
	// Fail closed: with the platform sink failing nothing is returned and nothing changes.
	e.d.Access.FailInTx = true
	code, b, _ := e.do("GET", "/internal/v1/vendor/users", admin.tok, nil, admin.h(e)...)
	e.d.Access.FailInTx = false
	if code < 500 || strings.Contains(string(b), "root@hostry.test") {
		t.Fatalf("platform audit failure must fail closed: %d %s", code, b)
	}
}

// A replayed vendor request runs no handler, but it is still an access: its row is written, on the same
// table as the original, and a failing sink refuses the replay.
func TestReplayedVendorRequestIsStillRecorded(t *testing.T) {
	e := newEnv(t)
	admin := e.bootstrapAdmin("root@hostry.test")
	owner, _ := e.ownerSession()
	e.activate(owner.Tokens.AccessToken, gen.Pos, double.NewDevice(newID()))
	key := []string{"Idempotency-Key", "replay-key-1"}

	body := gen.CreateVendorUser{Id: newID(), Email: openapiEmail("new@hostry.test"), DisplayName: "New", Role: gen.Support}
	hdr := append(admin.h(e), key...)
	e.mustJSON(201, "POST", "/internal/v1/vendor/users", admin.tok, body, nil, hdr...)
	before := len(e.d.Access.PlatformEntries())
	e.mustJSON(201, "POST", "/internal/v1/vendor/users", admin.tok, body, nil, hdr...)
	if n := len(e.d.Access.PlatformEntries()); n != before+1 {
		t.Fatalf("platform rows after a replay: %d, want %d", n, before+1)
	}

	// An organisation route: the replay is recorded against the organisation of the path.
	revoke := gen.VendorRevoke{Confirm: true, TicketReference: "SUP-1", Reason: "Owner called: tablet lost", VerificationMethod: gen.RequesterVerificationCallbackToRegisteredNumber}
	var devs gen.VendorDevicePage
	e.mustJSON(200, "GET", "/internal/v1/vendor/organisations/"+org.String()+"/devices", admin.tok, nil, &devs, admin.h(e)...)
	path := "/internal/v1/vendor/organisations/" + org.String() + "/devices/" + devs.Items[0].Id + "/revocation"
	hdr2 := append(admin.h(e), "Idempotency-Key", "replay-key-2")
	e.mustJSON(200, "PUT", path, admin.tok, revoke, nil, hdr2...)
	n := len(e.d.Access.Entries())
	e.mustJSON(200, "PUT", path, admin.tok, revoke, nil, hdr2...)
	rows := e.d.Access.Entries()
	if len(rows) != n+1 || rows[len(rows)-1].TenantID != org.String() {
		t.Fatalf("tenant rows after a replay: %d, want %d (%+v)", len(rows), n+1, rows[len(rows)-1])
	}
	e.d.Access.FailInTx = true
	code, _, _ := e.do("PUT", path, admin.tok, revoke, hdr2...)
	e.d.Access.FailInTx = false
	if code < 500 {
		t.Fatalf("a replay with a failing audit sink must be refused: %d", code)
	}
}

func dateOf(y int, m time.Month, d int) openapi_types.Date {
	return openapi_types.Date{Time: time.Date(y, m, d, 0, 0, 0, 0, time.UTC)}
}

var subjectHashRE = regexp.MustCompile(`^[0-9a-f]{64}$`) // A2.6: lower-case hex, no prefix

func jwtPayload(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWS: %q", tok)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// ADR-0014 A1.3: the approval kinds executed by another service. The decision carries a single-purpose
// grant bound to what was approved; the kinds lapse after 24 hours; tax_rule_set_publish names no
// organisation; a vendor user who neither requested nor may approve cannot see the approval.
func TestGrantKindApprovalsCarryAGrantAndLapse(t *testing.T) {
	e := newEnv(t)
	admin := e.bootstrapAdmin("root@hostry.test")
	second := e.newVendorUser(admin, "second@hostry.test", gen.PlatformAdmin)
	nobody := e.newVendorUser(admin, "support@hostry.test", gen.Support)
	e.d.Clock.Advance(8 * 24 * time.Hour)
	e.signInVendor(admin)
	e.signInVendor(second)
	e.signInVendor(nobody)

	decide := func(who *vendor, id string) (int, gen.ApprovalDecision) {
		e.d.Clock.Advance(31 * time.Second)
		var d gen.ApprovalDecision
		code, b, _ := e.do("PUT", "/internal/v1/vendor/approvals/"+id+"/decision", who.tok, gen.ApproveVendorApproval{TotpCode: crypto.TOTP(who.secret, e.d.Clock.Now())}, who.h(e)...)
		if code == 200 {
			mustUnmarshal(t, b, &d)
		}
		return code, d
	}

	// org_suspend: needs an organisation, lapses after 24 hours, the decision carries the grant.
	var ap gen.VendorApproval
	e.mustJSON(201, "POST", "/internal/v1/vendor/approvals", admin.tok, gen.CreateVendorApproval{Kind: gen.ApprovalKindOrgSuspend, OrganisationId: strPtr(org.String()),
		Reason: "Owner asked to pause the account", TicketReference: "ONB-11", VerificationMethod: gen.RequesterVerificationCallbackToRegisteredNumber}, &ap, admin.h(e)...)
	if ap.ExpiresAt.Sub(ap.CreatedAt) != 24*time.Hour || ap.OrganisationId == nil || *ap.OrganisationId != org.String() {
		t.Fatalf("org_suspend approval: %+v", ap)
	}
	e.expect(422, "", "POST", "/internal/v1/vendor/approvals", admin.tok, gen.CreateVendorApproval{Kind: gen.ApprovalKindOrgSuspend, Reason: "Owner asked to pause the account",
		TicketReference: "ONB-11", VerificationMethod: gen.RequesterVerificationCallbackToRegisteredNumber}, admin.h(e)...)
	if c, _ := decide(admin, ap.Id); c != 409 { // the requester cannot approve (two persons)
		t.Fatalf("requester approves own request: %d", c)
	}
	e.expect(404, "", "GET", "/internal/v1/vendor/approvals/"+ap.Id, nobody.tok, nil, nobody.h(e)...)
	e.mustJSON(200, "GET", "/internal/v1/vendor/approvals/"+ap.Id, admin.tok, nil, nil, admin.h(e)...)
	c, dec := decide(second, ap.Id)
	if c != 200 || dec.Grant == nil || dec.Approval.State != gen.VendorApprovalStateApproved || dec.CodeHalf != nil {
		t.Fatalf("decision: %d %+v", c, dec)
	}
	claims := jwtPayload(t, dec.Grant.Token)
	if claims["typ"] != "vendor_approval" || claims["realm"] != "vendor" || claims["kind"] != "org_suspend" || claims["org"] != org.String() ||
		claims["requester"] != admin.id || claims["approver"] != second.id || claims["approval_id"] != ap.Id || claims["aud"] != "tenancy" || !subjectHashRE.MatchString(claims["subject_hash"].(string)) {
		t.Fatalf("grant claims: %v", claims)
	}
	if dec.Grant.ExpiresAt.Sub(e.d.Clock.Now()) != 5*time.Minute {
		t.Fatalf("grant lifetime: %v", dec.Grant.ExpiresAt.Sub(e.d.Clock.Now()))
	}
	// If the executor refuses, the approval stays approved and the approver can have a fresh grant.
	c2, again := decide(second, ap.Id)
	if c2 != 200 || again.Grant == nil || again.Grant.Token == dec.Grant.Token {
		t.Fatalf("fresh grant: %d %+v", c2, again)
	}
	if c3, _ := decide(nobody, ap.Id); c3 == 200 {
		t.Fatal("a user without the approve permission decided")
	}
	e.d.Clock.Advance(24 * time.Hour)
	e.signInVendor(admin)
	e.signInVendor(second)
	e.mustJSON(200, "GET", "/internal/v1/vendor/approvals/"+ap.Id, admin.tok, nil, &ap, admin.h(e)...)
	if ap.State != gen.VendorApprovalStateExpired {
		t.Fatalf("after 24 hours: %s", ap.State)
	}
	if c4, _ := decide(second, ap.Id); c4 != 409 {
		t.Fatalf("lapsed approval decided: %d", c4)
	}

	// tax_rule_set_publish names no organisation and binds the rule set into the grant's subject hash.
	rule := gen.CreateVendorApproval{Kind: gen.ApprovalKindTaxRuleSetPublish, Reason: "Quarterly rule set update", TicketReference: "TAX-3",
		VerificationMethod: gen.RequesterVerificationCallbackToRegisteredNumber, RuleSetId: strPtr(newID()),
		RuleSetContentHash: strPtr("sha256:" + strings.Repeat("ab", 32))}
	d := dateOf(2026, 12, 1)
	rule.EffectiveDate = &d
	var tp gen.VendorApproval
	e.mustJSON(201, "POST", "/internal/v1/vendor/approvals", admin.tok, rule, &tp, admin.h(e)...)
	if tp.OrganisationId != nil {
		t.Fatalf("tax rule approval names an organisation: %+v", tp)
	}
	rule.OrganisationId = strPtr(org.String())
	e.expect(422, "", "POST", "/internal/v1/vendor/approvals", admin.tok, rule, admin.h(e)...)
	c5, tdec := decide(second, tp.Id)
	if c5 != 200 || tdec.Grant == nil || jwtPayload(t, tdec.Grant.Token)["org"] != service.PlatformOrg || jwtPayload(t, tdec.Grant.Token)["aud"] != "billing" { // O2-9 (provisional): org is "platform"
		t.Fatalf("tax rule decision: %d %+v", c5, tdec)
	}
}
