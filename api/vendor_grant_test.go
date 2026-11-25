package api_test

import (
	"context"
	"testing"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/internal/token"
	"github.com/hostryhq/svc-identity/service"
	openapi_types "github.com/oapi-codegen/runtime/types"
)

// A grant issued for each of the four kinds verifies under go-auth's GrantVerifier, the one the
// executing services use (ADR-0014 A2.6): signature and kid, typ, realm, aud, kind, org, approver,
// lifetime, and the subject hash recomputed from the executor's own state. The expected hash texts
// are written out here, from the contract, not computed with identity's own function.
func TestVendorGrantsVerifyUnderGoAuth(t *testing.T) {
	e := newEnv(t)
	admin := e.bootstrapAdmin("root@hostry.test")
	second := e.newVendorUser(admin, "second@hostry.test", gen.PlatformAdmin)
	e.d.Clock.Advance(8 * 24 * time.Hour) // the approver's account must be older than 7 days
	e.signInVendor(admin)
	e.signInVendor(second)

	const (
		ruleSet = "72bdd3f5-68b5-59b0-8e62-2075a1f43c47"
		chash   = "a3f5c0de9d1b7e44c2f9a8b6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6"
	)
	eff := openapi_types.Date{Time: time.Date(2026, 12, 15, 0, 0, 0, 0, time.UTC)}
	cases := []struct {
		kind    gen.ApprovalKind
		aud     string
		org     string // the org claim and what the executor passes
		subject string // the hashed text of the contract
		req     func(r *gen.CreateVendorApproval)
	}{
		{gen.ApprovalKindOrgSuspend, "tenancy", org.String(), "org_suspend\n" + org.String() + "\nsuspended", func(r *gen.CreateVendorApproval) { r.OrganisationId = strPtr(org.String()) }},
		{gen.ApprovalKindOrgReinstate, "tenancy", org.String(), "org_reinstate\n" + org.String() + "\nactive", func(r *gen.CreateVendorApproval) { r.OrganisationId = strPtr(org.String()) }},
		{gen.ApprovalKindOrgClose, "tenancy", org.String(), "org_close\n" + org.String() + "\nclosed", func(r *gen.CreateVendorApproval) { r.OrganisationId = strPtr(org.String()) }},
		{gen.ApprovalKindTaxRuleSetPublish, "billing", "platform", "tax_rule_set_publish\n" + ruleSet + "\n" + chash + "\n2026-12-15", func(r *gen.CreateVendorApproval) {
			r.RuleSetId, r.RuleSetContentHash, r.EffectiveDate = strPtr(ruleSet), strPtr(chash), &eff
		}},
	}
	for _, c := range cases {
		t.Run(string(c.kind), func(t *testing.T) {
			req := gen.CreateVendorApproval{Kind: c.kind, Reason: "Owner asked for this by phone", TicketReference: "SUP-9", VerificationMethod: gen.RequesterVerificationCallbackToRegisteredNumber}
			c.req(&req)
			var ap gen.VendorApproval
			e.mustJSON(201, "POST", "/internal/v1/vendor/approvals", admin.tok, req, &ap, admin.h(e)...)
			e.d.Clock.Advance(31 * time.Second)
			var dec gen.ApprovalDecision
			e.mustJSON(200, "PUT", "/internal/v1/vendor/approvals/"+ap.Id+"/decision", second.tok, gen.ApproveVendorApproval{TotpCode: crypto.TOTP(second.secret, e.d.Clock.Now())}, &dec, second.h(e)...)
			if dec.Grant == nil || dec.Grant.Token == "" {
				t.Fatalf("no grant: %+v", dec)
			}
			v := &auth.GrantVerifier{Keys: e.d.Signer.VendorKeys(), Issuer: token.VendorIssuer, Audience: c.aud, Clock: e.d.Clock, Used: auth.NewMemoryGrantUsed(e.d.Clock)}
			want := auth.GrantWant{Kind: string(c.kind), Org: c.org, Approver: second.id, SubjectHash: func() (string, error) { return auth.SubjectHash(string(c.kind), splitFields(c.subject)...), nil }}
			cl, err := v.Verify(context.Background(), dec.Grant.Token, want)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if cl.ApprovalID != ap.Id || cl.Requester != admin.id || cl.Approver != second.id || cl.ExpiresAt-cl.IssuedAt != 300 {
				t.Fatalf("claims: %+v", cl)
			}
			if _, err := v.Verify(context.Background(), dec.Grant.Token, want); !hasCode(err, auth.CodeGrantUsed) {
				t.Fatalf("a second use must be grant.used: %v", err)
			}
			// What the executor sees differently is refused: another service, another organisation, another subject.
			other := &auth.GrantVerifier{Keys: e.d.Signer.VendorKeys(), Issuer: token.VendorIssuer, Audience: "orders", Clock: e.d.Clock}
			if _, err := other.Verify(context.Background(), dec.Grant.Token, want); !hasCode(err, auth.CodeGrantInvalid) {
				t.Fatalf("wrong audience: %v", err)
			}
			moved := want
			moved.SubjectHash = func() (string, error) { return auth.SubjectHash(string(c.kind), "changed"), nil }
			if _, err := (&auth.GrantVerifier{Keys: e.d.Signer.VendorKeys(), Issuer: token.VendorIssuer, Audience: c.aud, Clock: e.d.Clock}).Verify(context.Background(), dec.Grant.Token, moved); !hasCode(err, auth.CodeGrantSubjectMismatch) {
				t.Fatalf("changed subject: %v", err)
			}
			e.d.Clock.Advance(service.GrantTTL + time.Second)
			if _, err := (&auth.GrantVerifier{Keys: e.d.Signer.VendorKeys(), Issuer: token.VendorIssuer, Audience: c.aud, Clock: e.d.Clock}).Verify(context.Background(), dec.Grant.Token, want); !hasCode(err, auth.CodeGrantExpired) {
				t.Fatalf("after 5 minutes: %v", err)
			}
			e.signInVendor(admin)
			e.signInVendor(second)
		})
	}
}

// splitFields turns the hashed text "kind\nfield\nfield" into the fields after the kind.
func splitFields(text string) []string {
	var out []string
	start, first := 0, true
	for i := 0; i <= len(text); i++ {
		if i == len(text) || text[i] == '\n' {
			if !first {
				out = append(out, text[start:i])
			}
			first, start = false, i+1
		}
	}
	return out
}

func hasCode(err error, code string) bool {
	ae, ok := err.(*apperr.Error)
	return ok && ae.Code == code
}
