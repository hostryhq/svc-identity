package api_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/hostryhq/go-common/events"
	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/internal/gen"
)

// A3.4: the executor's vendor_access.recorded event sets the approval executed; identity voids no earlier grant, a
// replayed grant request is replay_secret, a refused outcome changes nothing and a repeat is harmless.
func TestExecutedSignalFromVendorAccessEvent(t *testing.T) {
	e := newEnv(t)
	admin := e.bootstrapAdmin("root@hostry.test")
	second := e.newVendorUser(admin, "second@hostry.test", gen.PlatformAdmin)
	e.d.Clock.Advance(8 * 24 * time.Hour)
	e.signInVendor(admin)
	e.signInVendor(second)
	var ap gen.VendorApproval
	e.mustJSON(201, "POST", "/internal/v1/vendor/approvals", admin.tok, gen.CreateVendorApproval{Kind: gen.ApprovalKindOrgSuspend, OrganisationId: strPtr(org.String()),
		Reason: "Owner asked to pause the account", TicketReference: "ONB-11", VerificationMethod: gen.RequesterVerificationCallbackToRegisteredNumber}, &ap, admin.h(e)...)
	e.d.Clock.Advance(31 * time.Second)
	e.mustJSON(200, "PUT", "/internal/v1/vendor/approvals/"+ap.Id+"/decision", second.tok, gen.ApproveVendorApproval{TotpCode: crypto.TOTP(second.secret, e.d.Clock.Now())}, nil, second.h(e)...)
	grant := func(hdr ...string) (int, []byte) {
		c, b, _ := e.do("POST", "/internal/v1/vendor/approvals/"+ap.Id+"/grants", second.tok, nil, append(second.h(e), hdr...)...)
		return c, b
	}
	c1, _ := grant("Idempotency-Key", "k1")
	c2, _ := grant("Idempotency-Key", "k2") // the earlier grant is not voided: two are live
	if c1 != 201 || c2 != 201 {
		t.Fatalf("two grants: %d %d", c1, c2)
	}
	c, b := grant("Idempotency-Key", "k1")
	if c != 409 || problemCode(b) != "idempotency.replay_secret" {
		t.Fatalf("replay: %d %s", c, b)
	}
	ev := func(typ, data string) events.Envelope { return events.Envelope{Type: typ, Data: json.RawMessage(data)} }
	state := func() gen.VendorApprovalState {
		var got gen.VendorApproval
		e.mustJSON(200, "GET", "/internal/v1/vendor/approvals/"+ap.Id, second.tok, nil, &got, second.h(e)...)
		return got.State
	}
	for _, d := range []events.Envelope{
		ev("tenancy.vendor_access.recorded", `{"approval_id":"`+ap.Id+`","grant_jti":"j","outcome":"refused"}`),
		ev("tenancy.vendor_access.recorded", `{"outcome":"succeeded","action_key":"vendor.read"}`), // another vendor action: no approval id
		ev("identity.device.drained", `{"approval_id":"`+ap.Id+`","outcome":"succeeded"}`),         // not a vendor-access event
	} {
		if err := e.d.Service.ConsumeVendorAccess(e.ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	if st := state(); st != gen.VendorApprovalStateApproved {
		t.Fatalf("nothing but a success executes: %s", st)
	}
	success := ev("billing.vendor_access.recorded", `{"approval_id":"`+ap.Id+`","grant_jti":"j","result":"success"}`)
	for i := 0; i < 2; i++ { // redelivery changes nothing
		if err := e.d.Service.ConsumeVendorAccess(e.ctx, success); err != nil {
			t.Fatal(err)
		}
	}
	if st := state(); st != gen.VendorApprovalStateCompleted {
		t.Fatalf("state %s, want completed (executed)", st)
	}
	c, b = grant()
	var p struct{ Code, Reason string }
	_ = json.Unmarshal(b, &p)
	if c != 409 || p.Reason != "executed" {
		t.Fatalf("a grant for an executed approval: %d %s", c, b)
	}
}
