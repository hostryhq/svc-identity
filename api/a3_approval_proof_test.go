package api_test

import (
	"testing"

	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/service"
)

// ADR-0005 A3.1 check: verifyProof for kind approval derives every field section 8 binds. A proof made over
// the full record verifies; changing any bound field, or leaving the record incomplete, does not.
func TestApprovalProofBindsTheRecordFields(t *testing.T) {
	f := newPinFixture(t)
	hash := "sha256:cf03a846706f29a88ba61a212f79e7c224142fdd5df92fc1d7ed8bb1283fb8c8"
	at := f.e.d.Clock.Now()
	bound := service.ApprovalBound{ApprovalID: newID(), Permission: "bill.void", Target: "bill-1", Requester: newID(), Reason: "guest left", ApprovedAt: at}
	proof := service.Proof(f.sec.ProofKey, service.ApprovalProofMessageBound(hash, f.dev.ID, f.staff, f.pack.PackV, 1, bound))
	ask := func(mut func(*gen.ProofVerification)) (int, gen.ProofVerdict) {
		in := gen.ProofVerification{Kind: gen.ProofVerificationKindApproval, DeviceId: f.dev.ID, MemberId: f.staff, PackV: f.pack.PackV, PinV: 1, Proof: proof, ActionHash: &hash,
			ApprovalId: &bound.ApprovalID, Permission: &bound.Permission, Target: &bound.Target, RequesterId: &bound.Requester, ApprovedAt: &at, Reason: &bound.Reason}
		mut(&in)
		code, b, _ := f.e.do("POST", "/internal/v1/proof-verifications", "", in, "Hostry-Service-Token", f.e.d.ServiceToken("sync", org))
		var v gen.ProofVerdict
		if code == 200 {
			mustUnmarshal(t, b, &v)
		}
		return code, v
	}
	if c, v := ask(func(*gen.ProofVerification) {}); c != 200 || !v.Valid {
		t.Fatalf("the proof over the full record: %d %+v", c, v)
	}
	other := "bill.refund"
	if c, v := ask(func(in *gen.ProofVerification) { in.Permission = &other }); c != 200 || v.Valid {
		t.Fatalf("a changed permission must not verify: %d %+v", c, v)
	}
	if c, _ := ask(func(in *gen.ProofVerification) { in.RequesterId = nil }); c != 422 {
		t.Fatalf("an incomplete record: %d", c)
	}
}
