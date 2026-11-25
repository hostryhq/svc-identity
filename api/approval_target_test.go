package api_test

import (
	"strings"
	"testing"
	"time"

	"github.com/hostryhq/svc-identity/double"
	"github.com/hostryhq/svc-identity/internal/gen"
)

// SR-H1 / IST-13: an approval is bound to method and concrete path, not only to operation and body.
// An approval filed for removing the owner role of member A releases nothing on member B, and the
// approver sees a subject built from the operation and the target.
func TestApprovalIsBoundToTheTargetResource(t *testing.T) {
	e := newEnv(t)
	first, _ := e.ownerSession()
	e.d.Clock.Advance(40 * time.Second)
	second := e.signIn(ownerMobile, double.NewDevice(newID()))
	if second.CautionUntil == nil {
		t.Fatal("second device must be under caution")
	}
	memberA, memberB := newID(), newID()
	path := func(id string) string { return "/v1/members/" + id + "/owner-role" }
	var req gen.ApprovalRequest
	// A request naming a path that is not the operation's is refused at filing.
	e.expect(422, "", "POST", "/v1/approval-requests", second.Tokens.AccessToken, gen.CreateApprovalRequest{OperationId: "removeOwnerRole",
		RequestMethod: gen.CreateApprovalRequestRequestMethodDELETE, RequestPath: "/v1/members", RequestBody: map[string]any{}})
	e.mustJSON(201, "POST", "/v1/approval-requests", second.Tokens.AccessToken, gen.CreateApprovalRequest{OperationId: "removeOwnerRole",
		RequestMethod: gen.CreateApprovalRequestRequestMethodDELETE, RequestPath: path(memberA), RequestBody: map[string]any{}}, &req)
	if !strings.Contains(req.Subject, "Remove owner role") || !strings.Contains(req.Subject, memberA) {
		t.Fatalf("the approver must see what is approved: %v", req.Subject)
	}
	e.mustJSON(200, "PUT", "/v1/approval-requests/"+req.Id+"/decision", first.Tokens.AccessToken, gen.DecideApproval{Decision: gen.Approve}, nil)
	var got gen.ApprovalRequest
	e.mustJSON(200, "GET", "/v1/approval-requests/"+req.Id, second.Tokens.AccessToken, nil, &got)
	if got.ApprovalToken == nil {
		t.Fatal("no approval token")
	}
	// The same token on another member is refused by the guard, and so is another method.
	e.expect(403, "approval_required", "DELETE", path(memberB), second.Tokens.AccessToken, map[string]any{}, "Hostry-Approval", *got.ApprovalToken)
	e.expect(403, "approval_required", "PUT", path(memberA), second.Tokens.AccessToken, map[string]any{}, "Hostry-Approval", *got.ApprovalToken)
	// On the approved target the guard releases it (the handler then decides on its own merits).
	code, body, _ := e.do("DELETE", path(memberA), second.Tokens.AccessToken, map[string]any{}, "Hostry-Approval", *got.ApprovalToken)
	if code == 403 && problemCode(body) == "approval_required" {
		t.Fatalf("approved target refused by the guard: %s", body)
	}
}
