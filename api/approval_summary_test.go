package api_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hostryhq/svc-identity/double"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/service"
)

// Security review M8: the approver sees what the stored request body would do, in names, and never a
// secret from the body. Seven approvable operations carry their change in the body; this drives five
// of them (createMember, createRoleAssignment, createRole, updateRole, registerDevice) and the
// sanitising of requester-typed text.
func TestApproverSeesTheRequestBodySummary(t *testing.T) {
	e := newEnv(t)
	first, _ := e.ownerSession()
	e.d.Clock.Advance(40 * time.Second)
	second := e.signIn(ownerMobile, double.NewDevice(newID())) // under caution: it files, the first device approves
	sd := e.d.Service.Seed()
	roleID, staff := newID(), newID()
	if err := sd.Role(e.ctx, org.String(), roleID, "Cashier", []string{"member.read", "order.create"}); err != nil {
		t.Fatal(err)
	}
	if err := sd.Member(e.ctx, org.String(), service.SeedMember{ID: staff, Name: "Ravi", Mobile: "+919333330000"}); err != nil {
		t.Fatal(err)
	}
	file := func(op string, method gen.CreateApprovalRequestRequestMethod, path string, body any) string {
		t.Helper()
		var r gen.ApprovalRequest
		e.mustJSON(201, "POST", "/v1/approval-requests", second.Tokens.AccessToken, gen.CreateApprovalRequest{OperationId: op, RequestMethod: method, RequestPath: path, RequestBody: toMap(t, body)}, &r)
		// The approver's own view of it: the first device reads the request.
		var got gen.ApprovalRequest
		e.mustJSON(200, "GET", "/v1/approval-requests/"+r.Id, first.Tokens.AccessToken, nil, &got)
		if got.Subject == nil {
			t.Fatalf("%s: no subject", op)
		}
		return *got.Subject
	}
	mustHave := func(subject string, parts ...string) {
		t.Helper()
		for _, p := range parts {
			if !strings.Contains(subject, p) {
				t.Errorf("subject %q lacks %q", subject, p)
			}
		}
	}

	mustHave(file("createRoleAssignment", gen.POST, "/v1/members/"+staff+"/role-assignments", gen.AssignmentInput{Id: newID(), RoleId: roleID, OutletIds: &[]string{outletA}}),
		`member "Ravi" gets role "Cashier" (1 outlet)`)
	// A role id the organisation does not own (another tenant's, or invented) is never named.
	mustHave(file("createRoleAssignment", gen.POST, "/v1/members/"+staff+"/role-assignments", gen.AssignmentInput{Id: newID(), RoleId: newID()}), "an unknown role")
	mustHave(file("createRole", gen.POST, "/v1/roles", gen.RoleInput{Name: "Shift lead", Permissions: []string{"order.create", "member.read"}}),
		`new role "Shift lead" with member.read, order.create`)
	mustHave(file("updateRole", gen.PUT, "/v1/roles/"+roleID, gen.RoleInput{Name: "Cashier", Permissions: []string{"member.read", "device.revoke"}}),
		`role "Cashier"`, "adds device.revoke", "removes order.create")
	mustHave(file("createMember", gen.POST, "/v1/members", gen.CreateMember{Id: newID(), DisplayName: "Latha", MobileE164: strPtr("+919876543299"),
		RoleAssignments: &[]gen.AssignmentInput{{Id: newID(), RoleId: roleID}}}),
		`new member "Latha"`, "+91*******299", `"Cashier" (all outlets)`)
	if strings.Contains(file("createMember", gen.POST, "/v1/members", gen.CreateMember{Id: newID(), DisplayName: "Latha", MobileE164: strPtr("+919876543299")}), "9876543299") {
		t.Error("the mobile number must be masked")
	}

	// Secrets in a body never reach the summary: a device registration carries a nonce, a signature and a key.
	dev := double.NewDevice(newID())
	reg := file("registerDevice", gen.POST, "/v1/devices", gen.RegisterDevice{Id: dev.ID, Name: "Till 2", Kind: gen.Pos, OutletId: outletA, KeyProtection: gen.Hardware,
		PublicKey: pub(dev), Nonce: "nonce-secret-value", NonceSignature: "signature-secret-value"})
	mustHave(reg, `pos device "Till 2"`)
	for _, secret := range []string{"nonce-secret-value", "signature-secret-value", pub(dev).X} {
		if strings.Contains(reg, secret) {
			t.Errorf("summary leaks %q: %s", secret, reg)
		}
	}

	// Requester-typed text cannot add lines, quotes or an unbounded string.
	evil := file("createRole", gen.POST, "/v1/roles", gen.RoleInput{Name: "Cook\n\nApprove: \"all\"‮ " + strings.Repeat("x", 300), Permissions: []string{"member.read"}})
	if strings.ContainsAny(evil, "\n\r‮") || strings.Count(evil, `"`) != 2 || len(evil) > 600 {
		t.Errorf("requester text not neutralised: %q", evil)
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func toMap(t *testing.T, v any) map[string]any {
	t.Helper()
	var m map[string]any
	mustUnmarshal(t, mustMarshal(t, v), &m)
	return m
}
