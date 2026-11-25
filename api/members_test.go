package api_test

import (
	"testing"
	"time"

	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/svc-identity/double"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/service"
)

const (
	outletA  = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a61"
	outletB  = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a62"
	mgrMob   = "+919876500001"
	staffMob = "+919876500002"
)

func newID() string { return string(ids.New()) }

// managerSession seeds a manager (role with member and device administration but no owner rights)
// and signs them in, so grant-limit tests act as a non-owner.
func (e *env) managerSession(roleID string, perms []string) (gen.Session, string) {
	e.t.Helper()
	sd := e.d.Service.Seed()
	mid := newID()
	if err := sd.Role(e.ctx, org.String(), roleID, "Manager", perms); err != nil {
		e.t.Fatal(err)
	}
	if err := sd.Member(e.ctx, org.String(), seedMember(mid, "Mani", roleID)); err != nil {
		e.t.Fatal(err)
	}
	if _, err := sd.Account(e.ctx, org.String(), mid, mgrMob); err != nil {
		e.t.Fatal(err)
	}
	return e.signIn(mgrMob, double.NewDevice(newID())), mid
}

var managerPerms = []string{"member.read", "member.manage", "member.role.assign", "member.pin.authorise", "role.read", "role.manage", "device.read", "device.register", "device.activation_code.create", "device.revoke", "audit.read"}

func TestRoleGrantLimits(t *testing.T) {
	e := newEnv(t)
	owner, _ := e.ownerSession()
	mgrRole := newID()
	mgr, mgrID := e.managerSession(mgrRole, managerPerms)

	// IST-30 / G1: a manager cannot create a role holding a permission they lack.
	e.expect(403, "grant_not_permitted", "POST", "/v1/roles", mgr.Tokens.AccessToken, gen.RoleInput{Name: "Spy", Permissions: []string{"audit.read", "link.read"}})
	// G2: a role with an owner_grant permission (every strong_only one) is owner-only, even if the actor holds it.
	e.expect(403, "grant_not_permitted", "POST", "/v1/roles", mgr.Tokens.AccessToken, gen.RoleInput{Name: "Admin2", Permissions: []string{"member.manage"}})
	// A role within the actor's own non-owner-grant permissions is fine.
	var cashier gen.Role
	e.mustJSON(201, "POST", "/v1/roles", mgr.Tokens.AccessToken, gen.RoleInput{Name: "Cashier", Permissions: []string{"member.read", "device.read"}}, &cashier)
	// Unknown permission strings cannot be invented.
	e.expect(422, "", "POST", "/v1/roles", owner.Tokens.AccessToken, gen.RoleInput{Name: "X", Permissions: []string{"made.up"}})

	// G4: nobody changes their own assignments (owner included).
	e.expect(403, "grant_not_permitted", "POST", "/v1/members/"+mgrID+"/role-assignments", mgr.Tokens.AccessToken, gen.AssignmentInput{Id: newID(), RoleId: cashier.Id})
	e.expect(403, "grant_not_permitted", "POST", "/v1/members/"+owner.MemberId+"/role-assignments", owner.Tokens.AccessToken, gen.AssignmentInput{Id: newID(), RoleId: cashier.Id})

	// The manager adds a cashier-level member (G1 holds) and assigns the cashier role at an outlet.
	staff := newID()
	var m gen.Member
	e.mustJSON(201, "POST", "/v1/members", mgr.Tokens.AccessToken, gen.CreateMember{Id: staff, DisplayName: "Ravi"}, &m)
	e.mustJSON(201, "POST", "/v1/members/"+staff+"/role-assignments", mgr.Tokens.AccessToken, gen.AssignmentInput{Id: newID(), RoleId: cashier.Id, OutletIds: &[]string{outletA}}, nil)
	// ...but cannot assign the manager's own role onward (it has owner_grant permissions).
	e.expect(403, "grant_not_permitted", "POST", "/v1/members/"+staff+"/role-assignments", mgr.Tokens.AccessToken, gen.AssignmentInput{Id: newID(), RoleId: mgrRole})
	// The built-in owner role goes only through the owner-role operation.
	var roles gen.RolePage
	e.mustJSON(200, "GET", "/v1/roles", owner.Tokens.AccessToken, nil, &roles)
	var ownerRole string
	for _, r := range roles.Items {
		if r.BuiltIn {
			ownerRole = r.Id
		}
	}
	e.expect(422, "use_owner_role_operation", "POST", "/v1/members/"+staff+"/role-assignments", owner.Tokens.AccessToken, gen.AssignmentInput{Id: newID(), RoleId: ownerRole})
	// G3: a manager cannot make an owner; the owner can (step-up, fresh OTP).
	e.expect(403, "", "PUT", "/v1/members/"+staff+"/owner-role", mgr.Tokens.AccessToken, gen.OwnerRoleAssignment{Id: newID()})
	e.mustJSON(200, "PUT", "/v1/members/"+staff+"/owner-role", owner.Tokens.AccessToken, gen.OwnerRoleAssignment{Id: newID()}, nil)
	// The last owner cannot be removed; with two owners one can go, but not by themselves.
	e.expect(403, "grant_not_permitted", "DELETE", "/v1/members/"+owner.MemberId+"/owner-role", owner.Tokens.AccessToken, nil)
	e.mustJSON(204, "DELETE", "/v1/members/"+staff+"/owner-role", owner.Tokens.AccessToken, nil, nil)
	// G5: a manager cannot suspend the owner (permissions not a subset), and not themselves.
	e.expect(403, "grant_not_permitted", "PATCH", "/v1/members/"+owner.MemberId, mgr.Tokens.AccessToken, gen.UpdateMember{Status: statusPtr(gen.UpdateMemberStatusSuspended)})
	e.expect(403, "grant_not_permitted", "PATCH", "/v1/members/"+mgrID, mgr.Tokens.AccessToken, gen.UpdateMember{Status: statusPtr(gen.UpdateMemberStatusSuspended)})
}

func statusPtr(s gen.UpdateMemberStatus) *gen.UpdateMemberStatus { return &s }

// G7: grants are read from stored assignments at write time, not from the caller's token.
func TestDemotedManagerTokenGrantsNothing(t *testing.T) {
	e := newEnv(t)
	owner, _ := e.ownerSession()
	mgrRole := newID()
	mgr, mgrID := e.managerSession(mgrRole, managerPerms)
	var m gen.Member
	e.mustJSON(200, "GET", "/v1/members/"+mgrID, owner.Tokens.AccessToken, nil, &m)
	e.mustJSON(204, "DELETE", "/v1/members/"+mgrID+"/role-assignments/"+m.RoleAssignments[0].Id, owner.Tokens.AccessToken, nil, nil)
	// The token is 15 minutes old at most and still carries the old grants, but the stored assignments win.
	e.expect(403, "grant_not_permitted", "POST", "/v1/roles", mgr.Tokens.AccessToken, gen.RoleInput{Name: "Late", Permissions: []string{"member.read"}})
}

// IST-31: cross-tenant isolation of identity resources: 404, and organisation ids in bodies are ignored.
func TestTenantIsolationOfIdentityResources(t *testing.T) {
	e := newEnv(t)
	ownerA, _ := e.ownerSession()
	orgB := ids.ID("018f0000-0000-7000-8000-00000000000b")
	tokB := e.d.UserToken(orgB, "someone", "", grantsAll())
	// Tenant B seeds its own data.
	roleB, memberB := newID(), newID()
	sd := e.d.Service.Seed()
	if err := sd.Role(e.ctx, orgB.String(), roleB, "B role", []string{"member.read"}); err != nil {
		t.Fatal(err)
	}
	if err := sd.Member(e.ctx, orgB.String(), seedMember(memberB, "Bee", roleB)); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/v1/members/" + memberB, "/v1/roles/" + roleB} {
		e.expect(404, "", "GET", p, ownerA.Tokens.AccessToken, nil)
		e.mustJSON(200, "GET", p, tokB, nil, nil)
	}
	e.expect(404, "", "PATCH", "/v1/members/"+memberB, ownerA.Tokens.AccessToken, gen.UpdateMember{DisplayName: strPtr("Hacked")})
	e.expect(404, "", "POST", "/v1/members/"+memberB+"/role-assignments", ownerA.Tokens.AccessToken, gen.AssignmentInput{Id: newID(), RoleId: roleB})
	// A list under A never contains B's members.
	var page gen.MemberPage
	e.mustJSON(200, "GET", "/v1/members", ownerA.Tokens.AccessToken, nil, &page)
	for _, m := range page.Items {
		if m.Id == memberB {
			t.Fatal("tenant B member visible to tenant A")
		}
	}
	// A tenant_id in the body or query is never read (unknown fields are refused outright).
	e.expect(422, "", "POST", "/v1/roles", ownerA.Tokens.AccessToken, map[string]any{"name": "x", "permissions": []string{}, "tenant_id": orgB.String()})
}

func strPtr(s string) *string { return &s }

// IST-13 and IST-17: a binding under caution cannot do strong_only operations without a per-operation
// approval from an older binding; pin sessions never can.
func TestNewDeviceCautionBlocksStrongOnlyUntilApproved(t *testing.T) {
	e := newEnv(t)
	first, _ := e.ownerSession()
	e.d.Clock.Advance(40 * time.Second)
	d2 := double.NewDevice(newID())
	second := e.signIn(ownerMobile, d2) // same account, new device: caution
	if second.CautionUntil == nil {
		t.Fatal("a second device must be under caution")
	}
	body := gen.CreateMember{Id: newID(), DisplayName: "Sita"}
	e.expect(403, "approval_required", "POST", "/v1/members", second.Tokens.AccessToken, body)
	// Reading and signing out are not blocked.
	e.mustJSON(200, "GET", "/v1/members", second.Tokens.AccessToken, nil, nil)
	// The new device files the exact request; the first device (not under caution) approves it.
	var req gen.ApprovalRequest
	e.mustJSON(201, "POST", "/v1/approval-requests", second.Tokens.AccessToken, gen.CreateApprovalRequest{OperationId: "createMember", RequestMethod: gen.POST, RequestPath: "/v1/members", RequestBody: map[string]any{"id": body.Id, "display_name": body.DisplayName}}, &req)
	// A binding under caution can approve nothing.
	e.expect(403, "", "PUT", "/v1/approval-requests/"+req.Id+"/decision", second.Tokens.AccessToken, gen.DecideApproval{Decision: gen.Approve})
	e.mustJSON(200, "PUT", "/v1/approval-requests/"+req.Id+"/decision", first.Tokens.AccessToken, gen.DecideApproval{Decision: gen.Approve}, nil)
	var got gen.ApprovalRequest
	e.mustJSON(200, "GET", "/v1/approval-requests/"+req.Id, second.Tokens.AccessToken, nil, &got)
	if got.ApprovalToken == nil {
		t.Fatal("approval token not shown to the requester")
	}
	// Exactly one operation: the same body with the token works once, the token is single use.
	e.mustJSON(201, "POST", "/v1/members", second.Tokens.AccessToken, body, nil, "Hostry-Approval", *got.ApprovalToken)
	body2 := gen.CreateMember{Id: newID(), DisplayName: "Sita"}
	e.expect(403, "approval_required", "POST", "/v1/members", second.Tokens.AccessToken, body2, "Hostry-Approval", *got.ApprovalToken)
	// After 24 hours the block lifts without any approval: a refreshed token carries no caution.
	e.d.Clock.Advance(25 * time.Hour)
	var tp gen.TokenPair
	e.mustJSON(200, "POST", "/v1/tokens/refresh", "", gen.RefreshSession{RefreshToken: *second.Tokens.RefreshToken, DeviceId: d2.ID,
		Proof: d2.Assert(e.d.Clock.Now(), e.jti(), service.AssertionClaims{Rth: service.RefreshHash(*second.Tokens.RefreshToken)})}, &tp)
	e.mustJSON(201, "POST", "/v1/members", tp.AccessToken, gen.CreateMember{Id: newID(), DisplayName: "Gita"}, nil)
}

// IST-33: adding a member by phone answers the same for numbers with and without accounts and leaks nothing.
func TestMemberAddByPhoneIsIdenticalForKnownAndUnknownNumbers(t *testing.T) {
	e := newEnv(t)
	owner, _ := e.ownerSession()
	var a, b gen.Member
	e.mustJSON(201, "POST", "/v1/members", owner.Tokens.AccessToken, gen.CreateMember{Id: newID(), DisplayName: "Known", MobileE164: strPtr(ownerMobile)}, &a)
	e.mustJSON(201, "POST", "/v1/members", owner.Tokens.AccessToken, gen.CreateMember{Id: newID(), DisplayName: "Unknown", MobileE164: strPtr("+919222222222")}, &b)
	if a.Status != gen.MemberStatusInvited || b.Status != gen.MemberStatusInvited || a.HasPin != b.HasPin || len(a.RoleAssignments) != len(b.RoleAssignments) {
		t.Fatalf("responses differ: %+v %+v", a, b)
	}
	if a.MobileMasked == nil || *a.MobileMasked == ownerMobile {
		t.Fatal("number must be masked")
	}
}

func TestListAndAuditAreScopedAndAppendOnly(t *testing.T) {
	e := newEnv(t)
	owner, _ := e.ownerSession()
	e.mustJSON(201, "POST", "/v1/roles", owner.Tokens.AccessToken, gen.RoleInput{Name: "Cashier", Permissions: []string{"member.read"}}, nil)
	var page gen.TenantAuditPage
	e.mustJSON(200, "GET", "/v1/audit-entries", owner.Tokens.AccessToken, nil, &page)
	if len(page.Items) == 0 || page.Items[0].Action != "role.created" {
		t.Fatalf("audit newest first: %+v", page.Items)
	}
	// No operation edits or deletes an entry.
	e.expect(404, "", "DELETE", "/v1/audit-entries/"+page.Items[0].Id, owner.Tokens.AccessToken, nil)
	e.expect(404, "", "PUT", "/v1/audit-entries/"+page.Items[0].Id, owner.Tokens.AccessToken, map[string]any{})
}
