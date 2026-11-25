package service

import (
	"context"
	"strings"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/grantlimit"
	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/repository"
)

func memberDTO(m *member) gen.Member {
	g := gen.Member{Id: m.ID, DisplayName: m.DisplayName, Status: gen.MemberStatus(m.Status), HasPin: m.PinVerif != "",
		CreatedAt: m.CreatedAt, RoleAssignments: []gen.RoleAssignment{}}
	if m.Mobile != "" {
		mm := maskMobile(m.Mobile)
		g.MobileMasked = &mm
	}
	for _, a := range m.Assignments {
		ra := gen.RoleAssignment{Id: a.ID, RoleId: a.RoleID}
		if len(a.Outlets) > 0 {
			o := append([]string(nil), a.Outlets...)
			ra.OutletIds = &o
		}
		g.RoleAssignments = append(g.RoleAssignments, ra)
	}
	return g
}

func roleDTO(r *role) gen.Role {
	return gen.Role{Id: r.ID, Name: r.Name, BuiltIn: r.BuiltIn, Permissions: append([]string{}, r.Perms...), CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
}

func scopeOf(outlets []string) auth.OutletScope {
	if len(outlets) == 0 {
		return auth.AllOutlets()
	}
	return auth.OnlyOutlets(outlets...)
}

// memberOutletsOverlap reports whether any of the member's assignments reaches the scope.
func memberInScope(m *member, scope auth.OutletScope) bool {
	if scope.All() {
		return true
	}
	if len(m.Assignments) == 0 {
		return false
	}
	for _, a := range m.Assignments {
		if len(a.Outlets) == 0 {
			return true
		}
		for _, o := range a.Outlets {
			if scope.Contains(o) {
				return true
			}
		}
	}
	return false
}

// ListMembers lists members in the caller's outlet scope (mobile numbers only masked).
func (s *Service) ListMembers(ctx context.Context, p gen.ListMembersParams) (gen.MemberPage, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.MemberPage{}, errUnauth()
	}
	scope, err := auth.ScopeFor(ctx, "member.read")
	if err != nil {
		return gen.MemberPage{}, err
	}
	limit := pageLimit(p.Limit, 50, 200)
	out := gen.MemberPage{Items: []gen.Member{}}
	err = s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		ms, err := list[member](tx, kMember, pr.TenantID, deref(p.Cursor), 0)
		if err != nil {
			return err
		}
		for i := range ms {
			if !memberInScope(&ms[i], scope) || (p.Q != nil && !strings.Contains(strings.ToLower(ms[i].DisplayName), strings.ToLower(*p.Q))) {
				continue
			}
			if len(out.Items) == limit {
				c := out.Items[len(out.Items)-1].Id
				out.NextCursor = &c
				break
			}
			out.Items = append(out.Items, memberDTO(&ms[i]))
		}
		return nil
	})
	return out, err
}

// GetMember returns a member visible in the caller's scope; anything else is 404.
func (s *Service) GetMember(ctx context.Context, id string) (gen.Member, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.Member{}, errUnauth()
	}
	scope, err := auth.ScopeFor(ctx, "member.read")
	if err != nil {
		return gen.Member{}, err
	}
	var out gen.Member
	err = s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		m, err := get[member](tx, kMember, pr.TenantID, id)
		if err != nil || m == nil || !memberInScope(m, scope) {
			return notFoundOr(err)
		}
		out = memberDTO(m)
		return nil
	})
	return out, err
}

type actorCtx struct {
	pr    auth.Principal
	roles map[string]*role
	owner string
	h     grantlimit.Holdings
}

func (s *Service) actorFor(ctx context.Context, tx repository.Tx) (*actorCtx, error) {
	pr, ok := principal(ctx)
	if !ok {
		return nil, errUnauth()
	}
	roles, ownerID, err := s.loadRoles(tx, pr.TenantID)
	if err != nil {
		return nil, err
	}
	h, err := s.actorHoldings(tx, pr.TenantID, pr.Subject)
	if err != nil {
		return nil, err
	}
	return &actorCtx{pr: pr, roles: roles, owner: ownerID, h: h}, nil
}

func (a *actorCtx) role(id string) (grantlimit.Role, bool, *role) {
	r := a.roles[id]
	if r == nil {
		return grantlimit.Role{}, false, nil
	}
	return grantlimit.Role{ID: r.ID, Perms: r.Perms}, r.BuiltIn, r
}

func (s *Service) holdingsOf(a *actorCtx, m *member) grantlimit.Holdings {
	return holdings(m, a.roles, a.owner)
}

// CreateMember adds a member. With a mobile number the member is invited: the answer is the same
// whether or not the number has an account (IC-24).
func (s *Service) CreateMember(ctx context.Context, in gen.CreateMember) (gen.Member, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.Member{}, errUnauth()
	}
	if strings.TrimSpace(in.DisplayName) == "" || in.Id == "" {
		return gen.Member{}, errInvalid("display_name", "required")
	}
	if in.MobileE164 != nil && !mobileRE.MatchString(*in.MobileE164) {
		return gen.Member{}, errInvalid("mobile_e164", "not_indian_mobile")
	}
	var out gen.Member
	err := s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		if ex, err := get[member](tx, kMember, pr.TenantID, in.Id); err != nil {
			return err
		} else if ex != nil {
			out = memberDTO(ex)
			return nil
		}
		a, err := s.actorFor(ctx, tx)
		if err != nil {
			return err
		}
		m := member{ID: in.Id, TenantID: pr.TenantID, DisplayName: strings.TrimSpace(in.DisplayName), Status: "active", Assignments: []assignment{}, CreatedAt: s.now()}
		if in.MobileE164 != nil {
			m.Status, m.Mobile = "invited", *in.MobileE164
		}
		if in.RoleAssignments != nil {
			for _, ai := range *in.RoleAssignments {
				asg, err := s.checkAssign(a, &m, ai, false)
				if err != nil {
					return err
				}
				m.Assignments = append(m.Assignments, asg)
			}
		}
		if err := put(tx, kMember, pr.TenantID, m.ID, m, keys{}); err != nil {
			return err
		}
		if in.MobileE164 != nil {
			inv := invitation{ID: string(s.NewID()), Kind: "member", TenantID: pr.TenantID, MobileKey: s.mobileKey(*in.MobileE164), Mobile: *in.MobileE164,
				Status: "pending", CreatedAt: s.now(), ExpiresAt: s.now().Add(s.Cfg.InvitationTTL), MemberID: m.ID}
			if err := put(tx, kInvitation, repository.Global, inv.ID, inv, keys{k1: inv.MobileKey, k2: pr.TenantID}); err != nil {
				return err
			}
		}
		if err := s.emit(tx, pr.TenantID, "", "identity.member.changed", m.ID, pr.Subject, map[string]any{"member_id": m.ID, "change": "created"}); err != nil {
			return err
		}
		out = memberDTO(&m)
		k, l, d := actor(ctx)
		return s.audit(tx, pr.TenantID, auditDoc{Action: "member.created", ActorKind: k, ActorLbl: l, Device: d, Outcome: "succeeded", Target: m.ID})
	})
	return out, err
}

// checkAssign applies the grant limits to one assignment of role ai.RoleID to member m (G1 to G4).
func (s *Service) checkAssign(a *actorCtx, m *member, ai gen.AssignmentInput, remove bool) (assignment, error) {
	gr, builtin, r := a.role(ai.RoleId)
	if r == nil {
		return assignment{}, errInvalid("role_id", "unknown_role")
	}
	if builtin {
		return assignment{}, apperr.New(apperr.Validation, "use_owner_role_operation", "the owner role is assigned through the owner-role operation")
	}
	var outlets []string
	if ai.OutletIds != nil {
		outlets = append(outlets, *ai.OutletIds...)
	}
	if m.ID == a.pr.Subject { // G4: nobody changes their own assignments
		return assignment{}, errGrant()
	}
	cnt := 0
	err := s.Grants.CanAssign(a.h, grantlimit.Assignment{Target: s.holdingsOf(a, m), Role: gr, OwnerRole: builtin, Scope: scopeOf(outlets), Remove: remove, OwnerCount: cnt})
	if err != nil {
		return assignment{}, errGrant()
	}
	return assignment{ID: ai.Id, RoleID: ai.RoleId, Outlets: outlets}, nil
}

// UpdateMember changes the display name or status (suspension ends the member's sessions).
func (s *Service) UpdateMember(ctx context.Context, id string, in gen.UpdateMember) (gen.Member, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.Member{}, errUnauth()
	}
	var out gen.Member
	err := s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		m, err := get[member](tx, kMember, pr.TenantID, id)
		if err != nil || m == nil {
			return notFoundOr(err)
		}
		a, err := s.actorFor(ctx, tx)
		if err != nil {
			return err
		}
		if in.DisplayName != nil {
			if strings.TrimSpace(*in.DisplayName) == "" {
				return errInvalid("display_name", "required")
			}
			if err := mapGrant(s.Grants.CanAdminister(a.h, s.holdingsOf(a, m), auth.AllOutlets())); err != nil && m.ID != pr.Subject {
				return err
			}
			m.DisplayName = strings.TrimSpace(*in.DisplayName)
		}
		if in.Status != nil && string(*in.Status) != m.Status {
			if m.ID == pr.Subject { // G4
				return errGrant()
			}
			if err := mapGrant(s.Grants.CanAdminister(a.h, s.holdingsOf(a, m), auth.AllOutlets())); err != nil {
				return err
			}
			if s.holdingsOf(a, m).Owner && *in.Status == gen.UpdateMemberStatusSuspended {
				c, err := get[ownerCount](tx, kOwnerCount, repository.Global, pr.TenantID)
				if err != nil {
					return err
				}
				if c != nil && c.N <= 1 {
					return apperr.New(apperr.Conflict, "last_owner", "the last owner cannot be suspended")
				}
				if err := s.adjustOwners(tx, pr.TenantID, -1); err != nil {
					return err
				}
			}
			m.Status = string(*in.Status)
			if m.Status == "suspended" {
				if err := s.endMemberSessions(tx, pr.TenantID, m.ID, "member_deactivated"); err != nil {
					return err
				}
			}
			if err := s.emit(tx, pr.TenantID, "", "identity.member.changed", m.ID, pr.Subject, map[string]any{"member_id": m.ID, "change": "status_changed"}); err != nil {
				return err
			}
		}
		if err := put(tx, kMember, pr.TenantID, m.ID, m, keys{k1: m.AccountID}); err != nil {
			return err
		}
		out = memberDTO(m)
		k, l, d := actor(ctx)
		return s.audit(tx, pr.TenantID, auditDoc{Action: "member.updated", ActorKind: k, ActorLbl: l, Device: d, Outcome: "succeeded", Target: m.ID, After: m.Status})
	})
	return out, err
}

// endMemberSessions revokes every strong session of a member and feeds the gateway.
func (s *Service) endMemberSessions(tx repository.Tx, tenant, memberID, reason string) error {
	ss, err := find[session](tx, kSession, repository.Global, memberID)
	if err != nil {
		return err
	}
	for i := range ss {
		if ss[i].Revoked || ss[i].TenantID != tenant {
			continue
		}
		ss[i].Revoked = true
		if err := put(tx, kSession, repository.Global, ss[i].ID, ss[i], keys{k1: ss[i].MemberID, k2: ss[i].AccountID}); err != nil {
			return err
		}
		if err := s.addRevocation(tx, tenant, "session", ss[i].ID); err != nil {
			return err
		}
		if err := s.emitSessionRevoked(tx, &ss[i], reason); err != nil {
			return err
		}
	}
	return nil
}

// CreateRoleAssignment assigns a role at a scope (G1 to G4, G7).
func (s *Service) CreateRoleAssignment(ctx context.Context, memberID string, in gen.AssignmentInput) (gen.RoleAssignment, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.RoleAssignment{}, errUnauth()
	}
	var out gen.RoleAssignment
	err := s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		m, err := get[member](tx, kMember, pr.TenantID, memberID)
		if err != nil || m == nil {
			return notFoundOr(err)
		}
		for _, ex := range m.Assignments {
			if ex.ID == in.Id {
				ra := gen.RoleAssignment{Id: ex.ID, RoleId: ex.RoleID}
				if len(ex.Outlets) > 0 {
					o := ex.Outlets
					ra.OutletIds = &o
				}
				out = ra
				return nil
			}
		}
		a, err := s.actorFor(ctx, tx)
		if err != nil {
			return err
		}
		asg, err := s.checkAssign(a, m, in, false)
		if err != nil {
			return err
		}
		m.Assignments = append(m.Assignments, asg)
		if err := put(tx, kMember, pr.TenantID, m.ID, m, keys{k1: m.AccountID}); err != nil {
			return err
		}
		if err := s.emit(tx, pr.TenantID, "", "identity.member.changed", m.ID, pr.Subject, map[string]any{"member_id": m.ID, "change": "roles_changed"}); err != nil {
			return err
		}
		ra := gen.RoleAssignment{Id: asg.ID, RoleId: asg.RoleID}
		if len(asg.Outlets) > 0 {
			o := asg.Outlets
			ra.OutletIds = &o
		}
		out = ra
		k, l, d := actor(ctx)
		return s.audit(tx, pr.TenantID, auditDoc{Action: "member.role.assigned", ActorKind: k, ActorLbl: l, Device: d, Outcome: "succeeded", Target: m.ID, After: asg.RoleID})
	})
	return out, err
}

// DeleteRoleAssignment removes an assignment (idempotent).
func (s *Service) DeleteRoleAssignment(ctx context.Context, memberID, assignmentID string) error {
	pr, ok := principal(ctx)
	if !ok {
		return errUnauth()
	}
	return s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		m, err := get[member](tx, kMember, pr.TenantID, memberID)
		if err != nil || m == nil {
			return notFoundOr(err)
		}
		idx := -1
		for i, ex := range m.Assignments {
			if ex.ID == assignmentID {
				idx = i
			}
		}
		if idx < 0 {
			return nil
		}
		a, err := s.actorFor(ctx, tx)
		if err != nil {
			return err
		}
		ex := m.Assignments[idx]
		if _, err := s.checkAssign(a, m, gen.AssignmentInput{Id: ex.ID, RoleId: ex.RoleID, OutletIds: &ex.Outlets}, true); err != nil {
			return err
		}
		m.Assignments = append(m.Assignments[:idx:idx], m.Assignments[idx+1:]...)
		if err := put(tx, kMember, pr.TenantID, m.ID, m, keys{k1: m.AccountID}); err != nil {
			return err
		}
		if err := s.emit(tx, pr.TenantID, "", "identity.member.changed", m.ID, pr.Subject, map[string]any{"member_id": m.ID, "change": "roles_changed"}); err != nil {
			return err
		}
		k, l, d := actor(ctx)
		return s.audit(tx, pr.TenantID, auditDoc{Action: "member.role.unassigned", ActorKind: k, ActorLbl: l, Device: d, Outcome: "succeeded", Target: m.ID, Before: ex.RoleID})
	})
}

// AssignOwnerRole makes a member an owner (owners only, step-up; G3).
func (s *Service) AssignOwnerRole(ctx context.Context, memberID string, in gen.OwnerRoleAssignment) (gen.Member, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.Member{}, errUnauth()
	}
	var out gen.Member
	err := s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		m, err := get[member](tx, kMember, pr.TenantID, memberID)
		if err != nil || m == nil {
			return notFoundOr(err)
		}
		a, err := s.actorFor(ctx, tx)
		if err != nil {
			return err
		}
		if a.owner == "" || m.Status != "active" || m.ID == pr.Subject {
			return errGrant()
		}
		if s.holdingsOf(a, m).Owner {
			out = memberDTO(m)
			return nil
		}
		if err := s.Grants.CanAssign(a.h, grantlimit.Assignment{Target: s.holdingsOf(a, m), Role: grantlimit.Role{ID: a.owner, Perms: []string{auth.Wildcard}}, OwnerRole: true, Scope: auth.AllOutlets()}); err != nil {
			return errGrant()
		}
		m.Assignments = append(m.Assignments, assignment{ID: in.Id, RoleID: a.owner})
		if err := put(tx, kMember, pr.TenantID, m.ID, m, keys{k1: m.AccountID}); err != nil {
			return err
		}
		if err := s.adjustOwners(tx, pr.TenantID, +1); err != nil {
			return err
		}
		if err := s.emit(tx, pr.TenantID, "", "identity.member.changed", m.ID, pr.Subject, map[string]any{"member_id": m.ID, "change": "roles_changed"}); err != nil {
			return err
		}
		out = memberDTO(m)
		k, l, d := actor(ctx)
		return s.audit(tx, pr.TenantID, auditDoc{Action: "member.owner.assigned", ActorKind: k, ActorLbl: l, Device: d, Outcome: "succeeded", Target: m.ID})
	})
	return out, err
}

// RemoveOwnerRole removes the owner role from a member; the last owner cannot be removed.
func (s *Service) RemoveOwnerRole(ctx context.Context, memberID string) error {
	pr, ok := principal(ctx)
	if !ok {
		return errUnauth()
	}
	return s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		m, err := get[member](tx, kMember, pr.TenantID, memberID)
		if err != nil || m == nil {
			return notFoundOr(err)
		}
		a, err := s.actorFor(ctx, tx)
		if err != nil {
			return err
		}
		if !s.holdingsOf(a, m).Owner {
			return nil
		}
		c, err := get[ownerCount](tx, kOwnerCount, repository.Global, pr.TenantID)
		if err != nil {
			return err
		}
		n := 0
		if c != nil {
			n = c.N
		}
		if err := s.Grants.CanAssign(a.h, grantlimit.Assignment{Target: s.holdingsOf(a, m), Role: grantlimit.Role{ID: a.owner, Perms: []string{auth.Wildcard}}, OwnerRole: true, Scope: auth.AllOutlets(), Remove: true, OwnerCount: n}); err != nil || m.ID == pr.Subject {
			if m.ID != pr.Subject && n <= 1 && a.h.Owner {
				return apperr.New(apperr.Conflict, "last_owner", "the last owner cannot be removed")
			}
			return errGrant()
		}
		kept := m.Assignments[:0:0]
		for _, as := range m.Assignments {
			if as.RoleID != a.owner {
				kept = append(kept, as)
			}
		}
		m.Assignments = kept
		if err := put(tx, kMember, pr.TenantID, m.ID, m, keys{k1: m.AccountID}); err != nil {
			return err
		}
		if err := s.adjustOwners(tx, pr.TenantID, -1); err != nil {
			return err
		}
		s.Notify.Notify(ctx, Notice{Kind: "owner_removed", TenantID: pr.TenantID, MemberID: m.ID, AccountID: m.AccountID})
		if err := s.emit(tx, pr.TenantID, "", "identity.member.changed", m.ID, pr.Subject, map[string]any{"member_id": m.ID, "change": "roles_changed"}); err != nil {
			return err
		}
		k, l, d := actor(ctx)
		return s.audit(tx, pr.TenantID, auditDoc{Action: "member.owner.removed", ActorKind: k, ActorLbl: l, Device: d, Outcome: "succeeded", Target: m.ID})
	})
}

// ---- roles ----

// ListRoles lists the organisation's roles.
func (s *Service) ListRoles(ctx context.Context, p gen.ListRolesParams) (gen.RolePage, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.RolePage{}, errUnauth()
	}
	limit := pageLimit(p.Limit, 50, 200)
	out := gen.RolePage{Items: []gen.Role{}}
	err := s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		rs, err := list[role](tx, kRole, pr.TenantID, deref(p.Cursor), limit+1)
		if err != nil {
			return err
		}
		for i := range rs {
			if i == limit {
				c := out.Items[len(out.Items)-1].Id
				out.NextCursor = &c
				break
			}
			out.Items = append(out.Items, roleDTO(&rs[i]))
		}
		return nil
	})
	return out, err
}

// GetRole returns a role.
func (s *Service) GetRole(ctx context.Context, id string) (gen.Role, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.Role{}, errUnauth()
	}
	var out gen.Role
	err := s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		r, err := get[role](tx, kRole, pr.TenantID, id)
		if err != nil || r == nil {
			return notFoundOr(err)
		}
		out = roleDTO(r)
		return nil
	})
	return out, err
}

func (s *Service) validRolePerms(perms []string) error {
	seen := map[string]bool{}
	for _, p := range perms {
		if _, ok := tenantPermission(p); (!ok && !contains(s.Cfg.ExtraPermissions, p)) || seen[p] {
			return errInvalid("permissions", "unknown_permission")
		}
		seen[p] = true
	}
	return nil
}

// CreateRole creates a role (G1, G2).
func (s *Service) CreateRole(ctx context.Context, in gen.RoleInput) (gen.Role, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.Role{}, errUnauth()
	}
	if strings.TrimSpace(in.Name) == "" {
		return gen.Role{}, errInvalid("name", "required")
	}
	if err := s.validRolePerms(in.Permissions); err != nil {
		return gen.Role{}, err
	}
	var out gen.Role
	err := s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		id := string(s.NewID())
		if in.Id != nil {
			id = *in.Id
		}
		if ex, err := get[role](tx, kRole, pr.TenantID, id); err != nil {
			return err
		} else if ex != nil {
			out = roleDTO(ex)
			return nil
		}
		a, err := s.actorFor(ctx, tx)
		if err != nil {
			return err
		}
		if err := s.Grants.CanWriteRole(a.h, nil, grantlimit.Role{ID: id, Perms: in.Permissions}); err != nil {
			return errGrant()
		}
		now := s.now()
		r := role{ID: id, Name: strings.TrimSpace(in.Name), Perms: append([]string{}, in.Permissions...), CreatedAt: now, UpdatedAt: now}
		if err := put(tx, kRole, pr.TenantID, id, r, keys{}); err != nil {
			return err
		}
		out = roleDTO(&r)
		k, l, d := actor(ctx)
		return s.audit(tx, pr.TenantID, auditDoc{Action: "role.created", ActorKind: k, ActorLbl: l, Device: d, Outcome: "succeeded", Target: id})
	})
	return out, err
}

// UpdateRole edits a role (G1, G2). The built-in owner role cannot be edited.
func (s *Service) UpdateRole(ctx context.Context, id string, in gen.RoleInput) (gen.Role, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.Role{}, errUnauth()
	}
	if strings.TrimSpace(in.Name) == "" {
		return gen.Role{}, errInvalid("name", "required")
	}
	if err := s.validRolePerms(in.Permissions); err != nil {
		return gen.Role{}, err
	}
	var out gen.Role
	err := s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		r, err := get[role](tx, kRole, pr.TenantID, id)
		if err != nil || r == nil {
			return notFoundOr(err)
		}
		if r.BuiltIn {
			return errInvalid("id", "built_in_role")
		}
		a, err := s.actorFor(ctx, tx)
		if err != nil {
			return err
		}
		before := grantlimit.Role{ID: r.ID, Perms: r.Perms}
		if err := s.Grants.CanWriteRole(a.h, &before, grantlimit.Role{ID: r.ID, Perms: in.Permissions}); err != nil {
			return errGrant()
		}
		r.Name, r.Perms, r.UpdatedAt = strings.TrimSpace(in.Name), append([]string{}, in.Permissions...), s.now()
		if err := put(tx, kRole, pr.TenantID, id, r, keys{}); err != nil {
			return err
		}
		out = roleDTO(r)
		k, l, d := actor(ctx)
		return s.audit(tx, pr.TenantID, auditDoc{Action: "role.updated", ActorKind: k, ActorLbl: l, Device: d, Outcome: "succeeded", Target: id, Before: strings.Join(before.Perms, ","), After: strings.Join(r.Perms, ",")})
	})
	return out, err
}

// DeleteRole deletes an unused role (idempotent). The built-in owner role cannot be deleted.
func (s *Service) DeleteRole(ctx context.Context, id string) error {
	pr, ok := principal(ctx)
	if !ok {
		return errUnauth()
	}
	return s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		r, err := get[role](tx, kRole, pr.TenantID, id)
		if err != nil || r == nil {
			return err
		}
		if r.BuiltIn {
			return apperr.New(apperr.Conflict, "role.built_in", "the built-in owner role cannot be deleted")
		}
		a, err := s.actorFor(ctx, tx)
		if err != nil {
			return err
		}
		before := grantlimit.Role{ID: r.ID, Perms: r.Perms}
		if err := s.Grants.CanWriteRole(a.h, &before, grantlimit.Role{ID: r.ID}); err != nil {
			return errGrant()
		}
		ms, err := list[member](tx, kMember, pr.TenantID, "", 0)
		if err != nil {
			return err
		}
		for _, m := range ms {
			for _, as := range m.Assignments {
				if as.RoleID == id {
					return apperr.New(apperr.Conflict, "role.in_use", "the role is still assigned")
				}
			}
		}
		if err := tx.Delete(kRole, pr.TenantID, id); err != nil {
			return err
		}
		k, l, d := actor(ctx)
		return s.audit(tx, pr.TenantID, auditDoc{Action: "role.deleted", ActorKind: k, ActorLbl: l, Device: d, Outcome: "succeeded", Target: id})
	})
}

// ListPermissions returns the tenant-realm permission catalogue with its flags.
func (s *Service) ListPermissions() gen.PermissionList {
	out := gen.PermissionList{CatalogueVersion: CatalogueVersion, Items: []gen.Permission{}}
	for _, e := range catalogueEntries {
		if e.Realm != "tenant" {
			continue
		}
		out.Items = append(out.Items, gen.Permission{Key: e.Key, Service: e.Service, DescriptionKey: e.DescriptionKey, Sensitive: e.Sensitive,
			StrongOnly: e.StrongOnly, OwnerGrant: e.OwnerGrant, SupportViewable: e.SupportViewable, SupportActable: e.SupportActable})
	}
	return out
}
