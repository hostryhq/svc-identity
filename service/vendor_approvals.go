package service

import (
	"context"
	"strings"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/repository"
)

// vendorApproval is the one two-person record behind sign-in codes, owner recovery and device
// revokes over quota (ADR-0005 A2.3). No single-person override exists.
type vendorApproval struct {
	ID           string    `json:"id"`
	Kind         string    `json:"kind"`
	Requester    string    `json:"requester"`
	Approver     string    `json:"approver,omitempty"`
	Org          string    `json:"org"`
	Subject      string    `json:"subject,omitempty"`
	Mobile       string    `json:"mobile,omitempty"`
	NewMobile    string    `json:"new_mobile,omitempty"`
	Reason       string    `json:"reason"`
	Ticket       string    `json:"ticket"`
	Verified     string    `json:"verification"`
	State        string    `json:"state"` // pending, approved, rejected, cancelled, completed, expired
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	CompletesAt  time.Time `json:"completes_at,omitempty"`
	CodeMAC      string    `json:"code_mac,omitempty"`
	FirstHalf    []byte    `json:"first_half,omitempty"` // sealed; shown once to the requester
	Claimed      bool      `json:"claimed,omitempty"`
	Attempts     int       `json:"attempts,omitempty"`
	CodeUntil    time.Time `json:"code_until,omitempty"`
	Used         bool      `json:"used,omitempty"`
	TenantCancel bool      `json:"tenant_cancelled,omitempty"`
}

func (a *vendorApproval) effective(now time.Time) string {
	if (a.State == "pending") && !now.Before(a.ExpiresAt) {
		return "expired"
	}
	return a.State
}

func approvalDTOV(a *vendorApproval, now time.Time) gen.VendorApproval {
	g := gen.VendorApproval{Id: a.ID, Kind: gen.ApprovalKind(a.Kind), OrganisationId: a.Org, RequestedBy: a.Requester, State: gen.VendorApprovalState(a.effective(now)),
		TicketReference: a.Ticket, VerificationMethod: gen.RequesterVerification(a.Verified), CreatedAt: a.CreatedAt, ExpiresAt: a.ExpiresAt}
	if a.Approver != "" {
		x := a.Approver
		g.ApprovedBy = &x
	}
	if a.Subject != "" {
		x := a.Subject
		g.SubjectId = &x
	}
	if a.Mobile != "" {
		x := maskMobile(a.Mobile)
		g.MobileMasked = &x
	}
	if !a.CompletesAt.IsZero() {
		x := a.CompletesAt
		g.CompletesAt = &x
	}
	return g
}

func kindPerms(kind string) (create, approve string) {
	switch kind {
	case "sign_in_code":
		return "admin.signin_code.create", "admin.signin_code.approve"
	case "owner_recovery":
		return "admin.recovery.create", "admin.recovery.approve"
	case "device_revoke_over_quota":
		return "admin.device.revoke", "admin.device.revoke"
	}
	return "", ""
}

func (s *Service) holdsVendorPerm(ctx context.Context, perm string) bool {
	sc, err := auth.ScopeFor(ctx, perm)
	return err == nil && !sc.Empty()
}

func (s *Service) approvalDenied() error {
	return apperr.New(apperr.Forbidden, "auth.permission_denied", "permission denied")
}

func approvalConflict(code string) error {
	return apperr.New(apperr.Conflict, code, "the approval cannot be changed this way")
}

// eligibleApprovers counts active vendor users other than the requester who hold the kind's
// approve permission and whose account is older than the minimum age (A2.3).
func (s *Service) eligibleApprovers(tx repository.Tx, kind, requester string) (int, error) {
	_, perm := kindPerms(kind)
	us, err := list[vendorUser](tx, kVendorUser, repository.Global, "", 0)
	n := 0
	for _, u := range us {
		if u.ID == requester || u.Status != "active" || s.now().Sub(u.CredAt) < s.Cfg.MinApproverAge {
			continue
		}
		for _, p := range VendorPermissions(u.Role) {
			if p == perm {
				n++
				break
			}
		}
	}
	return n, err
}

// CreateVendorApproval files a two-person approval.
func (s *Service) CreateVendorApproval(ctx context.Context, in gen.CreateVendorApproval) (gen.VendorApproval, error) {
	pr, err := s.vendorPrincipal(ctx)
	if err != nil {
		return gen.VendorApproval{}, err
	}
	kind := string(in.Kind)
	create, _ := kindPerms(kind)
	if create == "" {
		return gen.VendorApproval{}, errInvalid("kind", "invalid")
	}
	if !s.holdsVendorPerm(ctx, create) {
		return gen.VendorApproval{}, s.approvalDenied()
	}
	if kind == "sign_in_code" && !s.Cfg.SignInCodeEnabled || kind == "owner_recovery" && !s.Cfg.RecoveryEnabled {
		return gen.VendorApproval{}, apperr.New(apperr.Forbidden, "vendor_assist_disabled", "this vendor-assisted action is switched off in this environment")
	}
	if len(strings.TrimSpace(in.Reason)) < 10 || strings.TrimSpace(in.TicketReference) == "" || !in.VerificationMethod.Valid() {
		return gen.VendorApproval{}, errInvalid("reason", "invalid")
	}
	ctx, err = s.vendorOrg(ctx, create, in.OrganisationId)
	if err != nil {
		return gen.VendorApproval{}, err
	}
	var out gen.VendorApproval
	err = s.Store.Tx(ctx, in.OrganisationId, func(tx repository.Tx) error {
		now := s.now()
		a := vendorApproval{ID: string(s.NewID()), Kind: kind, Requester: pr.VendorUser(), Org: in.OrganisationId, Reason: strings.TrimSpace(in.Reason),
			Ticket: strings.TrimSpace(in.TicketReference), Verified: string(in.VerificationMethod), State: "pending", CreatedAt: now, ExpiresAt: now.Add(s.Cfg.LongApprovalTTL)}
		if in.SubjectId != nil {
			a.Subject = *in.SubjectId
		}
		switch kind {
		case "sign_in_code":
			a.ExpiresAt = now.Add(s.Cfg.SignInApprovalTTL)
			if in.MobileE164 == nil || !mobileRE.MatchString(*in.MobileE164) {
				return errInvalid("mobile_e164", "required")
			}
			a.Mobile = *in.MobileE164
			acct, err := s.accountByMobile(tx, a.Mobile)
			if err != nil {
				return err
			}
			invs, err := s.pendingInvitations(tx, s.mobileKey(a.Mobile), now)
			if err != nil {
				return err
			}
			if (acct == nil && len(invs) == 0) || (acct != nil && acct.Verified) {
				return errInvalid("mobile_e164", "not_eligible")
			}
		case "owner_recovery":
			if in.MobileE164 == nil || in.NewMobileE164 == nil || !mobileRE.MatchString(*in.MobileE164) || !mobileRE.MatchString(*in.NewMobileE164) {
				return errInvalid("new_mobile_e164", "required")
			}
			a.Mobile, a.NewMobile = *in.MobileE164, *in.NewMobileE164
			if other, err := s.accountByMobile(tx, a.NewMobile); err != nil {
				return err
			} else if other != nil {
				return errInvalid("new_mobile_e164", "in_use")
			}
			acct, err := s.accountByMobile(tx, a.Mobile)
			if err != nil {
				return err
			}
			if acct == nil || !s.accountIsOwner(tx, acct.ID, in.OrganisationId) {
				return errNotFound()
			}
			if acct.RecoveryNeedsAdmin && !s.vendorIsRole(tx, pr.VendorUser(), "platform_admin") {
				return approvalConflict("platform_admin_required")
			}
		case "device_revoke_over_quota":
			if d, err := get[device](tx, kDevice, in.OrganisationId, a.Subject); err != nil || d == nil {
				return notFoundOr(err)
			}
		}
		n, err := s.eligibleApprovers(tx, kind, pr.VendorUser())
		if err != nil {
			return err
		}
		if n == 0 {
			return approvalConflict("second_approver_unavailable")
		}
		if err := put(tx, kVendorAppr, repository.Global, a.ID, a, keys{k1: a.Org, k2: a.Requester}); err != nil {
			return err
		}
		out = approvalDTOV(&a, now)
		return s.vendorAudit(ctx, tx, vaudit{Org: a.Org, Action: "vendor.approval.requested", Target: a.ID, Ticket: a.Ticket})
	})
	return out, err
}

func (s *Service) vendorIsRole(tx repository.Tx, id, role string) bool {
	u, _ := get[vendorUser](tx, kVendorUser, repository.Global, id)
	return u != nil && u.Role == role
}

func (s *Service) accountIsOwner(tx repository.Tx, accountID, org string) bool {
	ms, _ := find[membership](tx, kMembership, repository.Global, accountID)
	for _, m := range ms {
		if m.TenantID != org {
			continue
		}
		if mem, _ := get[member](tx, kMember, org, m.MemberID); mem != nil {
			_, ownerID, _ := s.loadRoles(tx, org)
			for _, a := range mem.Assignments {
				if a.RoleID == ownerID && ownerID != "" {
					return true
				}
			}
		}
	}
	return false
}

// ListVendorApprovals lists approvals the caller requested or may approve.
func (s *Service) ListVendorApprovals(ctx context.Context, p gen.ListVendorApprovalsParams) (gen.VendorApprovalPage, error) {
	pr, err := s.vendorPrincipal(ctx)
	if err != nil {
		return gen.VendorApprovalPage{}, err
	}
	limit := pageLimit(p.Limit, 50, 100)
	out := gen.VendorApprovalPage{Items: []gen.VendorApproval{}}
	err = s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		as, err := list[vendorApproval](tx, kVendorAppr, repository.Global, deref(p.Cursor), 0)
		if err != nil {
			return err
		}
		for i := range as {
			a := &as[i]
			_, ap := kindPerms(a.Kind)
			may := a.Requester != pr.VendorUser() && s.holdsVendorPerm(ctx, ap)
			if a.Requester != pr.VendorUser() && !may || (p.State != nil && a.effective(s.now()) != string(*p.State)) {
				continue
			}
			if len(out.Items) == limit {
				c := out.Items[len(out.Items)-1].Id
				out.NextCursor = &c
				break
			}
			out.Items = append(out.Items, approvalDTOV(a, s.now()))
		}
		return s.vendorAudit(ctx, tx, vaudit{Action: "vendor.approval.listed"})
	})
	return out, err
}

// ApproveVendorApproval approves with a fresh TOTP. The approver differs from the requester, holds
// the kind's approve permission and has an account older than 7 days.
func (s *Service) ApproveVendorApproval(ctx context.Context, id string, in gen.ApproveVendorApproval) (gen.ApprovalDecision, error) {
	pr, err := s.vendorPrincipal(ctx)
	if err != nil {
		return gen.ApprovalDecision{}, err
	}
	var out gen.ApprovalDecision
	var refuse error
	err = s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		a, err := get[vendorApproval](tx, kVendorAppr, repository.Global, id)
		if err != nil || a == nil {
			return notFoundOr(err)
		}
		_, ap := kindPerms(a.Kind)
		if !s.holdsVendorPerm(ctx, ap) {
			return s.approvalDenied()
		}
		now := s.now()
		u, err := get[vendorUser](tx, kVendorUser, repository.Global, pr.VendorUser())
		if err != nil || u == nil {
			return notFoundOr(err)
		}
		switch {
		case a.effective(now) != "pending":
			return approvalConflict("approval_not_pending")
		case a.Requester == u.ID:
			return approvalConflict("approver_is_requester")
		case now.Sub(u.CredAt) < s.Cfg.MinApproverAge:
			return approvalConflict("approver_too_new")
		}
		secret, err := crypto.Open(s.Cfg.TOTPKey, u.TOTPEnc)
		step, ok := int64(0), false
		if err == nil {
			step, ok = crypto.CheckTOTP(secret, in.TotpCode, now)
		}
		if !ok || step <= u.TOTPStep {
			refuse = errInvalid("totp_code", "invalid")
			return nil
		}
		u.TOTPStep = step
		if err := s.putVendorUser(tx, u); err != nil {
			return err
		}
		a.State, a.Approver = "approved", u.ID
		switch a.Kind {
		case "sign_in_code":
			code := s.Rand.Alphabet(8, crypto.CodeAlphabet)
			a.CodeMAC = crypto.MAC(s.Cfg.MACKey, "vcode", a.Mobile, code)
			if a.FirstHalf, err = crypto.Seal(s.Rand, s.Cfg.TOTPKey, []byte(code[:4])); err != nil {
				return err
			}
			a.CodeUntil = now.Add(s.Cfg.SignInCodeTTL)
			out.CodeHalf = &gen.CodeHalf{Half: code[4:], Position: gen.Second}
		case "owner_recovery":
			a.CompletesAt = now.Add(s.Cfg.RecoveryDelay)
			s.Notify.Notify(ctx, Notice{Kind: "recovery_started", TenantID: a.Org, Detail: a.ID})
		}
		if err := put(tx, kVendorAppr, repository.Global, a.ID, a, keys{k1: a.Org, k2: a.Requester}); err != nil {
			return err
		}
		out.Approval = approvalDTOV(a, now)
		return s.vendorAudit(ctx, tx, vaudit{Org: a.Org, Action: "vendor.approval.approved", Target: a.ID, Ticket: a.Ticket})
	})
	if err != nil {
		return out, err
	}
	if refuse == nil && out.Approval.Kind == gen.ApprovalKindOwnerRecovery || out.Approval.Kind == gen.ApprovalKindSignInCode {
		if e := s.Store.Tx(ctx, out.Approval.OrganisationId, func(tx repository.Tx) error {
			return s.audit(tx, out.Approval.OrganisationId, auditDoc{Action: "vendor.approval." + string(out.Approval.Kind) + ".approved", ActorKind: "vendor", ActorLbl: "Hostry support",
				Outcome: "succeeded", Target: out.Approval.Id, Ticket: out.Approval.TicketReference, Show: true, Summary: "requested by " + out.Approval.RequestedBy + ", approved by " + deref(out.Approval.ApprovedBy)})
		}); e != nil {
			return out, e
		}
	}
	return out, refuse
}

// ClaimCodeHalf shows the requester characters 1 to 4, once.
func (s *Service) ClaimCodeHalf(ctx context.Context, id string) (gen.CodeHalf, error) {
	pr, err := s.vendorPrincipal(ctx)
	if err != nil {
		return gen.CodeHalf{}, err
	}
	var out gen.CodeHalf
	err = s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		a, err := get[vendorApproval](tx, kVendorAppr, repository.Global, id)
		if err != nil || a == nil || a.Requester != pr.VendorUser() {
			return notFoundOr(err)
		}
		if a.Kind != "sign_in_code" || a.State != "approved" || a.Claimed || !s.now().Before(a.CodeUntil) {
			return approvalConflict("approval_not_pending")
		}
		first, err := crypto.Open(s.Cfg.TOTPKey, a.FirstHalf)
		if err != nil {
			return err
		}
		a.Claimed, a.FirstHalf = true, nil
		if err := put(tx, kVendorAppr, repository.Global, a.ID, a, keys{k1: a.Org, k2: a.Requester}); err != nil {
			return err
		}
		out = gen.CodeHalf{Half: string(first), Position: gen.First}
		return s.vendorAudit(ctx, tx, vaudit{Org: a.Org, Action: "vendor.approval.half_claimed", Target: a.ID})
	})
	return out, err
}

// CancelVendorApproval cancels a pending approval, or an owner recovery during its delay; either
// vendor user may.
func (s *Service) CancelVendorApproval(ctx context.Context, id string, in gen.RejectVendorApproval) (gen.VendorApproval, error) {
	pr, err := s.vendorPrincipal(ctx)
	if err != nil {
		return gen.VendorApproval{}, err
	}
	var out gen.VendorApproval
	err = s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		a, err := get[vendorApproval](tx, kVendorAppr, repository.Global, id)
		if err != nil || a == nil {
			return notFoundOr(err)
		}
		_, ap := kindPerms(a.Kind)
		if a.Requester != pr.VendorUser() && a.Approver != pr.VendorUser() && !s.holdsVendorPerm(ctx, ap) {
			return s.approvalDenied()
		}
		eff := a.effective(s.now())
		if !(eff == "pending" || (a.Kind == "owner_recovery" && eff == "approved" && s.now().Before(a.CompletesAt))) {
			return approvalConflict("approval_not_pending")
		}
		a.State = "cancelled"
		if err := put(tx, kVendorAppr, repository.Global, a.ID, a, keys{k1: a.Org, k2: a.Requester}); err != nil {
			return err
		}
		out = approvalDTOV(a, s.now())
		return s.vendorAudit(ctx, tx, vaudit{Org: a.Org, Action: "vendor.approval.cancelled", Target: a.ID})
	})
	return out, err
}

// consumeRevokeApproval checks and uses an approved over-quota revoke approval for this device.
func (s *Service) consumeRevokeApproval(tx repository.Tx, approvalID *string, org, deviceID, requester string) (bool, error) {
	if approvalID == nil {
		return false, nil
	}
	a, err := get[vendorApproval](tx, kVendorAppr, repository.Global, *approvalID)
	if err != nil || a == nil {
		return false, err
	}
	if a.Kind != "device_revoke_over_quota" || a.State != "approved" || a.Used || a.Org != org || a.Subject != deviceID || a.Requester != requester || a.Approver == requester {
		return false, nil
	}
	a.Used, a.State = true, "completed"
	return true, put(tx, kVendorAppr, repository.Global, a.ID, a, keys{k1: a.Org, k2: a.Requester})
}

// createSessionVendorCode signs an invited or known person in with a vendor-assisted code: eight
// characters made of the two halves, valid 10 minutes, single use, 5 attempts, bound to the named
// number and to the login transaction on this device (A2.3). The session is an ordinary strong
// session with amr vendor_code; go-auth never accepts that amr for step-up.
func (s *Service) createSessionVendorCode(ctx context.Context, in gen.CreateSession) (gen.Session, error) {
	now := s.now()
	var refuse error
	var acct *account
	var ch *challenge
	var invs []invitation
	var approval *vendorApproval
	err := s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		var err error
		ch, err = get[challenge](tx, kChallenge, repository.Global, in.ChallengeId)
		if err != nil {
			return err
		}
		if ch == nil || ch.Used || !now.Before(ch.ExpiresAt) || ch.Device != in.DeviceId || !s.Cfg.SignInCodeEnabled {
			refuse = errUnauth()
			return nil
		}
		cl, verr := s.Assertions.Verify(in.DeviceAssertion, ch.Key, now)
		if verr != nil || (!cl.Trusted && (cl.Did != in.DeviceId || cl.Cid != ch.ID)) {
			refuse = errUnauth()
			return nil
		}
		if ok, err := s.useJTI(tx, cl.Jti, now); err != nil || !ok {
			refuse = errUnauth()
			return err
		}
		as, err := list[vendorApproval](tx, kVendorAppr, repository.Global, "", 0)
		if err != nil {
			return err
		}
		for i := range as {
			if as[i].Kind == "sign_in_code" && as[i].State == "approved" && !as[i].Used && now.Before(as[i].CodeUntil) && s.mobileKey(as[i].Mobile) == ch.MobileKey {
				approval = &as[i]
			}
		}
		if approval == nil || approval.Attempts >= 5 {
			refuse = errUnauth()
			return nil
		}
		if !crypto.Equal(approval.CodeMAC, crypto.MAC(s.Cfg.MACKey, "vcode", approval.Mobile, strings.ToUpper(in.Code))) {
			approval.Attempts++
			refuse = errUnauth()
			return put(tx, kVendorAppr, repository.Global, approval.ID, approval, keys{k1: approval.Org, k2: approval.Requester})
		}
		approval.Used, approval.State = true, "completed"
		if err := put(tx, kVendorAppr, repository.Global, approval.ID, approval, keys{k1: approval.Org, k2: approval.Requester}); err != nil {
			return err
		}
		ch.Used = true
		if err := put(tx, kChallenge, repository.Global, ch.ID, ch, keys{}); err != nil {
			return err
		}
		if as, err := find[account](tx, kAccount, repository.Global, ch.MobileKey); err != nil {
			return err
		} else if len(as) > 0 {
			acct = &as[0]
		}
		invs, err = s.pendingInvitations(tx, ch.MobileKey, now)
		if err != nil {
			return err
		}
		if acct == nil {
			mobile := approval.Mobile
			acct = &account{ID: string(s.NewID()), Mobile: mobile, CreatedAt: now}
		}
		acct.NoStepUpUntil = now.Add(24 * time.Hour)
		if err := put(tx, kAccount, repository.Global, acct.ID, acct, keys{k1: ch.MobileKey, unique: true}); err != nil {
			return err
		}
		for i := range invs {
			invs[i].Status, invs[i].AcceptedAt, invs[i].AccountID = "accepted", now, acct.ID
			if err := put(tx, kInvitation, repository.Global, invs[i].ID, invs[i], keys{k1: invs[i].MobileKey, k2: invs[i].TenantID}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return gen.Session{}, err
	}
	if refuse != nil {
		return gen.Session{}, refuse
	}
	sess, err := s.startStrongSession(ctx, acct, invs, ch.Device, ch.Key, string(gen.AuthMethodVendorCode))
	if err != nil {
		return sess, err
	}
	org := approval.Org
	_ = s.Store.Tx(ctx, org, func(tx repository.Tx) error {
		return s.audit(tx, org, auditDoc{Action: "signin_code.used", ActorKind: "vendor", ActorLbl: "Hostry support", Outcome: "succeeded", Show: true,
			Summary: "requested by " + approval.Requester + ", approved by " + approval.Approver})
	})
	s.Notify.Notify(ctx, Notice{Kind: "vendor_code_signin", AccountID: acct.ID})
	return sess, nil
}

// CancelOwnerRecovery cancels a pending owner recovery from the tenant side: any binding of the
// account that is not under caution, or another owner of the organisation (A2.3). A new request
// for the account then needs a platform_admin approver.
func (s *Service) CancelOwnerRecovery(ctx context.Context, id string, in gen.RecoveryCancellation) (gen.OwnerRecovery, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.OwnerRecovery{}, errUnauth()
	}
	var out gen.OwnerRecovery
	err := s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		a, err := get[vendorApproval](tx, kVendorAppr, repository.Global, id)
		if err != nil || a == nil || a.Kind != "owner_recovery" || a.Org != pr.TenantID {
			return notFoundOr(err)
		}
		sess, b, err := s.callerSession(tx, pr)
		if err != nil || sess == nil {
			return notFoundOr(err)
		}
		acct, err := s.accountByMobile(tx, a.Mobile)
		if err != nil || acct == nil {
			return notFoundOr(err)
		}
		actor, err := s.actorFor(ctx, tx)
		if err != nil {
			return err
		}
		sameAccount := sess.AccountID == acct.ID
		if s.underCaution(b) || (!sameAccount && !actor.h.Owner) || pr.Type != auth.TypeUser {
			return apperr.New(apperr.Forbidden, "auth.permission_denied", "permission denied")
		}
		if a.State != "approved" || !s.now().Before(a.CompletesAt) {
			return approvalConflict("approval_not_pending")
		}
		a.State, a.TenantCancel = "cancelled", true
		acct.RecoveryNeedsAdmin = true
		if err := put(tx, kAccount, repository.Global, acct.ID, acct, keys{k1: s.mobileKey(acct.Mobile), unique: true}); err != nil {
			return err
		}
		if err := put(tx, kVendorAppr, repository.Global, a.ID, a, keys{k1: a.Org, k2: a.Requester}); err != nil {
			return err
		}
		out = gen.OwnerRecovery{Id: a.ID, State: gen.OwnerRecoveryStateCancelled}
		return s.audit(tx, pr.TenantID, auditDoc{Action: "owner_recovery.cancelled", ActorKind: "member", ActorLbl: pr.Subject, Outcome: "succeeded", Target: a.ID})
	})
	return out, err
}

// CompleteDueRecoveries completes approved owner recoveries whose 24-hour delay has passed on
// identity's clock: the account's login number changes, every refresh token is revoked and every
// binding cleared, so the first sign-in on the new number is under caution. It never issues a
// session. Called on a timer by the service and directly by tests.
func (s *Service) CompleteDueRecoveries(ctx context.Context) (int, error) {
	var due []vendorApproval
	err := s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		as, err := list[vendorApproval](tx, kVendorAppr, repository.Global, "", 0)
		for _, a := range as {
			if a.Kind == "owner_recovery" && a.State == "approved" && !s.now().Before(a.CompletesAt) {
				due = append(due, a)
			}
		}
		return err
	})
	if err != nil {
		return 0, err
	}
	for _, a := range due {
		a := a
		err := s.Store.Tx(ctx, a.Org, func(tx repository.Tx) error {
			acct, err := s.accountByMobile(tx, a.Mobile)
			if err != nil || acct == nil {
				return err
			}
			if err := tx.Delete(kAccount, repository.Global, acct.ID); err != nil {
				return err
			}
			acct.Mobile = a.NewMobile
			if err := put(tx, kAccount, repository.Global, acct.ID, acct, keys{k1: s.mobileKey(a.NewMobile), unique: true}); err != nil {
				return err
			}
			bs, err := find[binding](tx, kBinding, repository.Global, acct.ID)
			if err != nil {
				return err
			}
			for i := range bs {
				bs[i].State = "revoked"
				if err := put(tx, kBinding, repository.Global, bs[i].ID, bs[i], keys{k1: acct.ID, k2: bs[i].Device}); err != nil {
					return err
				}
			}
			ss, err := findK2[session](tx, kSession, repository.Global, acct.ID)
			if err != nil {
				return err
			}
			for i := range ss {
				if !ss[i].Revoked {
					ss[i].Revoked = true
					if err := put(tx, kSession, repository.Global, ss[i].ID, ss[i], keys{k1: ss[i].MemberID, k2: ss[i].AccountID}); err != nil {
						return err
					}
					if err := s.addRevocation(tx, ss[i].TenantID, "session", ss[i].ID); err != nil {
						return err
					}
				}
			}
			a.State = "completed"
			if err := put(tx, kVendorAppr, repository.Global, a.ID, a, keys{k1: a.Org, k2: a.Requester}); err != nil {
				return err
			}
			return s.audit(tx, a.Org, auditDoc{Action: "owner_recovery.completed", ActorKind: "system", ActorLbl: "identity", Outcome: "succeeded", Target: a.ID, Show: true})
		})
		if err != nil {
			return 0, err
		}
	}
	return len(due), nil
}
