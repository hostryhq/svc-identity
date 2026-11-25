package service

import (
	"context"
	"time"

	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/repository"
)

// invitation is a pending invitation found by mobile number: the first owner of an organisation
// (created by Hostry staff through the vendor API) or a member added by phone by an organisation.
type invitation struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`      // owner, member
	TenantID   string    `json:"tenant_id"` // the organisation
	MobileKey  string    `json:"mobile_key"`
	Mobile     string    `json:"mobile"`
	OwnerName  string    `json:"owner_name,omitempty"`
	Status     string    `json:"status"` // pending, accepted, cancelled
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	AcceptedAt time.Time `json:"accepted_at,omitempty"`
	MemberID   string    `json:"member_id"` // pre-allocated so acceptance is idempotent
	AccountID  string    `json:"account_id,omitempty"`
}

func (i *invitation) effective(now time.Time) string {
	if i.Status == "pending" && !now.Before(i.ExpiresAt) {
		return "expired"
	}
	return i.Status
}

func (s *Service) pendingInvitations(tx repository.Tx, mkey string, now time.Time) ([]invitation, error) {
	is, err := find[invitation](tx, kInvitation, repository.Global, mkey)
	if err != nil {
		return nil, err
	}
	var out []invitation
	for i := range is {
		if is[i].effective(now) == "pending" {
			out = append(out, is[i])
		}
	}
	return out, nil
}

// CreateSession exchanges a verified OTP for a session (ADR-0005 section 3). The code is bound to
// the challenge and to the device key that started it; failures advance the attempt counters.
func (s *Service) CreateSession(ctx context.Context, in gen.CreateSession) (gen.Session, error) {
	if in.GrantType == gen.CreateSessionGrantTypeVendorCode {
		return s.createSessionVendorCode(ctx, in)
	}
	now := s.now()
	var refuse error
	var acct *account
	var invs []invitation
	var ch *challenge
	err := s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		var err error
		ch, err = get[challenge](tx, kChallenge, repository.Global, in.ChallengeId)
		if err != nil {
			return err
		}
		if ch == nil {
			refuse = errUnauth()
			return nil
		}
		blocked, err := s.otpBlocked(tx, ch.MobileKey, now)
		if err != nil {
			return err
		}
		fail := func() error {
			ch.Attempts++
			if err := put(tx, kChallenge, repository.Global, ch.ID, ch, keys{}); err != nil {
				return err
			}
			refuse = errUnauth()
			return s.failOTP(tx, ch.MobileKey, now)
		}
		if blocked || ch.Used || !now.Before(ch.ExpiresAt) || ch.Attempts >= s.Cfg.OTPAttempts {
			refuse = errUnauth()
			return nil
		}
		if ch.Device != in.DeviceId {
			return fail()
		}
		cl, verr := s.Assertions.Verify(in.DeviceAssertion, ch.Key, now)
		if verr != nil || (!cl.Trusted && (cl.Did != in.DeviceId || cl.Cid != ch.ID)) {
			return fail()
		}
		if ok, err := s.useJTI(tx, cl.Jti, now); err != nil {
			return err
		} else if !ok {
			return fail()
		}
		if !ch.Known || !crypto.Equal(ch.CodeMAC, crypto.MAC(s.Cfg.MACKey, "otp", ch.ID, in.Code)) {
			return fail()
		}
		ch.Used = true
		if err := put(tx, kChallenge, repository.Global, ch.ID, ch, keys{}); err != nil {
			return err
		}
		mobile := "" // recovered from the account or the invitation, never from the request
		if as, err := find[account](tx, kAccount, repository.Global, ch.MobileKey); err != nil {
			return err
		} else if len(as) > 0 {
			acct = &as[0]
			mobile = acct.Mobile
		}
		invs, err = s.pendingInvitations(tx, ch.MobileKey, now)
		if err != nil {
			return err
		}
		if len(invs) > 0 {
			mobile = invs[0].Mobile
		}
		if acct == nil {
			acct = &account{ID: string(s.NewID()), Mobile: mobile, CreatedAt: now}
			if err := put(tx, kAccount, repository.Global, acct.ID, acct, keys{k1: ch.MobileKey, unique: true}); err != nil {
				return err
			}
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
	return s.startStrongSession(ctx, acct, invs, ch.Device, ch.Key, string(gen.AuthMethodOtp))
}

// startStrongSession picks the membership to sign in to, creates the account-device binding and
// issues the session. Accepted invitations create their members first (owner or invited member).
func (s *Service) startStrongSession(ctx context.Context, acct *account, invs []invitation, deviceID string, key crypto.JWK, amr string) (gen.Session, error) {
	var memberships []membership
	var chosen *membership
	for i := range invs {
		inv := invs[i]
		if err := s.Store.Tx(ctx, inv.TenantID, func(tx repository.Tx) error { return s.acceptInvitation(tx, &inv, acct) }); err != nil {
			return gen.Session{}, err
		}
		mm := membership{MemberID: inv.MemberID, TenantID: inv.TenantID, AccountID: acct.ID}
		memberships = append(memberships, mm)
		if chosen == nil {
			chosen = &memberships[len(memberships)-1]
		}
	}
	err := s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		existing, err := find[membership](tx, kMembership, repository.Global, acct.ID)
		if err != nil {
			return err
		}
		memberships = append(memberships, existing...)
		return nil
	})
	if err != nil {
		return gen.Session{}, err
	}
	if chosen == nil && len(memberships) > 0 {
		chosen = &memberships[0]
	}
	if chosen == nil {
		return gen.Session{}, errUnauth()
	}
	var out gen.Session
	err = s.Store.Tx(ctx, chosen.TenantID, func(tx repository.Tx) error {
		m, err := get[member](tx, kMember, chosen.TenantID, chosen.MemberID)
		if err != nil {
			return err
		}
		if m == nil || m.Status != "active" {
			return errUnauth()
		}
		bind, err := s.ensureBinding(ctx, tx, acct, deviceID, key)
		if err != nil {
			return err
		}
		out, err = s.issueStrong(tx, m, acct.ID, deviceID, bind, amr, false)
		return err
	})
	if err != nil {
		return gen.Session{}, err
	}
	out.InvitationAccepted = len(invs) > 0
	seen := map[string]bool{}
	for _, mm := range memberships {
		if !seen[mm.MemberID] {
			seen[mm.MemberID] = true
			out.Memberships = append(out.Memberships, gen.Membership{MemberId: mm.MemberID, OrganisationId: mm.TenantID})
		}
	}
	return out, nil
}

// acceptInvitation creates the member an invitation stands for. It is idempotent: the member id
// is fixed when the invitation is created.
func (s *Service) acceptInvitation(tx repository.Tx, inv *invitation, acct *account) error {
	now := s.now()
	if inv.Kind == "member" {
		m, err := get[member](tx, kMember, inv.TenantID, inv.MemberID)
		if err != nil || m == nil {
			return notFoundOr(err)
		}
		m.AccountID, m.Status = acct.ID, "active"
		if err := put(tx, kMember, inv.TenantID, m.ID, m, keys{k1: acct.ID}); err != nil {
			return err
		}
		if err := put(tx, kMembership, repository.Global, m.ID, membership{MemberID: m.ID, TenantID: inv.TenantID, AccountID: acct.ID}, keys{k1: acct.ID}); err != nil {
			return err
		}
		return s.emit(tx, inv.TenantID, "", "identity.member.changed", m.ID, m.ID, map[string]any{"member_id": m.ID, "change": "status_changed"})
	}
	_, ownerID, err := s.loadRoles(tx, inv.TenantID)
	if err != nil {
		return err
	}
	if ownerID == "" {
		ownerID = string(s.NewID())
		r := role{ID: ownerID, Name: "Owner", BuiltIn: true, Perms: []string{"*"}, CreatedAt: now, UpdatedAt: now}
		if err := put(tx, kRole, inv.TenantID, ownerID, r, keys{}); err != nil {
			return err
		}
	}
	if m, err := get[member](tx, kMember, inv.TenantID, inv.MemberID); err != nil || m != nil {
		return err
	}
	name := inv.OwnerName
	if name == "" {
		name = "Owner"
	}
	m := member{ID: inv.MemberID, TenantID: inv.TenantID, DisplayName: name, Status: "active", AccountID: acct.ID,
		Assignments: []assignment{{ID: string(s.NewID()), RoleID: ownerID}}, CreatedAt: now}
	if err := put(tx, kMember, inv.TenantID, m.ID, m, keys{k1: acct.ID}); err != nil {
		return err
	}
	if err := put(tx, kMembership, repository.Global, m.ID, membership{MemberID: m.ID, TenantID: inv.TenantID, AccountID: acct.ID}, keys{k1: acct.ID}); err != nil {
		return err
	}
	if err := s.adjustOwners(tx, inv.TenantID, +1); err != nil {
		return err
	}
	if err := s.emit(tx, inv.TenantID, "", "identity.member.changed", m.ID, m.ID, map[string]any{"member_id": m.ID, "change": "created"}); err != nil {
		return err
	}
	return s.audit(tx, inv.TenantID, auditDoc{Action: "member.created", ActorKind: "system", ActorLbl: "invitation", Outcome: "succeeded", Target: m.ID})
}

type ownerCount struct {
	N int `json:"n"`
}

func (s *Service) adjustOwners(tx repository.Tx, tenant string, d int) error {
	c, err := get[ownerCount](tx, kOwnerCount, repository.Global, tenant)
	if err != nil {
		return err
	}
	if c == nil {
		c = &ownerCount{}
	}
	c.N += d
	return put(tx, kOwnerCount, repository.Global, tenant, c, keys{})
}

// ensureBinding finds or creates the account-device binding. A binding is under caution for 24
// hours from creation, except for the first binding an account ever has (A2.2 items 1, 2).
func (s *Service) ensureBinding(ctx context.Context, tx repository.Tx, acct *account, deviceID string, key crypto.JWK) (*binding, error) {
	now := s.now()
	all, err := find[binding](tx, kBinding, repository.Global, acct.ID)
	if err != nil {
		return nil, err
	}
	thumb := crypto.Thumbprint(key)
	for i := range all {
		// SR-H2: a binding is "this device" only when id AND key match; a known id with a new key
		// is a new binding under caution (the clone signal of IC-14).
		if all[i].Device != deviceID || all[i].Thumb != thumb {
			continue
		}
		if all[i].State != "active" {
			return nil, apperr.New(apperr.Unauthenticated, "auth.invalid_token", "invalid or missing credentials")
		}
		return &all[i], nil
	}
	b := binding{ID: string(s.NewID()), AccountID: acct.ID, Device: deviceID, Key: key, Thumb: thumb, CreatedAt: now, State: "active"}
	if len(all) > 0 {
		b.Caution = now.Add(s.Cfg.CautionWindow)
		s.Notify.Notify(ctx, Notice{Kind: "new_device", AccountID: acct.ID, DeviceID: deviceID})
	}
	if err := put(tx, kBinding, repository.Global, b.ID, b, keys{k1: acct.ID, k2: deviceID}); err != nil {
		return nil, err
	}
	return &b, nil
}

// sessionKey returns the device key a session's refresh proofs must verify with.
func (s *Service) sessionKey(tx repository.Tx, sess *session) (*crypto.JWK, error) {
	if sess.Binding != "" {
		b, err := get[binding](tx, kBinding, repository.Global, sess.Binding)
		if err != nil || b == nil {
			return nil, err
		}
		return &b.Key, nil
	}
	d, err := get[device](tx, kDevice, sess.TenantID, sess.Device)
	if err != nil || d == nil {
		return nil, err
	}
	return &d.Key, nil
}
