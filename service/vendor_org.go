package service

import (
	"context"
	"strings"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/repository"
)

// vendorOrg returns a context whose tenancy context is the organisation named in the path, after
// checking the vendor permission (go-auth's one helper for this, ADR-0013 V3 item 4).
func (s *Service) vendorOrg(ctx context.Context, perm, org string) (context.Context, error) {
	if _, err := ids.Parse(org); err != nil {
		return ctx, errNotFound()
	}
	return auth.VendorTenant(ctx, perm, ids.ID(org))
}

func invitationDTO(i *invitation, now time.Time) gen.OwnerInvitation {
	g := gen.OwnerInvitation{Id: i.ID, OrganisationId: i.TenantID, MobileMasked: maskMobile(i.Mobile), CreatedAt: i.CreatedAt, ExpiresAt: i.ExpiresAt,
		Status: gen.InvitationStatus(i.effective(now))}
	if i.OwnerName != "" {
		n := i.OwnerName
		g.OwnerName = &n
	}
	if !i.AcceptedAt.IsZero() {
		t := i.AcceptedAt
		g.AcceptedAt = &t
	}
	return g
}

// newOwnerInvitation creates a pending owner invitation; the member id is fixed now so
// acceptance is idempotent. The number is stored only in identity (ADR-0005 section 3).
func (s *Service) newOwnerInvitation(tx repository.Tx, org, mobile, name string) (*invitation, error) {
	now := s.now()
	i := invitation{ID: string(s.NewID()), Kind: "owner", TenantID: org, MobileKey: s.mobileKey(mobile), Mobile: mobile, OwnerName: name,
		Status: "pending", CreatedAt: now, ExpiresAt: now.Add(s.Cfg.InvitationTTL), MemberID: string(s.NewID())}
	return &i, put(tx, kInvitation, repository.Global, i.ID, i, keys{k1: i.MobileKey, k2: org})
}

func (s *Service) orgInvitations(tx repository.Tx, org string) ([]invitation, error) {
	return findK2[invitation](tx, kInvitation, repository.Global, org)
}

// CreateOwnerInvitation invites the first owner of an organisation. Allowed only while the
// organisation has no owner member; a repeat for the same number returns the same pending
// invitation (ADR-0005 A2.3: no vendor can add or replace owners of a running organisation).
func (s *Service) CreateOwnerInvitation(ctx context.Context, org string, in gen.CreateOwnerInvitation) (gen.OwnerInvitation, error) {
	ctx, err := s.vendorOrg(ctx, "admin.owner_invite.manage", org)
	if err != nil {
		return gen.OwnerInvitation{}, err
	}
	if !mobileRE.MatchString(in.MobileE164) || strings.TrimSpace(in.OwnerName) == "" {
		return gen.OwnerInvitation{}, errInvalid("mobile_e164", "not_indian_mobile")
	}
	var out gen.OwnerInvitation
	err = s.Store.Tx(ctx, org, func(tx repository.Tx) error {
		now := s.now()
		if c, err := get[ownerCount](tx, kOwnerCount, repository.Global, org); err != nil {
			return err
		} else if c != nil && c.N > 0 {
			return apperr.New(apperr.Conflict, "owner_exists", "the organisation already has an owner")
		}
		invs, err := s.orgInvitations(tx, org)
		if err != nil {
			return err
		}
		mk := s.mobileKey(in.MobileE164)
		for i := range invs {
			if invs[i].Kind != "owner" || invs[i].effective(now) != "pending" {
				continue
			}
			if invs[i].MobileKey == mk {
				out = invitationDTO(&invs[i], now)
				return nil
			}
			invs[i].Status = "cancelled" // a different number replaces the pending one
			if err := put(tx, kInvitation, repository.Global, invs[i].ID, invs[i], keys{k1: invs[i].MobileKey, k2: org}); err != nil {
				return err
			}
		}
		i, err := s.newOwnerInvitation(tx, org, in.MobileE164, strings.TrimSpace(in.OwnerName))
		if err != nil {
			return err
		}
		out = invitationDTO(i, now)
		auth.SetAuditTarget(ctx, org)
		return s.vendorAudit(ctx, tx, vaudit{Org: org, Action: "owner_invitation.created", Target: i.ID})
	})
	return out, err
}

func (s *Service) invitationOf(tx repository.Tx, org, id string) (*invitation, error) {
	i, err := get[invitation](tx, kInvitation, repository.Global, id)
	if err != nil || i == nil || i.TenantID != org || i.Kind != "owner" {
		return nil, notFoundOr(err)
	}
	return i, nil
}

// ListOwnerInvitations lists an organisation's invitations, newest first, numbers masked.
func (s *Service) ListOwnerInvitations(ctx context.Context, org string) (gen.OwnerInvitationList, error) {
	ctx, err := s.vendorOrg(ctx, "admin.org.read", org)
	if err != nil {
		return gen.OwnerInvitationList{}, err
	}
	out := gen.OwnerInvitationList{Items: []gen.OwnerInvitation{}}
	err = s.Store.Tx(ctx, org, func(tx repository.Tx) error {
		invs, err := s.orgInvitations(tx, org)
		if err != nil {
			return err
		}
		for i := len(invs) - 1; i >= 0; i-- {
			if invs[i].Kind == "owner" {
				out.Items = append(out.Items, invitationDTO(&invs[i], s.now()))
			}
		}
		return nil
	})
	return out, err
}

func (s *Service) changeInvitation(ctx context.Context, org, id, action string, mut func(i *invitation)) (gen.OwnerInvitation, error) {
	ctx, err := s.vendorOrg(ctx, "admin.owner_invite.manage", org)
	if err != nil {
		return gen.OwnerInvitation{}, err
	}
	var out gen.OwnerInvitation
	err = s.Store.Tx(ctx, org, func(tx repository.Tx) error {
		i, err := s.invitationOf(tx, org, id)
		if err != nil {
			return err
		}
		if i.effective(s.now()) != "pending" {
			return apperr.New(apperr.Conflict, "invitation_not_pending", "the invitation is not pending")
		}
		mut(i)
		if err := put(tx, kInvitation, repository.Global, i.ID, i, keys{k1: i.MobileKey, k2: org}); err != nil {
			return err
		}
		out = invitationDTO(i, s.now())
		return s.vendorAudit(ctx, tx, vaudit{Org: org, Action: action, Target: i.ID})
	})
	return out, err
}

// RenewOwnerInvitation moves a pending invitation's expiry to 14 days from now.
func (s *Service) RenewOwnerInvitation(ctx context.Context, org, id string) (gen.OwnerInvitation, error) {
	return s.changeInvitation(ctx, org, id, "owner_invitation.renewed", func(i *invitation) { i.ExpiresAt = s.now().Add(s.Cfg.InvitationTTL) })
}

// CancelOwnerInvitation cancels a pending invitation.
func (s *Service) CancelOwnerInvitation(ctx context.Context, org, id string) (gen.OwnerInvitation, error) {
	return s.changeInvitation(ctx, org, id, "owner_invitation.cancelled", func(i *invitation) { i.Status = "cancelled" })
}

// LookupOrganisationsByOwnerMobile returns organisation ids for an exact number with a pending
// invitation or an owner membership; nothing for a prefix. One audit entry per lookup.
func (s *Service) LookupOrganisationsByOwnerMobile(ctx context.Context, in gen.OwnerLookup) (gen.OwnerLookupResult, error) {
	if _, err := s.vendorPrincipal(ctx); err != nil {
		return gen.OwnerLookupResult{}, err
	}
	if !mobileRE.MatchString(in.MobileE164) {
		return gen.OwnerLookupResult{}, errInvalid("mobile_e164", "not_indian_mobile")
	}
	out := gen.OwnerLookupResult{OrganisationIds: []string{}}
	err := s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		p, _ := principal(ctx)
		lim, err := s.limitGet(tx, "lookup:"+p.VendorUser())
		if err != nil {
			return err
		}
		now := s.now()
		lim.Times = prune(lim.Times, now, time.Hour)
		if len(lim.Times) >= 60 {
			return tooMany(time.Hour)
		}
		lim.Times = append(lim.Times, now)
		if err := s.limitPut(tx, "lookup:"+p.VendorUser(), lim); err != nil {
			return err
		}
		seen := map[string]bool{}
		invs, err := s.pendingInvitations(tx, s.mobileKey(in.MobileE164), now)
		if err != nil {
			return err
		}
		for _, i := range invs {
			if i.Kind == "owner" && !seen[i.TenantID] {
				seen[i.TenantID] = true
				out.OrganisationIds = append(out.OrganisationIds, i.TenantID)
			}
		}
		if a, err := s.accountByMobile(tx, in.MobileE164); err != nil {
			return err
		} else if a != nil {
			ms, err := find[membership](tx, kMembership, repository.Global, a.ID)
			if err != nil {
				return err
			}
			for _, m := range ms {
				if c, _ := get[ownerCount](tx, kOwnerCount, repository.Global, m.TenantID); c != nil && c.N > 0 && !seen[m.TenantID] {
					seen[m.TenantID] = true
					out.OrganisationIds = append(out.OrganisationIds, m.TenantID)
				}
			}
		}
		return s.vendorAudit(ctx, tx, vaudit{Action: "owner_lookup", Summary: "1 lookup"})
	})
	return out, err
}

// GetOwnerStatuses answers the directory's owner-status column: one item per requested id, no
// number, member or device data. Directory class: not audited per read.
func (s *Service) GetOwnerStatuses(ctx context.Context, orgIDs []string) (gen.OwnerStatusList, error) {
	if _, err := s.vendorPrincipal(ctx); err != nil {
		return gen.OwnerStatusList{}, err
	}
	if len(orgIDs) == 0 || len(orgIDs) > 100 {
		return gen.OwnerStatusList{}, errInvalid("organisation_ids", "invalid")
	}
	out := gen.OwnerStatusList{Items: []gen.OwnerStatusItem{}}
	err := s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		for _, org := range orgIDs {
			if _, err := ids.Parse(org); err != nil {
				return errInvalid("organisation_ids", "invalid")
			}
			it := gen.OwnerStatusItem{OrganisationId: org, OwnerStatus: gen.OwnerStatusNone}
			invs, err := s.orgInvitations(tx, org)
			if err != nil {
				return err
			}
			for _, i := range invs {
				if i.Kind != "owner" {
					continue
				}
				it.OwnerStatus = gen.OwnerStatus(i.effective(s.now()))
				if !i.AcceptedAt.IsZero() {
					t := i.AcceptedAt
					it.OwnerAcceptedAt = &t
				}
			}
			out.Items = append(out.Items, it)
		}
		return nil
	})
	return out, err
}

// ---- vendor operational device access (A2.5: list and revoke only) ----

func vendorDeviceDTO(d *device) gen.VendorDevice {
	g := gen.VendorDevice{Id: d.ID, Kind: gen.DeviceKind(d.Kind), OutletId: d.OutletID, State: gen.DeviceState(d.State), RegisteredAt: d.CreatedAt,
		BillingCapable: d.Billing == "active"}
	kp := gen.KeyProtection(d.KeyProt)
	g.KeyProtection = &kp
	if !d.LastSeen.IsZero() {
		t := d.LastSeen
		g.LastContactAt = &t
	}
	return g
}

func (s *Service) tenantVendorAudit(tx repository.Tx, ctx context.Context, org string, d auditDoc) error {
	d.ActorKind, d.ActorLbl, d.Show = "vendor", "Hostry support", true
	return s.audit(tx, org, d)
}

// ListOrganisationDevices lists an organisation's devices as the closed vendor view. Every read is
// written to the vendor log and to the tenant's own log.
func (s *Service) ListOrganisationDevices(ctx context.Context, org string, p gen.ListOrganisationDevicesParams) (gen.VendorDevicePage, error) {
	ctx, err := s.vendorOrg(ctx, "admin.device.read", org)
	if err != nil {
		return gen.VendorDevicePage{}, err
	}
	limit := pageLimit(p.Limit, 50, 100)
	out := gen.VendorDevicePage{Items: []gen.VendorDevice{}}
	err = s.Store.Tx(ctx, org, func(tx repository.Tx) error {
		ds, err := list[device](tx, kDevice, org, deref(p.Cursor), limit+1)
		if err != nil {
			return err
		}
		for i := range ds {
			if i == limit {
				c := ds[i-1].ID
				out.NextCursor = &c
				break
			}
			out.Items = append(out.Items, vendorDeviceDTO(&ds[i]))
		}
		auth.SetResultCount(ctx, len(out.Items))
		if err := s.tenantVendorAudit(tx, ctx, org, auditDoc{Action: "vendor.devices.listed", Outcome: "succeeded", Summary: "device list"}); err != nil {
			return err
		}
		return s.vendorAudit(ctx, tx, vaudit{Org: org, Action: "vendor.devices.listed"})
	})
	return out, err
}

// GetOrganisationDevice returns one device; a device of another organisation is 404.
func (s *Service) GetOrganisationDevice(ctx context.Context, org, id string) (gen.VendorDevice, error) {
	ctx, err := s.vendorOrg(ctx, "admin.device.read", org)
	if err != nil {
		return gen.VendorDevice{}, err
	}
	var out gen.VendorDevice
	err = s.Store.Tx(ctx, org, func(tx repository.Tx) error {
		d, err := get[device](tx, kDevice, org, id)
		if err != nil || d == nil {
			return notFoundOr(err)
		}
		auth.SetAuditTarget(ctx, id)
		out = vendorDeviceDTO(d)
		if err := s.tenantVendorAudit(tx, ctx, org, auditDoc{Action: "vendor.device.read", Outcome: "succeeded", Target: id}); err != nil {
			return err
		}
		return s.vendorAudit(ctx, tx, vaudit{Org: org, Action: "vendor.device.read", Target: id})
	})
	return out, err
}

// RevokeOrganisationDevice revokes a device on a vendor user's verified request. Terminal; no wipe
// order is issued or hastened. Over the quota (2 per organisation, 10 per user, rolling 24 hours)
// the revoke needs an approved two-person approval (A2.5).
func (s *Service) RevokeOrganisationDevice(ctx context.Context, org, id string, in gen.VendorRevoke) (gen.VendorRevokeResult, error) {
	ctx, err := s.vendorOrg(ctx, "admin.device.revoke", org)
	if err != nil {
		return gen.VendorRevokeResult{}, err
	}
	if len(strings.TrimSpace(in.Reason)) < 10 || strings.TrimSpace(in.TicketReference) == "" || !in.VerificationMethod.Valid() {
		return gen.VendorRevokeResult{}, errInvalid("reason", "invalid")
	}
	pr, _ := principal(ctx)
	var out gen.VendorRevokeResult
	err = s.Store.Tx(ctx, org, func(tx repository.Tx) error {
		d, err := get[device](tx, kDevice, org, id)
		if err != nil || d == nil {
			return notFoundOr(err)
		}
		auth.SetAuditTarget(ctx, id)
		if d.State != "active" {
			out = gen.VendorRevokeResult{Changed: false, Device: vendorDeviceDTO(d), Outcome: gen.VendorRevokeResultOutcomeAlreadyRevoked}
			return s.vendorAudit(ctx, tx, vaudit{Org: org, Action: "vendor.device.revoke", Target: id, Ticket: in.TicketReference, Summary: "already revoked"})
		}
		now := s.now()
		qo, err := s.limitGet(tx, "vrevoke:org:"+pr.VendorUser()+":"+org)
		if err != nil {
			return err
		}
		qu, err := s.limitGet(tx, "vrevoke:user:"+pr.VendorUser())
		if err != nil {
			return err
		}
		qo.Times, qu.Times = prune(qo.Times, now, 24*time.Hour), prune(qu.Times, now, 24*time.Hour)
		if len(qo.Times) >= s.Cfg.RevokeQuotaOrg || len(qu.Times) >= s.Cfg.RevokeQuotaUser {
			ok, err := s.consumeRevokeApproval(tx, in.ApprovalId, org, id, pr.VendorUser())
			if err != nil {
				return err
			}
			if !ok {
				return apperr.New(apperr.Conflict, "vendor_approval_required", "this revoke is over the quota and needs a second approver")
			}
		}
		qo.Times, qu.Times = append(qo.Times, now), append(qu.Times, now)
		if err := s.limitPut(tx, "vrevoke:org:"+pr.VendorUser()+":"+org, qo); err != nil {
			return err
		}
		if err := s.limitPut(tx, "vrevoke:user:"+pr.VendorUser(), qu); err != nil {
			return err
		}
		if err := s.revokeDeviceTx(tx, d, "other", "vendor:"+pr.VendorUser()); err != nil {
			return err
		}
		if err := s.tenantVendorAudit(tx, ctx, org, auditDoc{Action: "vendor.device.revoked", Outcome: "succeeded", Target: id, Reason: in.Reason, Ticket: in.TicketReference}); err != nil {
			return err
		}
		out = gen.VendorRevokeResult{Changed: true, Device: vendorDeviceDTO(d), Outcome: gen.VendorRevokeResultOutcomeRevoked}
		return s.vendorAudit(ctx, tx, vaudit{Org: org, Action: "vendor.device.revoke", Target: id, Ticket: in.TicketReference})
	})
	return out, err
}
