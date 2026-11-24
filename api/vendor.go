package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/service"
)

// vctx adds the vendor user's client address (set by the admin service) to the request context
// for audit; the admin service's service token is what makes the header trustworthy.
func vctx(r *http.Request) context.Context {
	return service.WithAddr(r.Context(), r.Header.Get("X-Vendor-Client-Address"))
}

func (h *Handler) CreateVendorSession(w http.ResponseWriter, r *http.Request, _ gen.CreateVendorSessionParams) {
	do(w, r, http.StatusCreated, func(in gen.VendorSignIn) (gen.VendorSession, error) { return h.s.CreateVendorSession(vctx(r), in) })
}

func (h *Handler) RenewVendorSession(w http.ResponseWriter, r *http.Request, _ gen.RenewVendorSessionParams) {
	do(w, r, http.StatusOK, func(in gen.VendorSessionRenewal) (gen.VendorSession, error) {
		return h.s.RenewVendorSession(vctx(r), in)
	})
}

func (h *Handler) EndVendorSession(w http.ResponseWriter, r *http.Request, _ gen.EndVendorSessionParams) {
	noContent(w, r, func() error { return h.s.EndVendorSession(vctx(r)) })
}

func (h *Handler) BeginVendorSetup(w http.ResponseWriter, r *http.Request, _ gen.BeginVendorSetupParams) {
	do(w, r, http.StatusCreated, func(in gen.BeginVendorSetup) (gen.VendorSetupChallenge, error) {
		return h.s.BeginVendorSetup(vctx(r), in)
	})
}

func (h *Handler) CompleteVendorSetup(w http.ResponseWriter, r *http.Request, _ gen.CompleteVendorSetupParams) {
	do(w, r, http.StatusOK, func(in gen.CompleteVendorSetup) (gen.VendorUser, error) { return h.s.CompleteVendorSetup(vctx(r), in) })
}

func (h *Handler) ListVendorUsers(w http.ResponseWriter, r *http.Request, p gen.ListVendorUsersParams) {
	call(w, r, http.StatusOK, func() (gen.VendorUserPage, error) { return h.s.ListVendorUsers(vctx(r), p) })
}

func (h *Handler) CreateVendorUser(w http.ResponseWriter, r *http.Request, _ gen.CreateVendorUserParams) {
	do(w, r, http.StatusCreated, func(in gen.CreateVendorUser) (gen.VendorUser, error) { return h.s.CreateVendorUser(vctx(r), in) })
}

func (h *Handler) UpdateVendorUser(w http.ResponseWriter, r *http.Request, id gen.Id, _ gen.UpdateVendorUserParams) {
	do(w, r, http.StatusOK, func(in gen.UpdateVendorUser) (gen.VendorUser, error) { return h.s.UpdateVendorUser(vctx(r), id, in) })
}

func (h *Handler) ResetVendorUserTotp(w http.ResponseWriter, r *http.Request, id gen.Id, _ gen.ResetVendorUserTotpParams) {
	call(w, r, http.StatusCreated, func() (gen.VendorUser, error) { return h.s.ResetVendorUserTotp(vctx(r), id) })
}

func (h *Handler) ListVendorAuditEntries(w http.ResponseWriter, r *http.Request, p gen.ListVendorAuditEntriesParams) {
	call(w, r, http.StatusOK, func() (gen.VendorAuditPage, error) { return h.s.ListVendorAuditEntries(vctx(r), p) })
}

func (h *Handler) LookupOrganisationsByOwnerMobile(w http.ResponseWriter, r *http.Request, _ gen.LookupOrganisationsByOwnerMobileParams) {
	do(w, r, http.StatusOK, func(in gen.OwnerLookup) (gen.OwnerLookupResult, error) {
		return h.s.LookupOrganisationsByOwnerMobile(vctx(r), in)
	})
}

func (h *Handler) GetOwnerStatuses(w http.ResponseWriter, r *http.Request, p gen.GetOwnerStatusesParams) {
	call(w, r, http.StatusOK, func() (gen.OwnerStatusList, error) {
		return h.s.GetOwnerStatuses(vctx(r), strings.Split(p.OrganisationIds, ","))
	})
}

func (h *Handler) CreateOwnerInvitation(w http.ResponseWriter, r *http.Request, org gen.Id, _ gen.CreateOwnerInvitationParams) {
	do(w, r, http.StatusCreated, func(in gen.CreateOwnerInvitation) (gen.OwnerInvitation, error) {
		return h.s.CreateOwnerInvitation(vctx(r), org, in)
	})
}

func (h *Handler) ListOwnerInvitations(w http.ResponseWriter, r *http.Request, org gen.Id, _ gen.ListOwnerInvitationsParams) {
	call(w, r, http.StatusOK, func() (gen.OwnerInvitationList, error) { return h.s.ListOwnerInvitations(vctx(r), org) })
}

func (h *Handler) RenewOwnerInvitation(w http.ResponseWriter, r *http.Request, org gen.Id, id gen.Id, _ gen.RenewOwnerInvitationParams) {
	call(w, r, http.StatusOK, func() (gen.OwnerInvitation, error) { return h.s.RenewOwnerInvitation(vctx(r), org, id) })
}

func (h *Handler) CancelOwnerInvitation(w http.ResponseWriter, r *http.Request, org gen.Id, id gen.Id, _ gen.CancelOwnerInvitationParams) {
	call(w, r, http.StatusOK, func() (gen.OwnerInvitation, error) { return h.s.CancelOwnerInvitation(vctx(r), org, id) })
}

func (h *Handler) ListOrganisationDevices(w http.ResponseWriter, r *http.Request, org gen.Id, p gen.ListOrganisationDevicesParams) {
	call(w, r, http.StatusOK, func() (gen.VendorDevicePage, error) { return h.s.ListOrganisationDevices(vctx(r), org, p) })
}

func (h *Handler) GetOrganisationDevice(w http.ResponseWriter, r *http.Request, org gen.Id, id gen.Id, _ gen.GetOrganisationDeviceParams) {
	call(w, r, http.StatusOK, func() (gen.VendorDevice, error) { return h.s.GetOrganisationDevice(vctx(r), org, id) })
}

func (h *Handler) RevokeOrganisationDevice(w http.ResponseWriter, r *http.Request, org gen.Id, id gen.Id, _ gen.RevokeOrganisationDeviceParams) {
	do(w, r, http.StatusOK, func(in gen.VendorRevoke) (gen.VendorRevokeResult, error) {
		return h.s.RevokeOrganisationDevice(vctx(r), org, id, in)
	})
}

func (h *Handler) StartSupportSession(w http.ResponseWriter, r *http.Request, _ gen.StartSupportSessionParams) {
	do(w, r, http.StatusCreated, func(in gen.StartSupportSession) (gen.SupportSessionStarted, error) {
		return h.s.StartSupportSession(vctx(r), in)
	})
}

func (h *Handler) GetSupportSession(w http.ResponseWriter, r *http.Request, id gen.Id, _ gen.GetSupportSessionParams) {
	call(w, r, http.StatusOK, func() (gen.SupportSession, error) { return h.s.GetSupportSession(vctx(r), id) })
}

func (h *Handler) RenewSupportToken(w http.ResponseWriter, r *http.Request, id gen.Id, _ gen.RenewSupportTokenParams) {
	call(w, r, http.StatusCreated, func() (gen.SupportToken, error) { return h.s.RenewSupportToken(vctx(r), id) })
}

func (h *Handler) EndSupportSession(w http.ResponseWriter, r *http.Request, id gen.Id, _ gen.EndSupportSessionParams) {
	call(w, r, http.StatusOK, func() (gen.SupportSession, error) { return h.s.EndSupportSession(vctx(r), id) })
}

func (h *Handler) CreateVendorApproval(w http.ResponseWriter, r *http.Request, _ gen.CreateVendorApprovalParams) {
	do(w, r, http.StatusCreated, func(in gen.CreateVendorApproval) (gen.VendorApproval, error) {
		return h.s.CreateVendorApproval(vctx(r), in)
	})
}

func (h *Handler) ListVendorApprovals(w http.ResponseWriter, r *http.Request, p gen.ListVendorApprovalsParams) {
	call(w, r, http.StatusOK, func() (gen.VendorApprovalPage, error) { return h.s.ListVendorApprovals(vctx(r), p) })
}

func (h *Handler) ApproveVendorApproval(w http.ResponseWriter, r *http.Request, id gen.Id, _ gen.ApproveVendorApprovalParams) {
	do(w, r, http.StatusOK, func(in gen.ApproveVendorApproval) (gen.ApprovalDecision, error) {
		return h.s.ApproveVendorApproval(vctx(r), id, in)
	})
}

func (h *Handler) ClaimCodeHalf(w http.ResponseWriter, r *http.Request, id gen.Id, _ gen.ClaimCodeHalfParams) {
	call(w, r, http.StatusCreated, func() (gen.CodeHalf, error) { return h.s.ClaimCodeHalf(vctx(r), id) })
}

func (h *Handler) CancelVendorApproval(w http.ResponseWriter, r *http.Request, id gen.Id, _ gen.CancelVendorApprovalParams) {
	do(w, r, http.StatusOK, func(in gen.RejectVendorApproval) (gen.VendorApproval, error) {
		return h.s.CancelVendorApproval(vctx(r), id, in)
	})
}

func (h *Handler) CancelOwnerRecovery(w http.ResponseWriter, r *http.Request, id gen.Id, _ gen.CancelOwnerRecoveryParams) {
	do(w, r, http.StatusOK, func(in gen.RecoveryCancellation) (gen.OwnerRecovery, error) {
		return h.s.CancelOwnerRecovery(r.Context(), id, in)
	})
}
