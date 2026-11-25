package api

import (
	"encoding/json"
	"net/http"

	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/svc-identity/internal/gen"
)

var _ gen.ServerInterface = (*Handler)(nil)

// ---- sessions and tokens ----

func (h *Handler) CreateOtpChallenge(w http.ResponseWriter, r *http.Request, _ gen.CreateOtpChallengeParams) {
	do(w, r, http.StatusAccepted, func(in gen.CreateOtpChallenge) (gen.OtpChallenge, error) {
		return h.s.CreateOtpChallenge(r.Context(), in, h.clientAddr(r))
	})
}

func (h *Handler) CreateSession(w http.ResponseWriter, r *http.Request, _ gen.CreateSessionParams) {
	do(w, r, http.StatusCreated, func(in gen.CreateSession) (gen.Session, error) { return h.s.CreateSession(r.Context(), in) })
}

func (h *Handler) EndSession(w http.ResponseWriter, r *http.Request, sessionId gen.Id, _ gen.EndSessionParams) {
	noContent(w, r, func() error { return h.s.EndSession(r.Context(), sessionId) })
}

func (h *Handler) RefreshSession(w http.ResponseWriter, r *http.Request, _ gen.RefreshSessionParams) {
	do(w, r, http.StatusOK, func(in gen.RefreshSession) (gen.TokenPair, error) { return h.s.RefreshSession(r.Context(), in) })
}

func (h *Handler) SwitchMember(w http.ResponseWriter, r *http.Request, _ gen.SwitchMemberParams) {
	do(w, r, http.StatusOK, func(in gen.SwitchMember) (gen.TokenPair, error) { return h.s.SwitchMember(r.Context(), in) })
}

func (h *Handler) CreateDeviceToken(w http.ResponseWriter, r *http.Request, _ gen.CreateDeviceTokenParams) {
	do(w, r, http.StatusOK, func(in gen.DeviceTokenRequest) (gen.DeviceToken, error) {
		kind, err := in.Discriminator()
		if err != nil {
			return gen.DeviceToken{}, apperr.New(apperr.Validation, "validation.failed", "the request is invalid")
		}
		if kind == string(gen.PinGrantGrantTypePin) {
			g, err := in.AsPinGrant()
			if err != nil {
				return gen.DeviceToken{}, apperr.New(apperr.Validation, "validation.failed", "the request is invalid")
			}
			return h.s.CreatePinToken(r.Context(), g)
		}
		g, err := in.AsDeviceGrant()
		if err != nil || g.GrantType != gen.DeviceGrantGrantTypeDevice {
			return gen.DeviceToken{}, apperr.New(apperr.Validation, "validation.failed", "the request is invalid")
		}
		return h.s.CreateDeviceGrantToken(r.Context(), g)
	})
}

func (h *Handler) CreateDrainToken(w http.ResponseWriter, r *http.Request, _ gen.CreateDrainTokenParams) {
	do(w, r, http.StatusOK, func(in gen.DrainRequest) (gen.DrainToken, error) { return h.s.CreateDrainToken(r.Context(), in) })
}

func (h *Handler) CreateDeviceNonce(w http.ResponseWriter, r *http.Request, _ gen.CreateDeviceNonceParams) {
	call(w, r, http.StatusCreated, func() (gen.DeviceNonce, error) { return h.s.CreateDeviceNonce(r.Context()) })
}

func (h *Handler) GetJwks(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.s.JWKS(false))
}

func (h *Handler) GetVendorJwks(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.s.JWKS(true))
}

// ---- devices ----

func (h *Handler) ListActivationCodes(w http.ResponseWriter, r *http.Request, p gen.ListActivationCodesParams) {
	call(w, r, http.StatusOK, func() (gen.ActivationCodePage, error) { return h.s.ListActivationCodes(r.Context(), p) })
}

func (h *Handler) RevokeActivationCode(w http.ResponseWriter, r *http.Request, activationCodeId gen.Id, _ gen.RevokeActivationCodeParams) {
	call(w, r, http.StatusOK, func() (gen.ActivationCodeSummary, error) {
		return h.s.RevokeActivationCode(r.Context(), activationCodeId)
	})
}

func (h *Handler) IssueVendorApprovalGrant(w http.ResponseWriter, r *http.Request, approvalId gen.Id, _ gen.IssueVendorApprovalGrantParams) {
	call(w, r, http.StatusCreated, func() (gen.VendorApprovalGrant, error) {
		return h.s.IssueVendorApprovalGrant(r.Context(), approvalId)
	})
}

func (h *Handler) CreateActivationCode(w http.ResponseWriter, r *http.Request, _ gen.CreateActivationCodeParams) {
	do(w, r, http.StatusCreated, func(in gen.CreateActivationCode) (gen.ActivationCode, error) {
		return h.s.CreateActivationCode(r.Context(), in)
	})
}

func (h *Handler) CreateDeviceRecoveryCode(w http.ResponseWriter, r *http.Request, deviceId gen.Id, _ gen.CreateDeviceRecoveryCodeParams) {
	call(w, r, http.StatusCreated, func() (gen.RecoveryCode, error) { return h.s.CreateDeviceRecoveryCode(r.Context(), deviceId) })
}

func (h *Handler) ActivateDevice(w http.ResponseWriter, r *http.Request, _ gen.ActivateDeviceParams) {
	do(w, r, http.StatusCreated, func(in gen.ActivateDevice) (gen.DeviceActivation, error) {
		return h.s.ActivateDevice(r.Context(), in, h.clientAddr(r))
	})
}

func (h *Handler) RegisterDevice(w http.ResponseWriter, r *http.Request, _ gen.RegisterDeviceParams) {
	do(w, r, http.StatusCreated, func(in gen.RegisterDevice) (gen.Device, error) { return h.s.RegisterDevice(r.Context(), in) })
}

func (h *Handler) ListDevices(w http.ResponseWriter, r *http.Request, p gen.ListDevicesParams) {
	call(w, r, http.StatusOK, func() (gen.DevicePage, error) { return h.s.ListDevices(r.Context(), p) })
}

func (h *Handler) GetDevice(w http.ResponseWriter, r *http.Request, deviceId gen.Id) {
	call(w, r, http.StatusOK, func() (gen.Device, error) { return h.s.GetDevice(r.Context(), deviceId) })
}

func (h *Handler) RevokeDevice(w http.ResponseWriter, r *http.Request, deviceId gen.Id, _ gen.RevokeDeviceParams) {
	do(w, r, http.StatusOK, func(in gen.RevokeDevice) (gen.Device, error) { return h.s.RevokeDevice(r.Context(), deviceId, in) })
}

func (h *Handler) GetDeviceOfflinePack(w http.ResponseWriter, r *http.Request, deviceId gen.Id) {
	call(w, r, http.StatusOK, func() (gen.OfflinePack, error) { return h.s.GetDeviceOfflinePack(r.Context(), deviceId) })
}

func (h *Handler) GetWipeOrder(w http.ResponseWriter, r *http.Request, deviceId gen.Id) {
	call(w, r, http.StatusOK, func() (gen.WipeOrder, error) { return h.s.GetWipeOrder(r.Context(), deviceId) })
}

// ---- members, roles, PIN ----

func (h *Handler) ListMembers(w http.ResponseWriter, r *http.Request, p gen.ListMembersParams) {
	call(w, r, http.StatusOK, func() (gen.MemberPage, error) { return h.s.ListMembers(r.Context(), p) })
}

func (h *Handler) CreateMember(w http.ResponseWriter, r *http.Request, _ gen.CreateMemberParams) {
	do(w, r, http.StatusCreated, func(in gen.CreateMember) (gen.Member, error) { return h.s.CreateMember(r.Context(), in) })
}

func (h *Handler) GetMember(w http.ResponseWriter, r *http.Request, memberId gen.Id) {
	call(w, r, http.StatusOK, func() (gen.Member, error) { return h.s.GetMember(r.Context(), memberId) })
}

func (h *Handler) UpdateMember(w http.ResponseWriter, r *http.Request, memberId gen.Id, _ gen.UpdateMemberParams) {
	do(w, r, http.StatusOK, func(in gen.UpdateMember) (gen.Member, error) { return h.s.UpdateMember(r.Context(), memberId, in) })
}

func (h *Handler) ClearPinLockout(w http.ResponseWriter, r *http.Request, memberId gen.Id, _ gen.ClearPinLockoutParams) {
	noContent(w, r, func() error { return h.s.ClearPinLockout(r.Context(), memberId) })
}

func (h *Handler) AuthorisePinReset(w http.ResponseWriter, r *http.Request, memberId gen.Id, _ gen.AuthorisePinResetParams) {
	call(w, r, http.StatusCreated, func() (gen.PinResetAuthorisation, error) { return h.s.AuthorisePinReset(r.Context(), memberId) })
}

func (h *Handler) SetPin(w http.ResponseWriter, r *http.Request, memberId gen.Id, _ gen.SetPinParams) {
	do(w, r, http.StatusOK, func(in gen.SetPin) (gen.PinSet, error) { return h.s.SetPin(r.Context(), memberId, in) })
}

func (h *Handler) CreateRoleAssignment(w http.ResponseWriter, r *http.Request, memberId gen.Id, _ gen.CreateRoleAssignmentParams) {
	do(w, r, http.StatusCreated, func(in gen.AssignmentInput) (gen.RoleAssignment, error) {
		return h.s.CreateRoleAssignment(r.Context(), memberId, in)
	})
}

func (h *Handler) DeleteRoleAssignment(w http.ResponseWriter, r *http.Request, memberId gen.Id, assignmentId gen.Id, _ gen.DeleteRoleAssignmentParams) {
	noContent(w, r, func() error { return h.s.DeleteRoleAssignment(r.Context(), memberId, assignmentId) })
}

func (h *Handler) AssignOwnerRole(w http.ResponseWriter, r *http.Request, memberId gen.Id, _ gen.AssignOwnerRoleParams) {
	do(w, r, http.StatusOK, func(in gen.OwnerRoleAssignment) (gen.Member, error) {
		return h.s.AssignOwnerRole(r.Context(), memberId, in)
	})
}

func (h *Handler) RemoveOwnerRole(w http.ResponseWriter, r *http.Request, memberId gen.Id, _ gen.RemoveOwnerRoleParams) {
	noContent(w, r, func() error { return h.s.RemoveOwnerRole(r.Context(), memberId) })
}

func (h *Handler) ListRoles(w http.ResponseWriter, r *http.Request, p gen.ListRolesParams) {
	call(w, r, http.StatusOK, func() (gen.RolePage, error) { return h.s.ListRoles(r.Context(), p) })
}

func (h *Handler) CreateRole(w http.ResponseWriter, r *http.Request, _ gen.CreateRoleParams) {
	do(w, r, http.StatusCreated, func(in gen.RoleInput) (gen.Role, error) { return h.s.CreateRole(r.Context(), in) })
}

func (h *Handler) GetRole(w http.ResponseWriter, r *http.Request, roleId gen.Id) {
	call(w, r, http.StatusOK, func() (gen.Role, error) { return h.s.GetRole(r.Context(), roleId) })
}

func (h *Handler) UpdateRole(w http.ResponseWriter, r *http.Request, roleId gen.Id, _ gen.UpdateRoleParams) {
	do(w, r, http.StatusOK, func(in gen.RoleInput) (gen.Role, error) { return h.s.UpdateRole(r.Context(), roleId, in) })
}

func (h *Handler) DeleteRole(w http.ResponseWriter, r *http.Request, roleId gen.Id, _ gen.DeleteRoleParams) {
	noContent(w, r, func() error { return h.s.DeleteRole(r.Context(), roleId) })
}

func (h *Handler) ListPermissions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.s.ListPermissions())
}

func (h *Handler) ListAuditEntries(w http.ResponseWriter, r *http.Request, p gen.ListAuditEntriesParams) {
	call(w, r, http.StatusOK, func() (gen.TenantAuditPage, error) { return h.s.ListAuditEntries(r.Context(), p) })
}

// ---- caution approvals and bindings ----

func (h *Handler) CreateApprovalRequest(w http.ResponseWriter, r *http.Request, _ gen.CreateApprovalRequestParams) {
	// request_body is hashed as the exact bytes received (no re-serialisation), so it is kept raw.
	do(w, r, http.StatusCreated, func(in struct {
		OperationID   string          `json:"operation_id"`
		RequestMethod string          `json:"request_method"`
		RequestPath   string          `json:"request_path"`
		RequestBody   json.RawMessage `json:"request_body"`
	}) (gen.ApprovalRequest, error) {
		return h.s.CreateApprovalRequest(r.Context(), in.OperationID, in.RequestMethod, in.RequestPath, in.RequestBody)
	})
}

func (h *Handler) ListApprovalRequests(w http.ResponseWriter, r *http.Request, p gen.ListApprovalRequestsParams) {
	call(w, r, http.StatusOK, func() (gen.ApprovalRequestPage, error) { return h.s.ListApprovalRequests(r.Context(), p) })
}

func (h *Handler) GetApprovalRequest(w http.ResponseWriter, r *http.Request, requestId gen.Id) {
	call(w, r, http.StatusOK, func() (gen.ApprovalRequest, error) { return h.s.GetApprovalRequest(r.Context(), requestId) })
}

func (h *Handler) DecideApprovalRequest(w http.ResponseWriter, r *http.Request, requestId gen.Id, _ gen.DecideApprovalRequestParams) {
	do(w, r, http.StatusOK, func(in gen.DecideApproval) (gen.ApprovalRequest, error) {
		return h.s.DecideApprovalRequest(r.Context(), requestId, in)
	})
}

func (h *Handler) ListBindings(w http.ResponseWriter, r *http.Request, p gen.ListBindingsParams) {
	call(w, r, http.StatusOK, func() (gen.BindingPage, error) { return h.s.ListBindings(r.Context(), p) })
}

func (h *Handler) RejectBinding(w http.ResponseWriter, r *http.Request, bindingId gen.Id, _ gen.RejectBindingParams) {
	call(w, r, http.StatusOK, func() (gen.Binding, error) { return h.s.RejectBinding(r.Context(), bindingId) })
}

// ---- internal (sync gateway) ----

func (h *Handler) ListRevocations(w http.ResponseWriter, r *http.Request, p gen.ListRevocationsParams) {
	call(w, r, http.StatusOK, func() (gen.RevocationPage, error) { return h.s.ListRevocations(r.Context(), p) })
}

func (h *Handler) RecordDeviceDrained(w http.ResponseWriter, r *http.Request, deviceId gen.Id, _ gen.RecordDeviceDrainedParams) {
	do(w, r, http.StatusOK, func(in gen.RecordDrain) (gen.Device, error) {
		return h.s.RecordDeviceDrained(r.Context(), deviceId, in)
	})
}

func (h *Handler) VerifyProof(w http.ResponseWriter, r *http.Request, _ gen.VerifyProofParams) {
	do(w, r, http.StatusOK, func(in gen.ProofVerification) (gen.ProofVerdict, error) { return h.s.VerifyProof(r.Context(), in) })
}

func (h *Handler) CheckPackHistory(w http.ResponseWriter, r *http.Request, _ gen.CheckPackHistoryParams) {
	do(w, r, http.StatusOK, func(in gen.PackHistoryCheck) (gen.PackHistoryVerdict, error) {
		return h.s.CheckPackHistory(r.Context(), in)
	})
}

// ---- internal directory questions of the sync gateway (ADR-0005 A3.2) ----

func (h *Handler) GetDeviceCredential(w http.ResponseWriter, r *http.Request, deviceId gen.Id) {
	call(w, r, http.StatusOK, func() (gen.DeviceCredential, error) { return h.s.GetDeviceCredential(r.Context(), deviceId) })
}

func (h *Handler) GetPackGrants(w http.ResponseWriter, r *http.Request, deviceId gen.Id, packV int) {
	call(w, r, http.StatusOK, func() (gen.PackGrants, error) { return h.s.GetPackGrants(r.Context(), deviceId, packV) })
}

func (h *Handler) GetMemberGrants(w http.ResponseWriter, r *http.Request, memberId gen.Id, p gen.GetMemberGrantsParams) {
	call(w, r, http.StatusOK, func() (gen.MemberGrants, error) { return h.s.GetMemberGrants(r.Context(), memberId, p.OutletId) })
}

func (h *Handler) GetDeviceRecovery(w http.ResponseWriter, r *http.Request, deviceId gen.Id) {
	call(w, r, http.StatusOK, func() (gen.DeviceRecovery, error) { return h.s.GetDeviceRecovery(r.Context(), deviceId) })
}

func (h *Handler) GetSession(w http.ResponseWriter, r *http.Request, sessionId gen.Id) {
	call(w, r, http.StatusOK, func() (gen.SessionFacts, error) { return h.s.GetSession(r.Context(), sessionId) })
}
