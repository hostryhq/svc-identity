# Operation status

Every `operationId` of `api-specs` `openapi/identity/v1` and whether it is implemented. "Implemented" means: a handler through
the service layer with its authorisation, and the shared contract run (status, media type, schema, idempotent replay) against both the double
and the Postgres assembly. Business rules have behaviour tests where the test strategy calls for them (see api/*_test.go). Nothing is silently missing: a limitation is written next to its operation.

Total: 75 operations, 75 implemented, 0 not yet.

| operationId | Route | x-permission | Status | Note |
|---|---|---|---|---|
| `activateDevice` | `POST /v1/device-activations` | `public` | implemented | Pack carries an empty `series` list and `registration_unverified` is never produced: the series registry is tenancy-owned and no tenancy client exists yet |
| `approveVendorApproval` | `PUT /internal/v1/vendor/approvals/{approval_id}/decision` | `admin.approval.decide` | implemented |  |
| `assignOwnerRole` | `PUT /v1/members/{member_id}/owner-role` | `member.owner.assign` | implemented |  |
| `authorisePinReset` | `POST /v1/members/{member_id}/pin-reset-authorisations` | `member.pin.authorise` | implemented |  |
| `beginVendorSetup` | `POST /internal/v1/vendor/setup-sessions` | `public` | implemented |  |
| `cancelOwnerInvitation` | `PUT /internal/v1/vendor/organisations/{organisation_id}/owner-invitations/{invitation_id}/cancellation` | `admin.owner_invite.manage` | implemented |  |
| `cancelOwnerRecovery` | `PUT /v1/owner-recoveries/{recovery_id}/cancellation` | `authenticated` | implemented | Completion runs on a timer (`CompleteDueRecoveries`); recovery is off by default |
| `cancelVendorApproval` | `PUT /internal/v1/vendor/approvals/{approval_id}/cancellation` | `admin.approval.decide` | implemented |  |
| `checkPackHistory` | `POST /internal/v1/pack-history-checks` | `proof.verify` | implemented | `series_issued` is always false until series codes are issued through tenancy |
| `claimCodeHalf` | `POST /internal/v1/vendor/approvals/{approval_id}/code-half-claims` | `admin.approval.create` | implemented |  |
| `clearPinLockout` | `DELETE /v1/members/{member_id}/pin-lockout` | `member.manage` | implemented |  |
| `completeVendorSetup` | `POST /internal/v1/vendor/setup-completions` | `public` | implemented |  |
| `createActivationCode` | `POST /v1/activation-codes` | `device.activation_code.create` | implemented |  |
| `createApprovalRequest` | `POST /v1/approval-requests` | `authenticated` | implemented |  |
| `createDeviceNonce` | `POST /v1/device-nonces` | `public` | implemented |  |
| `createDeviceToken` | `POST /v1/tokens/device` | `public` | implemented | Device grant carries an empty permission set per kind until products add device roles; pin grant is complete (A2.1) |
| `createDrainToken` | `POST /v1/tokens/drain` | `public` | implemented |  |
| `createMember` | `POST /v1/members` | `member.manage` | implemented |  |
| `createOtpChallenge` | `POST /v1/otp-challenges` | `public` | implemented | SMS goes through the SMSSender interface; only the test sender exists (no DLT registration). Limits per number, device, client address and daily budget |
| `createOwnerInvitation` | `POST /internal/v1/vendor/organisations/{organisation_id}/owner-invitations` | `admin.owner_invite.manage` | implemented |  |
| `createRole` | `POST /v1/roles` | `role.manage` | implemented |  |
| `createRoleAssignment` | `POST /v1/members/{member_id}/role-assignments` | `member.role.assign` | implemented |  |
| `createSession` | `POST /v1/sessions` | `public` | implemented | OTP grant and vendor-code grant (off by default, `vendor_assist.signin_code.enabled`) |
| `createVendorApproval` | `POST /internal/v1/vendor/approvals` | `admin.approval.create` | implemented | Kinds `sign_in_code` and `owner_recovery` are refused unless their switch is on (default off); `device_revoke_over_quota` always available |
| `createVendorSession` | `POST /internal/v1/vendor/sessions` | `public` | implemented |  |
| `createVendorUser` | `POST /internal/v1/vendor/users` | `admin.user.manage` | implemented |  |
| `decideApprovalRequest` | `PUT /v1/approval-requests/{request_id}/decision` | `authenticated` | implemented |  |
| `deleteRole` | `DELETE /v1/roles/{role_id}` | `role.manage` | implemented |  |
| `deleteRoleAssignment` | `DELETE /v1/members/{member_id}/role-assignments/{assignment_id}` | `member.role.assign` | implemented |  |
| `endSession` | `DELETE /v1/sessions/{session_id}` | `authenticated` | implemented |  |
| `endSupportSession` | `PUT /internal/v1/vendor/support-sessions/{support_session_id}/termination` | `admin.support.session.start` | implemented |  |
| `endVendorSession` | `DELETE /internal/v1/vendor/sessions/current` | `authenticated` | implemented |  |
| `getApprovalRequest` | `GET /v1/approval-requests/{request_id}` | `authenticated` | implemented |  |
| `getDevice` | `GET /v1/devices/{device_id}` | `device.read` | implemented |  |
| `getDeviceOfflinePack` | `GET /v1/devices/{device_id}/offline-packs/latest` | `authenticated` | implemented | Empty `series` list (see activateDevice); `op_signing_public_key` comes from configuration |
| `getJwks` | `GET /v1/jwks` | `public` | implemented |  |
| `getMember` | `GET /v1/members/{member_id}` | `member.read` | implemented |  |
| `getOrganisationDevice` | `GET /internal/v1/vendor/organisations/{organisation_id}/devices/{device_id}` | `admin.device.read` | implemented |  |
| `getOwnerStatuses` | `GET /internal/v1/vendor/owner-statuses` | `admin.org.read` | implemented | Directory class: not audited per read (`x-vendor-audit: none`) |
| `getRole` | `GET /v1/roles/{role_id}` | `role.read` | implemented |  |
| `getSupportSession` | `GET /internal/v1/vendor/support-sessions/{support_session_id}` | `admin.support.session.start` | implemented |  |
| `getVendorJwks` | `GET /v1/vendor-jwks` | `public` | implemented |  |
| `getWipeOrder` | `GET /v1/devices/{device_id}/wipe-order` | `authenticated` | implemented |  |
| `listApprovalRequests` | `GET /v1/approval-requests` | `authenticated` | implemented |  |
| `listAuditEntries` | `GET /v1/audit-entries` | `audit.read` | implemented | Tenant chain; vendor and support access appear in it |
| `listBindings` | `GET /v1/bindings` | `authenticated` | implemented |  |
| `listDevices` | `GET /v1/devices` | `device.read` | implemented |  |
| `listMembers` | `GET /v1/members` | `member.read` | implemented |  |
| `listOrganisationDevices` | `GET /internal/v1/vendor/organisations/{organisation_id}/devices` | `admin.device.read` | implemented |  |
| `listOwnerInvitations` | `GET /internal/v1/vendor/organisations/{organisation_id}/owner-invitations` | `admin.org.read` | implemented |  |
| `listPermissions` | `GET /v1/permissions` | `authenticated` | implemented | Tenant-realm entries of the generated catalogue (tenancy and identity permissions only until products add theirs) |
| `listRevocations` | `GET /internal/v1/revocations` | `revocation.read` | implemented |  |
| `listRoles` | `GET /v1/roles` | `role.read` | implemented |  |
| `listVendorApprovals` | `GET /internal/v1/vendor/approvals` | `admin.approval.read` | implemented |  |
| `listVendorAuditEntries` | `GET /internal/v1/vendor/audit-entries` | `admin.audit.read_own` | implemented | Hash-chained vendor log written by identity; entries for tenancy-served actions arrive by event (tenancy side, not here) |
| `listVendorUsers` | `GET /internal/v1/vendor/users` | `admin.user.manage` | implemented |  |
| `lookupOrganisationsByOwnerMobile` | `POST /internal/v1/vendor/owner-lookups` | `admin.org.read` | implemented |  |
| `recordDeviceDrained` | `PUT /internal/v1/devices/{device_id}/drain` | `device.drain.record` | implemented |  |
| `refreshSession` | `POST /v1/tokens/refresh` | `public` | implemented |  |
| `registerDevice` | `POST /v1/devices` | `device.register` | implemented | Same series and `registration_unverified` limitation as activateDevice |
| `rejectBinding` | `PUT /v1/bindings/{binding_id}/rejection` | `authenticated` | implemented |  |
| `removeOwnerRole` | `DELETE /v1/members/{member_id}/owner-role` | `member.owner.assign` | implemented |  |
| `renewOwnerInvitation` | `POST /internal/v1/vendor/organisations/{organisation_id}/owner-invitations/{invitation_id}/renewals` | `admin.owner_invite.manage` | implemented |  |
| `renewSupportToken` | `POST /internal/v1/vendor/support-sessions/{support_session_id}/tokens` | `admin.support.session.start` | implemented |  |
| `renewVendorSession` | `POST /internal/v1/vendor/session-renewals` | `public` | implemented |  |
| `resetVendorUserTotp` | `POST /internal/v1/vendor/users/{vendor_user_id}/totp-resets` | `admin.user.manage` | implemented |  |
| `revokeDevice` | `PUT /v1/devices/{device_id}/revocation` | `device.revoke` | implemented |  |
| `revokeOrganisationDevice` | `PUT /internal/v1/vendor/organisations/{organisation_id}/devices/{device_id}/revocation` | `admin.device.revoke` | implemented |  |
| `setPin` | `PUT /v1/members/{member_id}/pin` | `authenticated` | implemented |  |
| `startSupportSession` | `POST /internal/v1/vendor/support-sessions` | `admin.support.session.start` | implemented |  |
| `switchMember` | `POST /v1/tokens/switch` | `authenticated` | implemented |  |
| `updateMember` | `PATCH /v1/members/{member_id}` | `member.manage` | implemented |  |
| `updateRole` | `PUT /v1/roles/{role_id}` | `role.manage` | implemented |  |
| `updateVendorUser` | `PATCH /internal/v1/vendor/users/{vendor_user_id}` | `admin.user.manage` | implemented |  |
| `verifyProof` | `POST /internal/v1/proof-verifications` | `proof.verify` | implemented | Session and approval proofs with the HMAC construction of ADR-0005 sections 7 and 8 |

## Not in this service (by design)

- Verifying tokens, step-up and the `strong_only` ceiling: `go-auth` (identity wires its Guard; `x-permission: authenticated` and `public` with `x-service-callers` are handled by explicit wrappers because the Guard has no mode for them).
- The document-series registry, organisation and outlet existence: `tenancy`.
- Quarantine upload, op-signature checks, the verdict table: sync gateway.
