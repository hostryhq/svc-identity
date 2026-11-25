# Operation status

Every `operationId` of `api-specs` `openapi/identity/v1` and whether it is implemented. "Implemented" means: a handler through
the service layer with its authorisation, and the shared contract run (status, media type, schema, idempotent replay), each operation in its example world
(`SeedWorld`), against both the double
and the Postgres assembly. Business rules have behaviour tests where the test strategy calls for them (see api/*_test.go). Nothing is silently missing: a limitation is written next to its operation.

Total: 76 operations, 76 implemented, 0 not yet (api-specs c92ca77).

| operationId | Route | x-permission | Status | Note |
|---|---|---|---|---|
| `activateDevice` | `POST /v1/device-activations` | `public` | implemented | Series codes issued by tenancy (generated client; tested against svc-tenancy's double) and carried in the pack. Registration not verified: registers with billing `none` and no series. Unknown outlet for a billing kind: 422. Tenancy down: 503, and the same activation resumes |
| `approveVendorApproval` | `PUT /internal/v1/vendor/approvals/{approval_id}/decision` | `admin.approval.decide` | implemented | The four kinds executed by tenancy and billing return a 5-minute `vendor_approval` grant (vendor-realm key, claims: approval, kind, organisation or none, requester, approver, subject hash); the approver may ask again for a fresh grant until the approval lapses. go-auth has no verifier for the grant yet |
| `assignOwnerRole` | `PUT /v1/members/{member_id}/owner-role` | `member.owner.assign` | implemented |  |
| `authorisePinReset` | `POST /v1/members/{member_id}/pin-reset-authorisations` | `member.pin.authorise` | implemented |  |
| `beginVendorSetup` | `POST /internal/v1/vendor/setup-sessions` | `public` | implemented |  |
| `cancelOwnerInvitation` | `PUT /internal/v1/vendor/organisations/{organisation_id}/owner-invitations/{invitation_id}/cancellation` | `admin.owner_invite.manage` | implemented |  |
| `cancelOwnerRecovery` | `PUT /v1/owner-recoveries/{recovery_id}/cancellation` | `authenticated` | implemented | Completion runs on a timer (`CompleteDueRecoveries`); recovery is off by default |
| `cancelVendorApproval` | `PUT /internal/v1/vendor/approvals/{approval_id}/cancellation` | `admin.approval.decide` | implemented |  |
| `checkPackHistory` | `POST /internal/v1/pack-history-checks` | `proof.verify` | implemented | `series_issued` is judged against the codes tenancy issued to the device and the pack held |
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
| `createVendorApproval` | `POST /internal/v1/vendor/approvals` | `admin.approval.create` | implemented | Kinds `sign_in_code` and `owner_recovery` are refused unless their switch is on (default off); `device_revoke_over_quota` always available; `org_suspend`, `org_reinstate`, `org_close` (organisation required) and `tax_rule_set_publish` (no organisation; rule set id, content hash, effective date) lapse after 24 hours. Organisation-less route: platform access row |
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
| `getDeviceOfflinePack` | `GET /v1/devices/{device_id}/offline-packs/latest` | `authenticated` | implemented | Series stored with the device (see activateDevice); a device that registered unverified is issued its series here once the registration is verified; `op_signing_public_key` comes from configuration |
| `getJwks` | `GET /v1/jwks` | `public` | implemented |  |
| `getMember` | `GET /v1/members/{member_id}` | `member.read` | implemented |  |
| `getOrganisationDevice` | `GET /internal/v1/vendor/organisations/{organisation_id}/devices/{device_id}` | `admin.device.read` | implemented |  |
| `getOwnerStatuses` | `GET /internal/v1/vendor/owner-statuses` | `admin.org.read` | implemented | Directory class: not audited per read (`x-vendor-audit: none`) |
| `getRole` | `GET /v1/roles/{role_id}` | `role.read` | implemented |  |
| `getSupportSession` | `GET /internal/v1/vendor/support-sessions/{support_session_id}` | `admin.support.session.start` | implemented |  |
| `getVendorApproval` | `GET /internal/v1/vendor/approvals/{approval_id}` | `admin.approval.read` | implemented | The requester or a user who may approve it; anyone else 404 |
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
| `registerDevice` | `POST /v1/devices` | `device.register` | implemented | Same series, unverified-registration and outlet check as activateDevice |
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

- Verifying tokens, step-up and the `strong_only` ceiling: `go-auth` (identity wires its Guard: `Authenticated`, `Public`+`Internal`+`Callers` and `PlatformAudit` policy modes, no wrappers). Organisation-less vendor routes write their access row to `platform_access_log` (no tenant column, no RLS) through `WithPlatformAuditedTx`; routes naming an organisation write `vendor_access_log` with that tenant.
- The document-series registry, organisation and outlet existence: `tenancy` (identity calls it through its client; kinds with no billing are not outlet-checked, there being no internal outlet-existence route).
- Quarantine upload, op-signature checks, the verdict table: sync gateway.

## Contract examples that cannot be true as written (run with a stated substitute, to be fixed in api-specs)

`contract.specGaps` in this repository. Each is a spec fix, not a service fix.

- `createDrainToken` has no `x-example-world` (base) but a drain token is given only to a revoked device: run in `device-revoked`.
- `clearPinLockout`, `authorisePinReset`, `deleteRoleAssignment` name Asha as target and the caller is Asha; an owner cannot administer herself (grant limit G4): run as a second owner.
- `updateVendorUser` patches Priya, who is the caller; a vendor user cannot deactivate herself: run as Arun.
- The base world says no session exists, yet the caller is "in a strong session" and several operations need the session record: a session and a binding not under caution are seeded in every world.
- `vendor-setup-pending` needs the setup to have begun for `completeVendorSetup` (`beginVendorSetup` fixes the secret); the world is seeded after a begin.
