package contract

import (
	"context"
	"time"

	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/service"
)

type seedFn = func(ctx context.Context, w *World, sd *service.Seeder) error

func seq(fs ...seedFn) seedFn {
	return func(ctx context.Context, w *World, sd *service.Seeder) error {
		for _, f := range fs {
			if err := f(ctx, w, sd); err != nil {
				return err
			}
		}
		return nil
	}
}

func posDevice(state string, extra func(*service.SeedDevice)) seedFn {
	return func(ctx context.Context, w *World, sd *service.Seeder) error {
		d := service.SeedDevice{ID: DeviceID, Outlet: Outlet, Kind: "pos", Name: "Counter 1", KeyProt: "hardware", State: state, Key: ExampleKey, LastSeen: w.D.Clock.Now().Add(5 * time.Minute)}
		if extra != nil {
			extra(&d)
		}
		return sd.Device(ctx, Org, d)
	}
}

var activeDevice = posDevice("active", nil)

// pinReady gives Asha a PIN (pin_v 2) and records pack 7 as issued to the example device.
var pinReady seedFn = func(ctx context.Context, w *World, sd *service.Seeder) error {
	for i := 0; i < 2; i++ {
		if _, err := sd.PinFor(ctx, Org, Asha, "482916"); err != nil {
			return err
		}
	}
	return sd.PackHistory(ctx, Org, DeviceID, 7, []string{Asha}, []string{"A7"})
}

func vendorUsers(extra ...seedFn) seedFn {
	return func(ctx context.Context, w *World, sd *service.Seeder) error {
		secret := []byte("0123456789abcdefghij")
		const pw = "correct-horse-battery-staple"
		if err := sd.VendorUser(ctx, Vendor, "staff@example.invalid", "Priya", "support", pw, secret, 30*24*time.Hour); err != nil {
			return err
		}
		if err := sd.VendorUser(ctx, Vendor2, "admin@example.invalid", "Ravi", "platform_admin", pw, secret, 30*24*time.Hour); err != nil {
			return err
		}
		if err := sd.VendorUser(ctx, "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a79", "admin2@example.invalid", "Mina", "platform_admin", pw, secret, 30*24*time.Hour); err != nil {
			return err
		}
		return seq(extra...)(ctx, w, sd)
	}
}

func approval(kind, state, requester, approver string, completes time.Duration) seedFn {
	return func(ctx context.Context, w *World, sd *service.Seeder) error {
		p := service.SeedApproval{ID: Appr, Kind: kind, Requester: requester, Approver: approver, Org: Org, Mobile: AshaMobile, State: state}
		if kind == "owner_recovery" {
			p.Mobile, p.NewMobile = OwnerMobile, "+919876500099"
			p.CompletesAt = w.D.Clock.Now().Add(completes)
		}
		return sd.VendorApproval(ctx, p)
	}
}

// Scenarios is the per-operation setup of the contract run. Every operationId of the identity
// contract has an entry; an entry with Skip is reported as skipped with its reason.
var Scenarios = map[string]Scenario{
	// ---- sessions and tokens ----
	"createOtpChallenge": {Class: "public"},
	"createSession": {Class: "public", Seed: func(ctx context.Context, w *World, sd *service.Seeder) error {
		return sd.Challenge(ctx, Chall, AshaMobile, DeviceID, ExampleKey, "482915")
	}},
	"endSession": {Class: "tenant"},
	"refreshSession": {Class: "public", Seed: func(ctx context.Context, w *World, sd *service.Seeder) error {
		return sd.Refresh(ctx, Org, Session, "tok_example_refresh")
	}},
	"switchMember": {Class: "tenant", Seed: func(ctx context.Context, w *World, sd *service.Seeder) error {
		_, err := sd.Account(ctx, Org, Asha, OwnerMobile) // Asha becomes a second membership of the caller's account
		return err
	}},
	"createDeviceToken": {Class: "public", Seed: seq(activeDevice, pinReady)},
	"createDrainToken":  {Class: "public", Seed: posDevice("revoked", nil)},
	"createDeviceNonce": {Class: "public"},
	"getJwks":           {Class: "public"},
	"getVendorJwks":     {Class: "public"},

	// ---- devices ----
	"createActivationCode": {Class: "tenant"},
	"activateDevice": {Class: "public", Seed: func(ctx context.Context, w *World, sd *service.Seeder) error {
		if err := sd.Nonce(ctx, "nonce_example_01"); err != nil {
			return err
		}
		return sd.Activation(ctx, Org, "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a75", "7QK3M9XD", Outlet, "pos")
	}},
	"registerDevice": {Class: "tenant", Seed: func(ctx context.Context, w *World, sd *service.Seeder) error {
		return sd.Nonce(ctx, "nonce_example_01")
	}},
	"listDevices":          {Class: "tenant", Seed: activeDevice},
	"getDevice":            {Class: "tenant", Seed: activeDevice},
	"revokeDevice":         {Class: "tenant", Seed: activeDevice},
	"getDeviceOfflinePack": {Class: "tenant", Seed: seq(activeDevice, pinReady)},
	"getWipeOrder": {Class: "drain", Seed: posDevice("drained", func(d *service.SeedDevice) {
		d.DrainedAt = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
		d.DrainedThrough = map[string]int{"device-ops": 1842}
	})},

	// ---- members, roles, PIN ----
	"listMembers":       {Class: "tenant"},
	"createMember":      {Class: "tenant"},
	"getMember":         {Class: "tenant"},
	"updateMember":      {Class: "tenant"},
	"clearPinLockout":   {Class: "tenant"},
	"authorisePinReset": {Class: "tenant"},
	"setPin": {Class: "tenant", Seed: func(ctx context.Context, w *World, sd *service.Seeder) error {
		return sd.PinReset(ctx, Org, Reset, Asha)
	}},
	"createRoleAssignment": {Class: "tenant"},
	"deleteRoleAssignment": {Class: "tenant"},
	"assignOwnerRole":      {Class: "tenant"},
	"removeOwnerRole":      {Class: "tenant"},
	"listRoles":            {Class: "tenant"},
	"createRole":           {Class: "tenant"},
	"getRole":              {Class: "tenant"},
	"updateRole":           {Class: "tenant"},
	"deleteRole": {Class: "tenant", Seed: func(ctx context.Context, w *World, sd *service.Seeder) error {
		return sd.Member(ctx, Org, service.SeedMember{ID: Asha, Name: "Asha", Mobile: AshaMobile}) // unassigned, so the role can go
	}},
	"listPermissions":  {Class: "tenant"},
	"listAuditEntries": {Class: "tenant"},

	// ---- new-device caution ----
	"createApprovalRequest": {Class: "tenant"},
	"listApprovalRequests":  {Class: "tenant"},
	"getApprovalRequest": {Class: "tenant", Seed: func(ctx context.Context, w *World, sd *service.Seeder) error {
		return sd.ApprovalRequest(ctx, Org, ApprReq, Owner, w.OwnerAcct, Session, "createMember")
	}},
	"decideApprovalRequest": {Class: "tenant", Seed: func(ctx context.Context, w *World, sd *service.Seeder) error {
		return sd.ApprovalRequest(ctx, Org, ApprReq, Owner, w.OwnerAcct, Session, "createMember")
	}},
	"listBindings": {Class: "tenant"},
	"rejectBinding": {Class: "tenant", Seed: func(ctx context.Context, w *World, sd *service.Seeder) error {
		return sd.Binding(ctx, BindingX, w.OwnerAcct, "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a7a", ExampleKey, time.Time{})
	}},
	"cancelOwnerRecovery": {Class: "tenant", Seed: approval("owner_recovery", "approved", Vendor, Vendor2, 23*time.Hour)},

	// ---- internal (sync gateway) ----
	"listRevocations": {Class: "sync", Seed: func(ctx context.Context, w *World, sd *service.Seeder) error {
		return sd.Revocation(ctx, "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a77", Org, "device", DeviceID)
	}},
	"recordDeviceDrained": {Class: "sync", Seed: posDevice("revoked", nil)},
	"verifyProof":         {Class: "sync", Seed: seq(activeDevice, pinReady)},
	"checkPackHistory":    {Class: "sync", Seed: seq(activeDevice, pinReady)},

	// ---- vendor realm ----
	"createVendorSession": {Class: "public", Seed: vendorUsers()},
	"renewVendorSession": {Class: "public", Seed: vendorUsers(func(ctx context.Context, w *World, sd *service.Seeder) error {
		return sd.VendorSessionRec(ctx, "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a7b", Vendor, "renew_example")
	})},
	"endVendorSession": {Class: "vendor", Seed: vendorUsers(func(ctx context.Context, w *World, sd *service.Seeder) error {
		return sd.VendorSessionRec(ctx, "vendor-session", Vendor2, "handle")
	})},
	"beginVendorSetup": {Class: "public", Seed: func(ctx context.Context, w *World, sd *service.Seeder) error {
		return sd.SetupPending(ctx, Vendor, "staff@example.invalid", "Priya", "support", "setup_example")
	}},
	"completeVendorSetup": {Class: "public", Seed: func(ctx context.Context, w *World, sd *service.Seeder) error {
		if err := sd.SetupPending(ctx, Vendor, "staff@example.invalid", "Priya", "support", "setup_example"); err != nil {
			return err
		}
		_, err := w.D.Service.BeginVendorSetup(ctx, gen.BeginVendorSetup{SetupToken: "setup_example"})
		return err
	}},
	"listVendorUsers":                  {Class: "vendor", Seed: vendorUsers()},
	"createVendorUser":                 {Class: "vendor", Seed: vendorUsers()},
	"updateVendorUser":                 {Class: "vendor", Seed: vendorUsers()},
	"resetVendorUserTotp":              {Class: "vendor", Seed: vendorUsers()},
	"listVendorAuditEntries":           {Class: "vendor", Seed: vendorUsers()},
	"lookupOrganisationsByOwnerMobile": {Class: "vendor", Seed: vendorUsers()},
	"getOwnerStatuses":                 {Class: "vendor", Seed: vendorUsers()},
	"createOwnerInvitation":            {Class: "vendor", Seed: vendorUsers(func(ctx context.Context, w *World, sd *service.Seeder) error { return sd.OwnerCount(ctx, Org, 0) })},
	"listOwnerInvitations": {Class: "vendor", Seed: vendorUsers(func(ctx context.Context, w *World, sd *service.Seeder) error {
		return sd.OwnerInvitationWithID(ctx, Invite, Org, AshaMobile, "Asha")
	})},
	"renewOwnerInvitation": {Class: "vendor", Seed: vendorUsers(func(ctx context.Context, w *World, sd *service.Seeder) error {
		return sd.OwnerInvitationWithID(ctx, Invite, Org, AshaMobile, "Asha")
	})},
	"cancelOwnerInvitation": {Class: "vendor", Seed: vendorUsers(func(ctx context.Context, w *World, sd *service.Seeder) error {
		return sd.OwnerInvitationWithID(ctx, Invite, Org, AshaMobile, "Asha")
	})},
	"listOrganisationDevices":  {Class: "vendor", Seed: vendorUsers(activeDevice)},
	"getOrganisationDevice":    {Class: "vendor", Seed: vendorUsers(activeDevice)},
	"revokeOrganisationDevice": {Class: "vendor", Seed: vendorUsers(activeDevice)},
	"startSupportSession":      {Class: "vendor", Seed: vendorUsers()},
	"getSupportSession": {Class: "vendor", Seed: vendorUsers(func(ctx context.Context, w *World, sd *service.Seeder) error {
		return sd.SupportSession(ctx, service.SeedSupport{ID: Support, UserID: Vendor2, Org: Org, Ticket: "SUP-2041"})
	})},
	"renewSupportToken": {Class: "vendor", Seed: vendorUsers(func(ctx context.Context, w *World, sd *service.Seeder) error {
		return sd.SupportSession(ctx, service.SeedSupport{ID: Support, UserID: Vendor2, Org: Org, Ticket: "SUP-2041"})
	})},
	"endSupportSession": {Class: "vendor", Seed: vendorUsers(func(ctx context.Context, w *World, sd *service.Seeder) error {
		return sd.SupportSession(ctx, service.SeedSupport{ID: Support, UserID: Vendor2, Org: Org, Ticket: "SUP-2041"})
	})},
	"createVendorApproval":  {Class: "vendor", Config: func(c *service.Config) { c.SignInCodeEnabled = true }, Seed: vendorUsers()},
	"listVendorApprovals":   {Class: "vendor", Seed: vendorUsers(approval("sign_in_code", "pending", Vendor, "", 0))},
	"approveVendorApproval": {Class: "vendor", Config: func(c *service.Config) { c.SignInCodeEnabled = true }, Seed: vendorUsers(approval("sign_in_code", "pending", Vendor, "", 0))},
	"claimCodeHalf":         {Class: "vendor", Config: func(c *service.Config) { c.SignInCodeEnabled = true }, Seed: vendorUsers(approval("sign_in_code", "approved", Vendor2, Vendor, 0))},
	"cancelVendorApproval":  {Class: "vendor", Seed: vendorUsers(approval("owner_recovery", "approved", Vendor, Vendor2, 23*time.Hour))},
}
