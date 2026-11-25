package contract

import (
	"context"
	"fmt"
	"time"

	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/service"
)

// SeedWorld puts a fresh target into the named example world of the identity specification
// (info.x-example-worlds). It is the SeedWorld hook of the shared harness. The target is empty
// (each operation runs in its own fresh target), so a world is built, not reset.
//
// Tenancy's own double stands in for the series registry (Double.Tenancy) and is put into the matching
// world of its contract first, so the device and its series code (A7K) come from tenancy, not from a
// fake. Where a world's prose is silent the choice made here is stated in a comment; the one deliberate
// addition is the caller's own session and binding (the spec's base world says the caller is "in a
// strong session" yet lists no session): they are seeded in every world.
func (w *World) SeedWorld(ctx context.Context, name string) error {
	sd := w.D.Service.Seed()
	if g := specGaps[w.op]; g.World != "" {
		name = g.World
	}
	switch name {
	case "base", "otp-challenge-pending", "session-open", "device-revoked", "device-drained", "pin-reset-authorised", "pin-locked", "co-owner", "device-key-recovered",
		"approval-pending", "approval-approved", "owner-recovery-pending", "vendor-session-active", "support-session-active",
		"vendor-approval-pending", "vendor-approval-approved", "vendor-grant-approved", "activation-code-pending", "device-unregistered", "org-no-owner", "owner-invited", "vendor-setup-pending":
	default:
		return fmt.Errorf("contract: example world %q is not implemented", name)
	}
	if w.D.Tenancy != nil {
		tw := "series-issued" // the device has its series A7K
		if name == "device-unregistered" {
			tw = "registration-verified" // the device registers during the call and is issued its code then
		}
		if err := w.D.Tenancy.SeedWorld(ctx, tw); err != nil {
			return err
		}
	}
	tenant := name != "org-no-owner" && name != "owner-invited"
	if tenant {
		if err := w.seedTenant(ctx, sd, name != "device-unregistered"); err != nil {
			return err
		}
	} else if err := sd.OwnerCount(ctx, Org, 0); err != nil {
		return err
	}
	if err := w.seedVendor(ctx, sd, name == "vendor-setup-pending"); err != nil {
		return err
	}
	if err := sd.Nonce(ctx, "nonce_example_01"); err != nil {
		return err
	}
	return w.delta(ctx, sd, name)
}

// seedTenant builds the organisation's people, roles and (when device) device 4a5e with its pack history.
func (w *World) seedTenant(ctx context.Context, sd *service.Seeder, device bool) error {
	if err := sd.BuiltInOwnerRole(ctx, Org, OwnerRole); err != nil {
		return err
	}
	for _, r := range []struct {
		id, name string
		perms    []string
	}{
		{CashierID, "Cashier", []string{"outlet.read", "device.read"}},
		{WaiterID, "Waiter", []string{"outlet.read"}},
	} {
		if err := sd.Role(ctx, Org, r.id, r.name, r.perms); err != nil {
			return err
		}
	}
	if err := sd.Member(ctx, Org, service.SeedMember{ID: Asha, Name: "Asha", Mobile: AshaMobile, Assignments: []service.SeedAssignment{
		{ID: AshaOwner, RoleID: OwnerRole}, {ID: AshaCash, RoleID: CashierID, Outlets: []string{Outlet}}}}); err != nil {
		return err
	}
	if err := sd.Member(ctx, Org, service.SeedMember{ID: Ravi, Name: "Ravi", Mobile: RaviMobile, Assignments: []service.SeedAssignment{{ID: RaviCash, RoleID: CashierID}}}); err != nil {
		return err
	}
	owners := 1
	if specGaps[w.op].ExtraOwner {
		owners = 2
		if err := sd.Member(ctx, Org, service.SeedMember{ID: Mohan, Name: "Mohan", Mobile: MohanMobile, Assignments: []service.SeedAssignment{{ID: MohanAssign, RoleID: OwnerRole}}}); err != nil {
			return err
		}
		macct, err := sd.Account(ctx, Org, Mohan, MohanMobile)
		if err != nil {
			return err
		}
		if err := sd.Binding(ctx, MohanBinding, macct, MohanDevice, ExampleKey, time.Time{}); err != nil {
			return err
		}
		if err := sd.Session(ctx, Org, MohanSession, Mohan, macct, MohanDevice, MohanBinding); err != nil {
			return err
		}
	}
	if err := sd.OwnerCount(ctx, Org, owners); err != nil {
		return err
	}
	acct, err := sd.Account(ctx, Org, Asha, AshaMobile)
	if err != nil {
		return err
	}
	w.acct = acct
	raviAcct, err := sd.Account(ctx, Org, Ravi, RaviMobile)
	if err != nil {
		return err
	}
	w.raviAcct = raviAcct
	// Asha has a PIN (pin_v 2): set twice, as the pack's verifier version is the count of changes.
	for i := 0; i < 2; i++ {
		if _, err := sd.PinFor(ctx, Org, Asha, "482916"); err != nil {
			return err
		}
	}
	// The caller's own session on a binding that is not under caution, so the operations the spec
	// shows as allowed to Asha are not refused for caution.
	if err := sd.Binding(ctx, BindingO, acct, DeviceO, ExampleKey, time.Time{}); err != nil {
		return err
	}
	if err := sd.Session(ctx, Org, Session, Asha, acct, DeviceO, BindingO); err != nil {
		return err
	}
	if !device {
		return nil
	}
	d := service.SeedDevice{ID: DeviceID, Outlet: Outlet, Kind: "pos", Name: "Counter 1", KeyProt: "hardware", State: "active", Key: ExampleKey, LastSeen: w.D.Clock.Now().Add(5 * time.Minute)}
	if err := sd.Device(ctx, Org, d); err != nil {
		return err
	}
	// The binding 4a6e of Asha on the device is under caution until 2026-12-08.
	if err := sd.Binding(ctx, BindingX, acct, DeviceID, ExampleKey, w.D.Clock.Now().Add(14*24*time.Hour)); err != nil {
		return err
	}
	// Pack 7 listed Asha, who then held these two permissions (getPackGrants example).
	return sd.PackHistory(ctx, Org, DeviceID, 7, []string{Asha}, []string{"A7K"}, map[string][]string{Asha: {"bill.void", "order.create"}})
}

func (w *World) seedVendor(ctx context.Context, sd *service.Seeder, priyaSetup bool) error {
	secret := []byte("0123456789abcdefghij")
	const pw = "correct-horse-battery-staple"
	if priyaSetup {
		if err := sd.SetupPending(ctx, Vendor, "staff@example.invalid", "Priya", "support", "setup_example"); err != nil {
			return err
		}
	} else if err := sd.VendorUser(ctx, Vendor, "staff@example.invalid", "Priya", "support", pw, secret, 30*24*time.Hour); err != nil {
		return err
	}
	return sd.VendorUser(ctx, Vendor2, "admin@example.invalid", "Arun", "platform_admin", pw, secret, 30*24*time.Hour)
}

// delta adds what the world has over the base.
func (w *World) delta(ctx context.Context, sd *service.Seeder, name string) error {
	switch name {
	case "device-unregistered":
		return sd.Activation(ctx, Org, Activ, "7QK3M9XD", Outlet, "pos", Asha)
	case "otp-challenge-pending":
		return sd.Challenge(ctx, Chall, AshaMobile, DeviceID, ExampleKey, "482915")
	case "session-open":
		// Asha's session 4a5d is on the example device (the refresh and device grants check it).
		if err := sd.Session(ctx, Org, Session, Asha, w.acct, DeviceID, BindingX); err != nil {
			return err
		}
		return sd.Refresh(ctx, Org, Session, "tok_example_refresh")
	case "device-revoked":
		w.D.Clock.Advance(10 * time.Minute) // revoked 13:15:11
		return sd.RevokeDevice(ctx, Org, DeviceID, "lost", Vendor)
	case "device-key-recovered":
		// Device 4a5e lost its key; 4a5f (pos, same outlet, a key of its own) adopted it under recovery 4aa2, approved by Asha
		// at 13:15:11. The old device's drain is not recorded, so the recovery is open.
		w.D.Clock.Advance(10 * time.Minute)
		if err := sd.Device(ctx, Org, service.SeedDevice{ID: NewDeviceID, Outlet: Outlet, Kind: "pos", Name: "Counter 2", KeyProt: "hardware", State: "active",
			Key: crypto.ToJWK(&NewKey().PublicKey)}); err != nil {
			return err
		}
		return sd.KeyLossRecovery(ctx, Org, RecoveryID, DeviceID, NewDeviceID, Asha)
	case "device-drained":
		w.D.Clock.Advance(10 * time.Minute)
		if err := sd.RevokeDevice(ctx, Org, DeviceID, "lost", Vendor); err != nil {
			return err
		}
		if err := sd.DrainDevice(ctx, Org, DeviceID, map[string]int{"device-ops": 1842}); err != nil {
			return err
		}
		w.D.Clock.Advance(15 * time.Minute) // the wipe order is issued 15 minutes after the drain
		return nil
	case "vendor-setup-pending":
		// The setup challenge exists: Priya has been shown her authenticator secret (beginVendorSetup is
		// repeatable, completeVendorSetup needs it).
		_, err := w.D.Service.BeginVendorSetup(ctx, gen.BeginVendorSetup{SetupToken: "setup_example"})
		return err
	case "pin-reset-authorised":
		return sd.PinReset(ctx, Org, Reset, Asha)
	case "pin-locked":
		return sd.PinLocked(ctx, Org, DeviceID, Asha)
	case "co-owner":
		return sd.AssignRole(ctx, Org, Ravi, CoOwner, OwnerRole)
	case "approval-pending", "approval-approved":
		// Ravi files it from his own session; Asha (the owner) decides.
		if err := sd.Binding(ctx, RaviBinding, w.raviAcct, RaviDevice, ExampleKey, time.Time{}); err != nil {
			return err
		}
		if err := sd.Session(ctx, Org, RaviSession, Ravi, w.raviAcct, RaviDevice, RaviBinding); err != nil {
			return err
		}
		if err := sd.ApprovalRequest(ctx, Org, ApprReq, Ravi, w.raviAcct, RaviSession, "createMember"); err != nil {
			return err
		}
		if name == "approval-approved" {
			return sd.ApproveRequest(ctx, Org, ApprReq, Asha)
		}
	case "owner-recovery-pending":
		return sd.VendorApproval(ctx, service.SeedApproval{ID: Recovery, Kind: "owner_recovery", Requester: Vendor, Approver: Vendor2, Org: Org, Mobile: AshaMobile,
			NewMobile: "+919876500099", State: "approved", CompletesAt: w.D.Clock.Now().Add(23 * time.Hour)})
	case "owner-invited":
		return sd.OwnerInvitationWithID(ctx, Invite, Org, AshaMobile, "Asha")
	case "vendor-session-active":
		return sd.VendorSessionRec(ctx, "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a7b", Vendor, "renew_example")
	case "support-session-active":
		return sd.SupportSession(ctx, service.SeedSupport{ID: Support, UserID: Vendor, Org: Org, Ticket: "SUP-2041"})
	case "activation-code-pending":
		return sd.Activation(ctx, Org, Activ, "7QK3M9XD", Outlet, "pos", Asha)
	case "vendor-grant-approved":
		// An organisation suspension Priya requested and Arun approved; the grant it yielded has lapsed or was refused.
		return sd.VendorApproval(ctx, service.SeedApproval{ID: Appr, Kind: "org_suspend", Requester: Vendor, Approver: Vendor2, Org: Org, State: "approved", Lifetime: 24 * time.Hour})
	case "vendor-approval-pending", "vendor-approval-approved":
		state, approver := "pending", ""
		if name == "vendor-approval-approved" {
			state, approver = "approved", Vendor2
		}
		return sd.VendorApproval(ctx, service.SeedApproval{ID: Appr, Kind: "sign_in_code", Requester: Vendor, Approver: approver, Org: Org, Mobile: AshaMobile, State: state})
	}
	return nil
}
