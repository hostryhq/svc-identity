// Package contract runs the shared contract suite of api-specs (harness
// github.com/hostryhq/api-specs/contracttest) against the identity service and its double.
//
// The harness is example-driven: every operation is called with the examples of the specification as
// its input. An example is true only in some state of the world, so the spec declares named example
// worlds (info.x-example-worlds) and each operation says which one it assumes (x-example-world, default
// base). The harness calls SeedWorld before each operation; this package implements it (worlds.go) for
// the in-memory double and for the service assembled over PostgreSQL, and runs each operation in its own
// fresh target so one operation's effect (a device revoked, a code used) cannot break the next. Nothing
// is skipped: every operation of the specification runs in its world.
package contract

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/svc-identity/double"
	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/service"
)

// Example identifiers of the specification (the suffixes of its example worlds).
const (
	Org       = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a60"
	Outlet    = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a61"
	Asha      = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a64"
	Ravi      = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a9e"
	CashierID = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a65"
	WaiterID  = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a9b"
	OwnerRole = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a9a"
	DeviceID  = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5e"
	Session   = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5d"
	Chall     = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"
	AshaOwner = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a6f" // Asha's assignment of the Owner role
	AshaCash  = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a8b" // Asha's assignment of the Cashier role
	RaviCash  = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a9f"
	CoOwner   = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a8d"
	Recovery  = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a99" // owner recovery (the vendor approval id)
	BindingX  = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a6e" // the device binding under caution
	BindingO  = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a6c" // the caller's own binding, not under caution
	DeviceO   = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a7a" // the device of that binding
	ApprReq   = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a70"
	Reset     = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a76"
	Revoked   = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a77"
	Vendor    = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a66" // Priya, support
	Vendor2   = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a78" // Arun, platform_admin
	Invite    = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a67"
	Support   = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a68"
	Appr      = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a6d"
	Activ     = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a75"

	// Ravi's own session, for the worlds in which he is the caller.
	RaviSession = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c"
	RaviBinding = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a7c"
	RaviDevice  = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a7d"
	// VendorSess is the session of the vendor user token (the vendor-session-active world stores it).
	VendorSess = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a7b"

	// Mohan is a second owner, added only where an example has the caller administer herself (see specGaps).
	Mohan        = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4aa5"
	MohanAssign  = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4aa6"
	MohanSession = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4aa7"
	MohanBinding = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4aa8"
	MohanDevice  = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4aa9"
	MohanMobile  = "+919876543213"

	AshaMobile = "+919876543210"
	RaviMobile = "+919876543211"
)

// ExampleKey is the public key of the examples.
var ExampleKey = crypto.JWK{Kty: "EC", Crv: "P-256", X: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", Y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}

// World is one target of the suite: a double, or the real assembly over PostgreSQL wrapped in one.
type World struct {
	D        *double.Double
	acct     string // Asha's account
	raviAcct string // Ravi's account
	op       string // the operation being run (set by Run)
}

// specGap is where the specification's example cannot be true as written, and what this run does
// instead. They are reported to the contract owner; each is a fix to the spec, not to the service.
type specGap struct {
	World      string // run in this world instead of the declared one
	ExtraOwner bool   // the caller is a second owner (the example makes the caller administer herself, which grant limit G4 refuses)
	VendorUser string // the caller is this vendor user (the example has the caller change or deactivate herself)
}

var specGaps = map[string]specGap{
	// base world, but a drain token is only given to a revoked device
	"createDrainToken": {World: "device-revoked"},
	// the examples target Asha, who is the caller: an owner cannot administer herself
	"clearPinLockout":      {ExtraOwner: true},
	"authorisePinReset":    {ExtraOwner: true},
	"deleteRoleAssignment": {ExtraOwner: true},
	// the example patches Priya, who is the caller: a vendor user cannot deactivate herself
	"updateVendorUser": {VendorUser: Vendor2},
	// the base world holds no activation code, and the spec names code 4a75 in these examples
	"listActivationCodes":  {World: "activation-code-pending"},
	"revokeActivationCode": {World: "activation-code-pending"},
	// the world named (vendor-approval-approved) is a sign-in code approved by Arun with Priya as caller; the
	// operation needs a grant kind and its approver as the caller, so run on an approved org_suspend as Arun
	"issueVendorApprovalGrant": {World: "vendor-grant-approved", VendorUser: Vendor2},
}

// Header returns the request headers of a caller class for the world being exercised. Classes:
// "tenant" (Asha, owner, in a strong session), "sync" (service token of the sync gateway), "vendor"
// (a vendor user's token and the admin service token), "drain" (drain token of the example device) and
// "public" (no user credential; the admin service token, which only the vendor sign-in routes read).
func (w *World) Header(class, world string) http.Header {
	h := http.Header{}
	org := ids.ID(Org)
	switch class {
	case "tenant":
		h.Set("Authorization", "Bearer "+w.tenantToken(world))
	case "drain":
		now := w.D.Clock.Now()
		t, _ := w.D.Signer.Access(auth.Claims{Subject: "device:" + DeviceID, Type: auth.TypeDrain, TenantID: Org, DeviceID: DeviceID, IssuedAt: now.Unix(),
			ExpiresAt: now.Add(5 * time.Minute).Unix(), JTI: string(w.D.Clock.IDs().New())})
		h.Set("Authorization", "Bearer "+t)
	case "sync":
		h.Set("Hostry-Service-Token", w.D.ServiceToken("sync", org))
	case "vendor":
		caller := Vendor
		if world == "vendor-approval-pending" {
			caller = Vendor2
		}
		if g := specGaps[w.op]; g.VendorUser != "" {
			caller = g.VendorUser
		}
		now := w.D.Clock.Now()
		// The token carries every admin permission: the specification names the caller by person, and
		// the permission each operation needs is the operation's own (several need more than a
		// support user holds).
		t, _ := w.D.Signer.Vendor(auth.Claims{Subject: caller, Type: auth.TypeUser, SessionID: VendorSess, AMR: []string{"otp"}, AuthTime: now.Unix(),
			Grants: []auth.Grant{{Outlets: []string{"*"}, Perms: service.VendorPermissions("platform_admin")}}, IssuedAt: now.Unix(), ExpiresAt: now.Add(15 * time.Minute).Unix(),
			JTI: string(w.D.Clock.IDs().New())})
		h.Set("Authorization", "Bearer "+t)
		h.Set("Hostry-Service-Token", w.D.ServiceToken("admin", ""))
	case "public":
		h.Set("Hostry-Service-Token", w.D.ServiceToken("admin", ""))
	}
	return h
}

func (w *World) tenantToken(world string) string {
	now := w.D.Clock.Now()
	subject, sid, device, grants := Asha, Session, DeviceO, []auth.Grant{{Outlets: []string{"*"}, Perms: []string{"*"}}}
	if specGaps[w.op].ExtraOwner {
		subject, sid, device = Mohan, MohanSession, MohanDevice
	}
	if world == "approval-approved" { // the requester, Ravi, collects the token
		subject, sid, device, grants = Ravi, RaviSession, RaviDevice, []auth.Grant{{Outlets: []string{"*"}, Perms: []string{"outlet.read", "device.read"}}}
	}
	t, _ := w.D.Signer.Access(auth.Claims{Subject: subject, Type: auth.TypeUser, TenantID: Org, DeviceID: device, SessionID: sid, AMR: []string{auth.AMROTP},
		AuthTime: now.Unix(), Grants: grants, IssuedAt: now.Unix(), ExpiresAt: now.Add(15 * time.Minute).Unix(), JTI: string(w.D.Clock.IDs().New())})
	return t
}

// NewKey returns a fresh device key (for scenarios that need to sign).
func NewKey() *ecdsa.PrivateKey {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return k
}
