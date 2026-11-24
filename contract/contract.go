// Package contract runs the shared contract suite of api-specs (contract-tests/identity, harness
// github.com/hostryhq/api-specs/contracttest) against the identity service and its double.
//
// The harness is example-driven and stateless: every operation is called with the examples of the
// specification as its input, so the target must be seeded to make each example resolvable. This
// package seeds a fresh target per operation (so an operation that revokes a device cannot break
// the next one), runs the harness for that operation only and reports its failures. The same
// scenarios run against the in-memory double and against the service assembled over PostgreSQL.
package contract

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"sort"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/svc-identity/double"
	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/service"
)

// Example identifiers of the specification.
const (
	Org      = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a60"
	Outlet   = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a61"
	Owner    = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a62"
	Asha     = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a64"
	RoleID   = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a65"
	DeviceID = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5e"
	Session  = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5d"
	Chall    = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"
	Assign   = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a6f"
	BindingX = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a6e"
	BindingO = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a6c"
	ApprReq  = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a70"
	Reset    = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a76"
	Vendor   = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a66"
	Vendor2  = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a78"
	Invite   = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a67"
	Support  = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a68"
	Appr     = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a6d"

	AshaMobile  = "+919876543210"
	OwnerMobile = "+919876500062"
)

// ExampleKey is the public key of the examples.
var ExampleKey = crypto.JWK{Kty: "EC", Crv: "P-256", X: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", Y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}

// World is one target of the suite: a double or the real assembly, with tokens for each caller class.
type World struct {
	D         *double.Double
	OwnerAcct string // account of the caller (the owner)
}

// Scenario describes what one operation needs.
type Scenario struct {
	// Class selects the caller: "tenant" (owner token), "sync" (service token), "vendor" (vendor
	// token and admin service token), "drain" (drain token of the example device) or "public".
	Class string
	// Seed adds the state this operation's examples need, on top of the common state.
	Seed func(ctx context.Context, w *World, sd *service.Seeder) error
	// Config adjusts the service configuration (for example switching a vendor-assisted flow on).
	Config func(*service.Config)
	// Skip, when set, is the reason the operation is not run; it is reported, never silent.
	Skip string
}

// Header returns the request headers of a class for a world.
func (w *World) Header(class string) http.Header {
	h := http.Header{}
	org := ids.ID(Org)
	switch class {
	case "tenant":
		h.Set("Authorization", "Bearer "+w.tenantToken())
	case "drain":
		now := w.D.Clock.Now()
		t, _ := w.D.Signer.Access(auth.Claims{Subject: "device:" + DeviceID, Type: auth.TypeDrain, TenantID: Org, DeviceID: DeviceID, IssuedAt: now.Unix(),
			ExpiresAt: now.Add(5 * time.Minute).Unix(), JTI: string(w.D.Clock.IDs().New())})
		h.Set("Authorization", "Bearer "+t)
	case "sync":
		h.Set("Hostry-Service-Token", w.D.ServiceToken("sync", org))
	case "vendor":
		now := w.D.Clock.Now()
		t, _ := w.D.Signer.Vendor(auth.Claims{Subject: Vendor2, Type: auth.TypeUser, SessionID: "vendor-session", AMR: []string{"otp"}, AuthTime: now.Unix(),
			Grants: []auth.Grant{{Outlets: []string{"*"}, Perms: service.VendorPermissions("platform_admin")}}, IssuedAt: now.Unix(), ExpiresAt: now.Add(15 * time.Minute).Unix(),
			JTI: string(w.D.Clock.IDs().New())})
		h.Set("Authorization", "Bearer "+t)
		h.Set("Hostry-Service-Token", w.D.ServiceToken("admin", ""))
	case "public":
		h.Set("Hostry-Service-Token", w.D.ServiceToken("admin", "")) // vendor sign-in routes need the admin service token; others ignore it
	}
	return h
}

func (w *World) tenantToken() string {
	now := w.D.Clock.Now()
	t, _ := w.D.Signer.Access(auth.Claims{Subject: Owner, Type: auth.TypeUser, TenantID: Org, DeviceID: DeviceID, SessionID: Session, AMR: []string{auth.AMROTP},
		AuthTime: now.Unix(), Grants: authOwner(), IssuedAt: now.Unix(), ExpiresAt: now.Add(15 * time.Minute).Unix(), JTI: string(w.D.Clock.IDs().New())})
	return t
}

func authOwner() []auth.Grant { return []auth.Grant{{Outlets: []string{"*"}, Perms: []string{"*"}}} }

// Common seeds the state every operation shares: the organisation with its owner (the caller), the
// caller's session and binding, Asha (a cashier with a PIN, found by her number) and the cashier role.
func Common(ctx context.Context, w *World) error {
	sd := w.D.Service.Seed()
	acct, err := sd.Owner(ctx, Org, Owner, "Owner", OwnerMobile)
	if err != nil {
		return err
	}
	w.OwnerAcct = acct
	if err := sd.Binding(ctx, BindingO, acct, DeviceID, ExampleKey, time.Time{}); err != nil {
		return err
	}
	if err := sd.Session(ctx, Org, Session, Owner, acct, DeviceID, BindingO); err != nil {
		return err
	}
	if err := sd.Role(ctx, Org, RoleID, "Cashier", []string{"member.read", "device.read"}); err != nil {
		return err
	}
	if err := sd.Member(ctx, Org, service.SeedMember{ID: Asha, Name: "Asha", Mobile: AshaMobile, Assignments: []service.SeedAssignment{{ID: Assign, RoleID: RoleID}}}); err != nil {
		return err
	}
	if _, err := sd.Account(ctx, Org, Asha, AshaMobile); err != nil {
		return err
	}
	return nil
}

// NewKey returns a fresh device key (for scenarios that need to sign).
func NewKey() *ecdsa.PrivateKey {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return k
}

// Operations returns the sorted operationIds of the scenario table.
func Operations() []string {
	out := make([]string, 0, len(Scenarios))
	for op := range Scenarios {
		out = append(out, op)
	}
	sort.Strings(out)
	return out
}
