package api_test

import (
	"testing"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/svc-identity/double"
	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/service"
)

// IST-02: the JWKS publishes the current and the pre-published next key; a token signed with the
// next key verifies; the JWKS endpoint cannot be made to fetch anything by a token.
func TestJWKSPublishesNextKeyBeforeItSigns(t *testing.T) {
	e := newEnv(t)
	var jwks gen.Jwks
	e.mustJSON(200, "GET", "/v1/jwks", "", nil, &jwks)
	if len(jwks.Keys) != 2 || jwks.Keys[0].Kid == jwks.Keys[1].Kid {
		t.Fatalf("want current and next key: %+v", jwks.Keys)
	}
	now := e.d.Clock.Now()
	next := e.d.Signer.NextTenant
	claims := auth.Claims{Issuer: "hostry-identity", Audience: auth.Audience{"hostry-tenant"}, Realm: auth.RealmTenant, Subject: "m", Type: auth.TypeUser, TenantID: org.String(),
		SessionID: "s", AuthTime: now.Unix(), IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), JTI: "j"}
	tok, err := crypto.SignES256(next.Priv, next.Kid, "JWT", claims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.d.Verifier.Verify(tok); err != nil {
		t.Fatalf("a token signed with the pre-published next key must verify: %v", err)
	}
	// A vendor-realm key set is separate: the tenant JWKS never lists it.
	var v gen.Jwks
	e.mustJSON(200, "GET", "/v1/vendor-jwks", "", nil, &v)
	for _, k := range v.Keys {
		for _, tk := range jwks.Keys {
			if k.X == tk.X && k.Y == tk.Y {
				t.Fatal("vendor and tenant realms share a key")
			}
		}
	}
}

// IST-11 and IC-12: a sign-in on a new device and a device registration notify the owners.
func TestNewDeviceAndRegistrationAreNotified(t *testing.T) {
	e := newEnv(t)
	owner, _ := e.ownerSession()
	e.d.Clock.Advance(40 * time.Second)
	e.signIn(ownerMobile, double.NewDevice(newID()))
	e.activate(owner.Tokens.AccessToken, gen.Pos, double.NewDevice(newID()))
	kinds := map[string]bool{}
	for _, n := range e.d.Notices.All() {
		kinds[n.Kind] = true
	}
	if !kinds["new_device"] || !kinds["device_registered"] {
		t.Fatalf("notices: %v", kinds)
	}
}

// IST-37: a PIN change advances pin_v and the earlier proof key still verifies late operations.
func TestOldProofKeyStillVerifiesLateOperationsAfterPinChange(t *testing.T) {
	e := newEnv(t)
	owner, _ := e.ownerSession()
	staff, roleID := newID(), newID()
	sd := e.d.Service.Seed()
	_ = sd.Role(e.ctx, org.String(), roleID, "Cashier", []string{"member.read"})
	_ = sd.Member(e.ctx, org.String(), service.SeedMember{ID: staff, Name: "Ravi", Assignments: []service.SeedAssignment{{ID: newID(), RoleID: roleID}}})
	salt1, _ := sd.PinFor(e.ctx, org.String(), staff, "482916")
	dev := double.NewDevice(newID())
	pack := e.activate(owner.Tokens.AccessToken, gen.Pos, dev).OfflinePack
	sec1 := double.PinSecrets(e.d.Service.Cfg.PinParams, "482916", salt1)
	opened := e.d.Clock.Now()
	sid := newID()
	proof1 := double.SessionProof(sec1.ProofKey, sid, dev.ID, staff, pack.PackV, 1, opened)
	if _, err := sd.PinFor(e.ctx, org.String(), staff, "739204"); err != nil { // pin_v 2
		t.Fatal(err)
	}
	verify := func(proof string, pinV int) gen.ProofVerdict {
		var v gen.ProofVerdict
		e.mustJSON(200, "POST", "/internal/v1/proof-verifications", "", gen.ProofVerification{Kind: gen.ProofVerificationKindSession, DeviceId: dev.ID, MemberId: staff,
			SessionId: &sid, PackV: pack.PackV, PinV: pinV, OpenedAt: &opened, Proof: proof}, &v, "Hostry-Service-Token", e.d.ServiceToken("sync", org))
		return v
	}
	if v := verify(proof1, 1); !v.Valid {
		t.Fatal("a proof made under the previous pin_v must still verify a late operation")
	}
	e.d.Clock.Advance(91 * 24 * time.Hour)
	if v := verify(proof1, 1); v.Valid {
		t.Fatal("the previous proof key must expire after 90 days")
	}
}
