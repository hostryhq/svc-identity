package api_test

import (
	"testing"

	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/svc-identity/double"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/service"
)

func (e *env) registerBody(id string, k *double.Device, outlet string) gen.RegisterDevice {
	var n gen.DeviceNonce
	e.mustJSON(201, "POST", "/v1/device-nonces", "", nil, &n)
	return gen.RegisterDevice{Id: id, Kind: gen.Pos, Name: "Till", OutletId: outlet, KeyProtection: gen.OsSoftware, PublicKey: pub(k), Nonce: n.Nonce, NonceSignature: k.SignNonce(n.Nonce)}
}

// SR-H3: device ids come from clients, so one tenant cannot take over another tenant's id, and no
// registration (by key, in the same tenant) reactivates a revoked device.
func TestDeviceIdsAreInsertOnlyAcrossTenantsAndStates(t *testing.T) {
	e := newEnv(t)
	ownerA, _ := e.ownerSession()
	tokA := ownerA.Tokens.AccessToken
	devA := double.NewDevice(newID())
	e.activate(tokA, gen.Pos, devA)

	// Tenant B registers A's device id with its own key: refused, and A's device still works.
	orgB := ids.ID("018f0000-0000-7000-8000-00000000000b")
	tokB := e.d.UserToken(orgB, "someone", "", grantsAll())
	attacker := double.NewDevice(devA.ID)
	code, body, _ := e.do("POST", "/v1/devices", tokB, e.registerBody(devA.ID, attacker, outletA))
	if code != 409 || problemCode(body) != "device_id_unavailable" {
		t.Fatalf("cross-tenant id takeover: %d %s", code, body)
	}
	var tok gen.DeviceToken
	e.mustJSON(200, "POST", "/v1/tokens/device", "", gen.DeviceGrant{GrantType: gen.DeviceGrantGrantTypeDevice, DeviceId: devA.ID,
		Assertion: devA.Assert(e.d.Clock.Now(), e.jti(), service.AssertionClaims{})}, &tok)

	// Same tenant, same id, other key: refused too (no overwrite of the record or its key).
	code, body, _ = e.do("POST", "/v1/devices", tokA, e.registerBody(devA.ID, double.NewDevice(devA.ID), outletA))
	if code != 409 || problemCode(body) != "device_id_unavailable" {
		t.Fatalf("same-tenant overwrite: %d %s", code, body)
	}
	// A revoked device is never brought back, with its old key or a new one.
	e.mustJSON(200, "PUT", "/v1/devices/"+devA.ID+"/revocation", tokA, gen.RevokeDevice{Reason: gen.RevokeDeviceReasonLost}, nil)
	code, body, _ = e.do("POST", "/v1/devices", tokA, e.registerBody(devA.ID, devA, outletA))
	if code != 409 || problemCode(body) != "device_revoked" {
		t.Fatalf("re-registering a revoked device with its key: %d %s", code, body)
	}
	code, body, _ = e.do("POST", "/v1/devices", tokA, e.registerBody(devA.ID, double.NewDevice(devA.ID), outletA))
	if code != 409 {
		t.Fatalf("re-registering a revoked id with a new key: %d %s", code, body)
	}
	var d gen.Device
	e.mustJSON(200, "GET", "/v1/devices/"+devA.ID, tokA, nil, &d)
	if d.State != gen.DeviceStateRevoked {
		t.Fatalf("device state after attempts: %s", d.State)
	}
}

// M2: an activation code does not return the offline pack of an existing device of another
// outlet or kind, even when the request names that device's id.
func TestActivationWithAnExistingDeviceIdIsRefused(t *testing.T) {
	e := newEnv(t)
	owner, _ := e.ownerSession()
	tok := owner.Tokens.AccessToken
	pos := double.NewDevice(newID())
	e.activate(tok, gen.Pos, pos)
	var code gen.ActivationCode
	e.mustJSON(201, "POST", "/v1/activation-codes", tok, gen.CreateActivationCode{OutletId: outletA, Kind: gen.Kds}, &code)
	var n gen.DeviceNonce
	e.mustJSON(201, "POST", "/v1/device-nonces", "", nil, &n)
	other := double.NewDevice(pos.ID)
	c, b, _ := e.do("POST", "/v1/device-activations", "", gen.ActivateDevice{ActivationCode: code.Code, Id: pos.ID, Name: "K", PublicKey: pub(other),
		KeyProtection: gen.OsSoftware, Nonce: n.Nonce, NonceSignature: other.SignNonce(n.Nonce)})
	if c == 201 {
		t.Fatalf("activation returned an existing device's pack: %s", b)
	}
}
