package api_test

import (
	"net/http"
	"testing"

	"github.com/hostryhq/svc-identity/double"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/service"
	tdouble "github.com/hostryhq/svc-tenancy/double"
)

const tenBrand = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a6a" // brand of the outlet in tenancy's example worlds

func (e *env) credential(devID string) (int, gen.DeviceCredential) {
	e.t.Helper()
	status, b, _ := e.do("GET", "/internal/v1/devices/"+devID+"/credential", "", nil, "Hostry-Service-Token", e.d.ServiceToken("sync", orgID(tenOrg)))
	var c gen.DeviceCredential
	if status == 200 {
		mustUnmarshal(e.t, b, &c)
	}
	return status, c
}

// ADR-0014 A3.4 items 1 and 3: activation reads the outlet's brand from tenancy (every kind, kds included), stores it
// and signs it into the credential and the pack with the device's own kid. Tenancy down: 503, nothing registered.
func TestActivationSignsTheBrandFromTenancyIntoCredentialAndPack(t *testing.T) {
	e, tok := tenancyEnv(t, "registration-verified")
	for _, kind := range []gen.DeviceKind{gen.Pos, gen.Kds} {
		dev := double.NewDevice(newID())
		status, act := e.activateAt(tok, tenOutlet, kind, dev)
		cd := act.OfflinePack.Claims.Device
		if status != 201 || cd.BrandId != tenBrand || cd.Kid != service.DeviceKID(dev.ID) {
			t.Fatalf("%s: %d pack device %+v", kind, status, cd)
		}
		cs, c := e.credential(dev.ID)
		if cs != 200 || c.BrandId != tenBrand || c.Kid != cd.Kid {
			t.Fatalf("%s: credential %d %+v", kind, cs, c)
		}
	}
	remove := e.d.Tenancy.Inject(tdouble.Fault{Status: http.StatusServiceUnavailable, Match: func(r *http.Request) bool {
		return r.URL.Path == "/internal/v1/stream-owners/"+tenOutlet
	}})
	dev := double.NewDevice(newID())
	if status, _ := e.activateAt(tok, tenOutlet, gen.Kds, dev); status != 503 {
		t.Fatalf("tenancy down: %d", status)
	}
	if status, _ := e.credential(dev.ID); status != 404 {
		t.Fatalf("a refused activation must register nothing: %d", status)
	}
	remove()
}

// ADR-0014 A3.4 item 2: a device row from before the brand is filled once by the start-up job; until then the
// credential and the pack answer 503 tenancy.unavailable, never a credential without a brand.
func TestBackfillFillsDeviceRowsThatHaveNoBrand(t *testing.T) {
	e, tok := tenancyEnv(t, "registration-verified")
	dev := double.NewDevice(newID())
	if status, _ := e.activateAt(tok, tenOutlet, gen.Kds, dev); status != 201 {
		t.Fatal(status)
	}
	if err := e.d.Service.Seed().ClearDeviceBrand(e.ctx, tenOrg, dev.ID); err != nil {
		t.Fatal(err)
	}
	if status, _ := e.credential(dev.ID); status != 503 {
		t.Fatalf("credential without a brand: %d", status)
	}
	e.expect(503, "tenancy.unavailable", "GET", "/v1/devices/"+dev.ID+"/offline-packs/latest", tok, nil)
	remove := e.d.Tenancy.Inject(tdouble.Fault{Status: http.StatusServiceUnavailable, Match: func(*http.Request) bool { return true }})
	if left, err := e.d.Service.BackfillDeviceBrands(e.ctx); err != nil || left != 1 {
		t.Fatalf("backfill with tenancy down: left %d err %v", left, err)
	}
	remove()
	if left, err := e.d.Service.BackfillDeviceBrands(e.ctx); err != nil || left != 0 {
		t.Fatalf("backfill: left %d err %v", left, err)
	}
	if status, c := e.credential(dev.ID); status != 200 || c.BrandId != tenBrand {
		t.Fatalf("credential after backfill: %d %+v", status, c)
	}
}

func (e *env) recoveryCode(tok, oldID string, status int) gen.RecoveryCode {
	e.t.Helper()
	var rc gen.RecoveryCode
	if status == 201 {
		e.mustJSON(201, "POST", "/v1/devices/"+oldID+"/recovery-codes", tok, nil, &rc)
	} else {
		e.expect(status, "", "POST", "/v1/devices/"+oldID+"/recovery-codes", tok, nil)
	}
	return rc
}

func (e *env) redeem(code string, dev *double.Device, status int) gen.DeviceActivation {
	e.t.Helper()
	var n gen.DeviceNonce
	e.mustJSON(201, "POST", "/v1/device-nonces", "", nil, &n)
	body := gen.ActivateDevice{ActivationCode: code, Id: dev.ID, Name: "Counter 1 again", PublicKey: pub(dev), KeyProtection: gen.Hardware, Nonce: n.Nonce, NonceSignature: dev.SignNonce(n.Nonce)}
	var act gen.DeviceActivation
	if status == 201 {
		e.mustJSON(201, "POST", "/v1/device-activations", "", body, &act)
	} else {
		e.expect(status, "", "POST", "/v1/device-activations", "", body)
	}
	return act
}

// ADR-0002 A1.3 items 2 and 3: the owner creates a single-use code bound to the old device; redeeming it revokes the
// old device (key_lost), registers a new one at the same outlet and kind with a brand and new series, writes the
// recovery record, and the new credential carries `recovers`.
func TestKeyLossRecoveryCodeRedeemedAtActivation(t *testing.T) {
	e, tok := tenancyEnv(t, "series-issued")
	oldDev := double.NewDevice("0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5e")
	if status, _ := e.activateAt(tok, tenOutlet, gen.Pos, oldDev); status != 201 {
		t.Fatal(status)
	}
	first := e.recoveryCode(tok, oldDev.ID, 201)
	if first.OldDeviceId != oldDev.ID || first.OutletId != tenOutlet || first.Kind != gen.Pos || len(first.Code) != 8 {
		t.Fatalf("code: %+v", first)
	}
	second := e.recoveryCode(tok, oldDev.ID, 201) // replaces the first
	e.redeem(first.Code, double.NewDevice(newID()), 422)

	newDev := double.NewDevice(newID())
	act := e.redeem(second.Code, newDev, 201)
	if act.Recovery == nil || act.Recovery.OldDeviceId != oldDev.ID || act.Recovery.NewDeviceId != newDev.ID || act.Recovery.State != gen.DeviceRecoveryStateOpen {
		t.Fatalf("recovery: %+v", act.Recovery)
	}
	if act.Device.Kind != gen.Pos || act.OfflinePack.Claims.Device.OutletId != tenOutlet || act.OfflinePack.Claims.Device.BrandId != tenBrand {
		t.Fatalf("new device: %+v", act.Device)
	}
	if len(act.OfflinePack.Claims.Series) == 0 {
		t.Fatalf("the new device needs new series: %+v", act.OfflinePack.Claims.Series)
	}
	_, nc := e.credential(newDev.ID)
	if nc.Recovers == nil || *nc.Recovers != oldDev.ID || nc.BrandId != tenBrand {
		t.Fatalf("credential: %+v", nc)
	}
	var old gen.Device
	e.mustJSON(200, "GET", "/v1/devices/"+oldDev.ID, tok, nil, &old)
	if old.State != gen.DeviceStateRevoked {
		t.Fatalf("old device: %+v", old)
	}
	var r gen.DeviceRecovery
	e.mustJSON(200, "GET", "/internal/v1/devices/"+oldDev.ID+"/recovery", "", nil, &r, "Hostry-Service-Token", e.d.ServiceToken("sync", orgID(tenOrg)))
	if r.NewDeviceId != newDev.ID || r.State != gen.DeviceRecoveryStateOpen {
		t.Fatalf("record: %+v", r)
	}
	// The code is single use and the device is recovered once; a revoked device cannot be recovered.
	e.redeem(second.Code, double.NewDevice(newID()), 409)
	e.recoveryCode(tok, oldDev.ID, 409)
	// A replay of the same activation (same id and key) answers the same device and the record again.
	if again := e.redeem(second.Code, newDev, 201); again.Recovery == nil || again.Recovery.Id != act.Recovery.Id {
		t.Fatalf("replay: %+v", again.Recovery)
	}
}

// Tenant isolation: another organisation's owner cannot create a recovery code for this device (404, never 403).
func TestRecoveryCodeOfAnotherTenantsDeviceIsNotFound(t *testing.T) {
	e, tok := tenancyEnv(t, "registration-verified")
	dev := double.NewDevice(newID())
	if status, _ := e.activateAt(tok, tenOutlet, gen.Pos, dev); status != 201 {
		t.Fatal(status)
	}
	other := "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a63"
	if _, _, err := e.d.Service.Seed().OwnerInvitation(e.ctx, other, "+919876543299", "Bala"); err != nil {
		t.Fatal(err)
	}
	b := e.signIn("+919876543299", double.NewDevice(newID()))
	e.recoveryCode(b.Tokens.AccessToken, dev.ID, 404)
	e.recoveryCode(tok, newID(), 404)
}
