package api_test

import (
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/hostryhq/svc-identity/double"
	"github.com/hostryhq/svc-identity/internal/gen"
	tdouble "github.com/hostryhq/svc-tenancy/double"
)

// These tests run identity against svc-tenancy's own double (not a hand-written fake): the generated
// client, service tokens and the tenancy contract's error answers are the real ones.

const (
	tenOrg    = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a60" // organisation of tenancy's example worlds
	tenOutlet = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a61"
	tenReg    = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a6b"
)

// tenancyEnv is an identity double wired to the tenancy double, with an owner of tenancy's example
// organisation signed in.
func tenancyEnv(t *testing.T, world string) (*env, string) {
	t.Helper()
	e := &env{t: t, d: double.New(double.Options{WithTenancy: true}), ctx: ctxBackground()}
	if err := e.d.Tenancy.SeedWorld(e.ctx, world); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.d.Service.Seed().OwnerInvitation(e.ctx, tenOrg, ownerMobile, "Asha"); err != nil {
		t.Fatal(err)
	}
	s := e.signIn(ownerMobile, double.NewDevice(newID()))
	return e, s.Tokens.AccessToken
}

// activateAt is activate with an explicit outlet; it returns the status and the activation.
func (e *env) activateAt(tok, outlet string, kind gen.DeviceKind, dev *double.Device) (int, gen.DeviceActivation) {
	e.t.Helper()
	var code gen.ActivationCode
	e.mustJSON(201, "POST", "/v1/activation-codes", tok, gen.CreateActivationCode{OutletId: outlet, Kind: kind}, &code)
	var n gen.DeviceNonce
	e.mustJSON(201, "POST", "/v1/device-nonces", "", nil, &n)
	body := gen.ActivateDevice{ActivationCode: code.Code, Id: dev.ID, Name: "Counter 1", PublicKey: pub(dev), KeyProtection: gen.Hardware, Nonce: n.Nonce, NonceSignature: dev.SignNonce(n.Nonce)}
	status, b, _ := e.do("POST", "/v1/device-activations", "", body)
	var act gen.DeviceActivation
	if status == 201 {
		mustUnmarshal(e.t, b, &act)
	}
	return status, act
}

func TestBillingDeviceCarriesTenancySeriesInItsPack(t *testing.T) {
	// Tenancy's example world already holds series A7K for device 4a5e: a repeat issue returns the same code.
	e, tok := tenancyEnv(t, "series-issued")
	pos := double.NewDevice("0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5e")
	status, act := e.activateAt(tok, tenOutlet, gen.Pos, pos)
	if status != 201 || act.Device.BillingCapability != gen.BillingCapabilityActive {
		t.Fatalf("pos activation: %d %+v", status, act.Device)
	}
	s := packClaims(act.OfflinePack).Series
	if len(s) != 2 || s[0].Code != "A7K" || s[0].DocType != gen.TaxInvoice || s[0].State != gen.PackSeriesStateActive || s[0].TaxRegistrationId != tenReg || s[1].Code != "A7M" || s[1].DocType != gen.CreditNote {
		t.Fatalf("pos pack series: %+v", s)
	}
	// A waiter tablet gets a dormant series of its own under the same registration.
	status, wact := e.activateAt(tok, tenOutlet, gen.Waiter, double.NewDevice(newID()))
	ws := packClaims(wact.OfflinePack).Series
	if status != 201 || len(ws) != 2 || ws[0].State != gen.PackSeriesStateDormant || ws[0].Code == "A7K" || ws[0].Code == "A7M" || ws[0].TaxRegistrationId != tenReg {
		t.Fatalf("waiter: %d series %+v", status, ws)
	}
	// A kitchen display has no billing and is issued nothing.
	status, kact := e.activateAt(tok, tenOutlet, gen.Kds, double.NewDevice(newID()))
	if status != 201 || len(packClaims(kact.OfflinePack).Series) != 0 || kact.Device.BillingCapability != gen.BillingCapabilityNone {
		t.Fatalf("kds: %d %+v", status, kact.Device)
	}
}

func TestUnverifiedRegistrationRegistersWithoutBillingThenGetsSeries(t *testing.T) {
	e, tok := tenancyEnv(t, "base") // the outlet's tax registration is not verified yet
	pos := double.NewDevice(newID())
	status, act := e.activateAt(tok, tenOutlet, gen.Pos, pos)
	if status != 201 || act.Device.BillingCapability != gen.BillingCapabilityNone || len(packClaims(act.OfflinePack).Series) != 0 {
		t.Fatalf("unverified: %d %+v series %+v", status, act.Device, packClaims(act.OfflinePack).Series)
	}
	// Staff verify the registration; the next pack fetch carries the series and the device can bill.
	if err := e.d.Tenancy.SeedWorld(e.ctx, "registration-verified"); err != nil {
		t.Fatal(err)
	}
	var pack gen.OfflinePack
	e.mustJSON(200, "GET", "/v1/devices/"+pos.ID+"/offline-packs/latest", tok, nil, &pack)
	if len(packClaims(pack).Series) != 2 || len(packClaims(pack).Series[0].Code) != 3 || pack.PackV <= act.OfflinePack.PackV {
		t.Fatalf("pack after verification: v%d series %+v", pack.PackV, packClaims(pack).Series)
	}
	var d gen.Device
	e.mustJSON(200, "GET", "/v1/devices/"+pos.ID, tok, nil, &d)
	if d.BillingCapability != gen.BillingCapabilityActive {
		t.Fatalf("billing after verification: %s", d.BillingCapability)
	}
}

func TestOutletMustExistInTheCallersTenant(t *testing.T) {
	e, tok := tenancyEnv(t, "registration-verified")
	// An outlet tenancy does not know is refused.
	if status, _ := e.activateAt(tok, newID(), gen.Pos, double.NewDevice(newID())); status != 422 {
		t.Fatalf("unknown outlet: %d", status)
	}
	// Tenant isolation: an owner of another organisation cannot be issued codes under this outlet,
	// because tenancy answers 404 for an outlet that is not in the service token's tenant.
	other := "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a63"
	if _, _, err := e.d.Service.Seed().OwnerInvitation(e.ctx, other, "+919876543299", "Bala"); err != nil {
		t.Fatal(err)
	}
	b := e.signIn("+919876543299", double.NewDevice(newID()))
	if status, _ := e.activateAt(b.Tokens.AccessToken, tenOutlet, gen.Pos, double.NewDevice(newID())); status != 422 {
		t.Fatalf("outlet of another tenant: %d", status)
	}
}

func TestTenancyOutageIsRetriedWithinTheCallAndFailsAsUnavailable(t *testing.T) {
	e, tok := tenancyEnv(t, "registration-verified")
	// One 503: the client retries once with the same Idempotency-Key and the device registers.
	var hits atomic.Int32
	remove := e.d.Tenancy.Inject(tdouble.Fault{Status: http.StatusServiceUnavailable, Match: func(r *http.Request) bool {
		return r.URL.Path == "/internal/v1/document-series-issuances" && hits.Add(1) == 1
	}})
	status, act := e.activateAt(tok, tenOutlet, gen.Pos, double.NewDevice(newID()))
	remove()
	if status != 201 || len(packClaims(act.OfflinePack).Series) != 2 || hits.Load() != 2 {
		t.Fatalf("one outage: %d hits %d series %+v", status, hits.Load(), packClaims(act.OfflinePack).Series)
	}
	// A longer outage answers 503.
	remove = e.d.Tenancy.Inject(tdouble.Fault{Status: http.StatusServiceUnavailable, Match: func(r *http.Request) bool { return true }})
	if status, _ := e.activateAt(tok, tenOutlet, gen.Pos, double.NewDevice(newID())); status != 503 {
		t.Fatalf("outage: %d", status)
	}
	remove()
}
