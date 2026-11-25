package api_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hostryhq/svc-identity/double"
	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/service"
)

// packClaims is the OfflinePackClaims of a pack for every kind but a hub.
func packClaims(p gen.OfflinePack) gen.OfflinePackClaims {
	c, err := p.Claims.AsOfflinePackClaims()
	if err != nil {
		panic(err)
	}
	return c
}

func (e *env) activateStore(tok string, kind gen.DeviceKind, dev *double.Device, store *gen.StoreProtection, status int) (gen.DeviceActivation, []byte) {
	e.t.Helper()
	var code gen.ActivationCode
	e.mustJSON(201, "POST", "/v1/activation-codes", tok, gen.CreateActivationCode{OutletId: outletA, Kind: kind}, &code)
	var n gen.DeviceNonce
	e.mustJSON(201, "POST", "/v1/device-nonces", "", nil, &n)
	body := gen.ActivateDevice{ActivationCode: code.Code, Id: dev.ID, Name: "Hub", PublicKey: pub(dev), KeyProtection: gen.OsSoftware, Store: store,
		Nonce: n.Nonce, NonceSignature: dev.SignNonce(n.Nonce)}
	var act gen.DeviceActivation
	got, b, _ := e.do("POST", "/v1/device-activations", "", body)
	if got != status {
		e.t.Fatalf("activate %s: got %d, want %d (%s)", kind, got, status, b)
	}
	if got == 201 {
		mustUnmarshal(e.t, b, &act)
	}
	return act, b
}

// jwsParts decodes a compact JWS (header, payload) and verifies it with the key.
func jwsParts(t *testing.T, tok string, key gen.Jwk) (hdr map[string]string, payload map[string]any) {
	t.Helper()
	pk, err := crypto.FromJWK(crypto.JWK{Kty: string(key.Kty), Crv: string(key.Crv), X: key.X, Y: key.Y})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := crypto.VerifyES256(tok, pk)
	if err != nil {
		t.Fatalf("credential does not verify under the pack's identity key: %v", err)
	}
	h, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[0])
	mustUnmarshal(t, h, &hdr)
	mustUnmarshal(t, raw, &payload)
	return hdr, payload
}

// ADR-0002 A3.4 (HP1, HP2): a hub is activated like any device and receives a HubPackClaims whose credential is the
// identity-signed LAN credential; the pack holds no name, verifier, salt, series code or manual book, and it
// follows the outlet's revocations on refresh.
func TestHubActivationIssuesHubPackAndLANCredential(t *testing.T) {
	e := newEnv(t)
	owner, _ := e.ownerSession()
	tok := owner.Tokens.AccessToken
	hub := double.NewDevice(newID())
	protected := gen.Protected
	act, raw := e.activateStore(tok, gen.Hub, hub, &protected, 201)
	if act.Device.Kind != gen.Hub || act.Device.Store == nil || *act.Device.Store != gen.Protected {
		t.Fatalf("device: %+v", act.Device)
	}
	hc, err := act.OfflinePack.Claims.AsHubPackClaims()
	if err != nil || hc.Device.DeviceId != hub.ID || hc.Device.Kind != gen.Hub || hc.Device.Store != gen.Protected || hc.OrganisationId != org.String() {
		t.Fatalf("hub claims: %v %+v", err, hc.Device)
	}
	if len(hc.Members) == 0 || len(hc.IdentityPublicKeys) == 0 || hc.OpSigningPublicKey.X == "" || hc.PackV != act.OfflinePack.PackV {
		t.Fatalf("hub pack is missing what cmd/hub needs: %+v", hc)
	}
	// HP2: nothing a hub must not hold, in the pack as served and in the signed payload.
	var served map[string]any
	mustUnmarshal(t, raw, &served)
	pk, _ := json.Marshal(served["offline_pack"])
	signed, _ := base64.RawURLEncoding.DecodeString(strings.Split(act.OfflinePack.Jws, ".")[1])
	for _, doc := range []string{string(pk), string(signed)} {
		for _, banned := range []string{"display_name", "pin_salt", "pin_verifier", "pin_v", "vbits", "\"series\"", "manual_books", "entitlements"} {
			if strings.Contains(doc, banned) {
				t.Fatalf("a hub pack must not carry %s: %s", banned, doc)
			}
		}
	}

	// The LAN credential: ES256 under the pack's identity key, typ hostry-cred+jws, the credential claims plus not_after.
	hdr, c := jwsParts(t, hc.Device.Credential, hc.IdentityPublicKeys[0])
	if hdr["typ"] != service.CredentialTyp || hdr["alg"] != "ES256" || hdr["kid"] != hc.IdentityPublicKeys[0].Kid {
		t.Fatalf("credential header: %v", hdr)
	}
	if c["device_id"] != hub.ID || c["kind"] != "hub" || c["store"] != "protected" || c["tenant_id"] != org.String() || c["outlet_id"] != outletA ||
		c["kid"] != hub.KID() || int64(c["not_after"].(float64)) != hc.OfflineValidUntil.Unix() {
		t.Fatalf("credential claims: %v", c)
	}
	if _, ok := c["recovers"]; ok {
		t.Fatalf("no recovers on a first activation: %v", c)
	}
	// Refresh with the device's own token: a hub pack again, and it lists a tablet revoked meanwhile.
	tablet := double.NewDevice(newID())
	e.activate(tok, gen.Pos, tablet)
	e.mustJSON(200, "PUT", "/v1/devices/"+tablet.ID+"/revocation", tok, gen.RevokeDevice{Reason: gen.RevokeDeviceReasonLost}, &gen.Device{})
	var dtok gen.DeviceToken
	e.mustJSON(200, "POST", "/v1/tokens/device", "", gen.DeviceGrant{GrantType: gen.DeviceGrantGrantTypeDevice, DeviceId: hub.ID, Assertion: hub.Assert(e.d.Clock.Now(), e.jti(), service.AssertionClaims{})}, &dtok)
	var fresh gen.OfflinePack
	e.mustJSON(200, "GET", "/v1/devices/"+hub.ID+"/offline-packs/latest", dtok.AccessToken, nil, &fresh)
	fh, err := fresh.Claims.AsHubPackClaims()
	if err != nil || fresh.PackV <= act.OfflinePack.PackV {
		t.Fatalf("refreshed hub pack: %v v%d", err, fresh.PackV)
	}
	found := false
	for _, id := range fh.RevokedDeviceIds {
		found = found || id == tablet.ID
	}
	if !found {
		t.Fatalf("the refreshed pack must list the revoked tablet: %v", fh.RevokedDeviceIds)
	}
	// The directory answer (getDeviceCredential) agrees with the signed credential on every claim but not_after.
	var dc gen.DeviceCredential
	e.mustJSON(200, "GET", "/internal/v1/devices/"+hub.ID+"/credential", "", nil, &dc, "Hostry-Service-Token", e.d.ServiceToken("sync", org))
	if dc.Store != gen.Protected || dc.Kind != gen.Hub || dc.Pub != c["pub"] || dc.Kid != c["kid"] || dc.DeviceId != c["device_id"] || dc.BrandId != c["brand_id"] {
		t.Fatalf("directory credential %+v differs from the signed one %v", dc, c)
	}
}

// ADR-0002 A3.3 item 3, A3.5 item 1 (PP2): the build declares its store at activation. The browser build declares
// `unprotected` (or nothing), and a live identity refuses it before the code is spent; dev, test and ci accept it.
func TestUnprotectedStoreRefusedOutsideDevTestCI(t *testing.T) {
	for _, tc := range []struct {
		env   string
		store *gen.StoreProtection
		want  int
	}{
		{"production", nil, 422},                       // the browser build declares nothing, or unprotected
		{"production", ptrStore(gen.Unprotected), 422}, // a hub on a key file
		{"production", ptrStore(gen.Protected), 201},   // the native shell's encrypted store
		{"staging", ptrStore(gen.Unprotected), 422},    // any named environment is live
		{"test", ptrStore(gen.Unprotected), 201},       // synthetic data only
		{"ci", nil, 201},
	} {
		e := newEnv(t)
		owner, _ := e.ownerSession()
		e.d.Service.Cfg.Environment = tc.env // sign-in used the test SMS sender; the activation judges the environment
		dev := double.NewDevice(newID())
		_, raw := e.activateStore(owner.Tokens.AccessToken, gen.Pos, dev, tc.store, tc.want)
		if tc.want == 422 {
			if problemCode(raw) != "store.unprotected_refused" {
				t.Fatalf("%s: %s", tc.env, raw)
			}
			// Nothing was registered: the device list is empty, and the same device then activates with a protected store.
			var page gen.DevicePage
			e.mustJSON(200, "GET", "/v1/devices", owner.Tokens.AccessToken, nil, &page)
			if len(page.Items) != 0 {
				t.Fatalf("%s: a refused activation registered a device: %+v", tc.env, page.Items)
			}
			e.activateStore(owner.Tokens.AccessToken, gen.Pos, dev, ptrStore(gen.Protected), 201)
		}
	}
}

// The store claim is recorded, fixed for the life of the id and signed into the credential the gateway reads.
func TestStoreClaimIsSignedAndFixed(t *testing.T) {
	e := newEnv(t) // environment test: an unprotected store is allowed
	owner, _ := e.ownerSession()
	tok := owner.Tokens.AccessToken
	dev := double.NewDevice(newID())
	act, _ := e.activateStore(tok, gen.Pos, dev, nil, 201)
	pc := packClaims(act.OfflinePack)
	if pc.Device.Store != gen.Unprotected || act.Device.Store == nil || *act.Device.Store != gen.Unprotected {
		t.Fatalf("an absent declaration is unprotected: %+v", pc.Device)
	}
	_, c := jwsParts(t, pc.Device.Credential, pc.IdentityPublicKeys[0])
	if c["store"] != "unprotected" || c["kind"] != "pos" {
		t.Fatalf("credential: %v", c)
	}
	var page gen.DevicePage
	e.mustJSON(200, "GET", "/v1/devices", tok, nil, &page)
	for _, d := range page.Items {
		if d.Id == dev.ID && (d.Store == nil || *d.Store != gen.Unprotected) {
			t.Fatalf("device list: %+v", d)
		}
	}
}

func ptrStore(s gen.StoreProtection) *gen.StoreProtection { return &s }
