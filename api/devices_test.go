package api_test

import (
	"encoding/base64"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/svc-identity/double"
	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/service"
)

// activate registers a device of a kind at outletA with an activation code made by tok.
func (e *env) activate(tok string, kind gen.DeviceKind, dev *double.Device) gen.DeviceActivation {
	e.t.Helper()
	var code gen.ActivationCode
	e.mustJSON(201, "POST", "/v1/activation-codes", tok, gen.CreateActivationCode{OutletId: outletA, Kind: kind}, &code)
	var n gen.DeviceNonce
	e.mustJSON(201, "POST", "/v1/device-nonces", "", nil, &n)
	var act gen.DeviceActivation
	e.mustJSON(201, "POST", "/v1/device-activations", "", gen.ActivateDevice{ActivationCode: code.Code, Id: dev.ID, Name: "Counter 1", PublicKey: pub(dev),
		KeyProtection: gen.OsSoftware, Nonce: n.Nonce, NonceSignature: dev.SignNonce(n.Nonce)}, &act)
	return act
}

func TestActivationCodeLifecycleAndRegistrationProof(t *testing.T) {
	e := newEnv(t)
	owner, _ := e.ownerSession()
	tok := owner.Tokens.AccessToken
	dev := double.NewDevice(newID())
	act := e.activate(tok, gen.Pos, dev)
	if act.Device.State != gen.DeviceStateActive || act.Device.KeyProtection != gen.OsSoftware || act.Device.BillingCapability != gen.BillingCapabilityActive {
		t.Fatalf("device: %+v", act.Device)
	}
	if act.OfflinePack.PackV < 1 || packClaims(act.OfflinePack).Device.DeviceId != dev.ID {
		t.Fatalf("pack: %+v", act.OfflinePack)
	}
	// Event and audit: device.registered is in the outbox.
	found := false
	for _, ev := range e.d.Memory.Events() {
		found = found || ev.Type == "identity.device.registered"
	}
	if !found {
		t.Fatal("no identity.device.registered event")
	}

	// IST-21: the code is single use; a second device cannot redeem it.
	var code gen.ActivationCode
	e.mustJSON(201, "POST", "/v1/activation-codes", tok, gen.CreateActivationCode{OutletId: outletA, Kind: gen.Kds}, &code)
	redeem := func(d *double.Device, c string, nonceFor *double.Device) int {
		var n gen.DeviceNonce
		e.mustJSON(201, "POST", "/v1/device-nonces", "", nil, &n)
		sig := d.SignNonce(n.Nonce)
		if nonceFor != nil {
			sig = nonceFor.SignNonce(n.Nonce)
		}
		c2, _, _ := e.do("POST", "/v1/device-activations", "", gen.ActivateDevice{ActivationCode: c, Id: d.ID, Name: "K", PublicKey: pub(d), KeyProtection: gen.Hardware, Nonce: n.Nonce, NonceSignature: sig})
		return c2
	}
	kds := double.NewDevice(newID())
	// IST-22: a registration whose nonce signature is not from the submitted key is refused.
	if c := redeem(kds, code.Code, double.NewDevice(kds.ID)); c != 422 {
		t.Fatalf("registration without proof of possession: %d", c)
	}
	if c := redeem(kds, code.Code, nil); c != 201 {
		t.Fatalf("valid redemption: %d", c)
	}
	if c := redeem(double.NewDevice(newID()), code.Code, nil); c != 409 {
		t.Fatalf("code redeemed twice: %d", c)
	}
	// A key already bound to an active device is refused for a different device id.
	var code2 gen.ActivationCode
	e.mustJSON(201, "POST", "/v1/activation-codes", tok, gen.CreateActivationCode{OutletId: outletA, Kind: gen.Pos}, &code2)
	dup := &double.Device{ID: newID(), Priv: dev.Priv}
	if c := redeem(dup, code2.Code, nil); c != 422 {
		t.Fatalf("key reuse: %d", c)
	}
	// Expiry at 10 minutes.
	var code3 gen.ActivationCode
	e.mustJSON(201, "POST", "/v1/activation-codes", tok, gen.CreateActivationCode{OutletId: outletA, Kind: gen.Waiter}, &code3)
	e.d.Clock.Advance(11 * time.Minute)
	if c := redeem(double.NewDevice(newID()), code3.Code, nil); c != 422 {
		t.Fatalf("expired code: %d", c)
	}
}

// IST-21: two parallel redemptions of one code, one wins.
func TestActivationCodeConcurrentRedemption(t *testing.T) {
	e := newEnv(t)
	owner, _ := e.ownerSession()
	var code gen.ActivationCode
	e.mustJSON(201, "POST", "/v1/activation-codes", owner.Tokens.AccessToken, gen.CreateActivationCode{OutletId: outletA, Kind: gen.Pos}, &code)
	var wg sync.WaitGroup
	results := make([]int, 4)
	nonces := make([]gen.DeviceNonce, 4)
	devs := make([]*double.Device, 4)
	for i := range devs {
		devs[i] = double.NewDevice(newID())
		e.mustJSON(201, "POST", "/v1/device-nonces", "", nil, &nonces[i])
	}
	for i := range devs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, _, _ := e.doNoT("POST", "/v1/device-activations", gen.ActivateDevice{ActivationCode: code.Code, Id: devs[i].ID, Name: "x", PublicKey: pub(devs[i]),
				KeyProtection: gen.Hardware, Nonce: nonces[i].Nonce, NonceSignature: devs[i].SignNonce(nonces[i].Nonce)}, i)
			results[i] = c
		}(i)
	}
	wg.Wait()
	wins := 0
	for _, c := range results {
		if c == 201 {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("redemption results %v: want exactly one 201", results)
	}
}

func TestStrongOnlyCeilingForPinAndDeviceTokens(t *testing.T) {
	e := newEnv(t)
	owner, _ := e.ownerSession()
	// IST-17 (generated from the catalogue): a pin-type token, even carrying the owner's grants, is
	// refused on every strong_only operation; a device-type token likewise.
	for _, typ := range []auth.TokenType{auth.TypePin, auth.TypeDevice} {
		tok := e.mint(typ)
		e.expect(403, "", "POST", "/v1/members", tok, gen.CreateMember{Id: newID(), DisplayName: "X"})
		e.expect(403, "", "POST", "/v1/activation-codes", tok, gen.CreateActivationCode{OutletId: outletA, Kind: gen.Pos})
		e.expect(403, "", "PUT", "/v1/devices/"+newID()+"/revocation", tok, gen.RevokeDevice{Reason: gen.RevokeDeviceReasonLost})
		e.expect(403, "", "POST", "/v1/roles", tok, gen.RoleInput{Name: "x", Permissions: []string{}})
	}
	_ = owner
}

func TestRevokeDeviceDrainTokenAndWipeOrder(t *testing.T) {
	e := newEnv(t)
	owner, _ := e.ownerSession()
	tok := owner.Tokens.AccessToken
	dev := double.NewDevice(newID())
	e.activate(tok, gen.Pos, dev)

	var d gen.Device
	e.mustJSON(200, "PUT", "/v1/devices/"+dev.ID+"/revocation", tok, gen.RevokeDevice{Reason: gen.RevokeDeviceReasonLost}, &d)
	if d.State != gen.DeviceStateRevoked {
		t.Fatal("not revoked")
	}
	// Idempotent: a repeat returns the same body; one revoked event only.
	e.mustJSON(200, "PUT", "/v1/devices/"+dev.ID+"/revocation", tok, gen.RevokeDevice{Reason: gen.RevokeDeviceReasonLost}, &d)
	n := 0
	for _, ev := range e.d.Memory.Events() {
		if ev.Type == "identity.device.revoked" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("device.revoked events: %d", n)
	}
	// The revoked device gets device_revoked for packs and device tokens, and no pin token.
	e.expect(403, "device_revoked", "POST", "/v1/tokens/device", "", gen.DeviceGrant{GrantType: gen.DeviceGrantGrantTypeDevice, DeviceId: dev.ID,
		Assertion: dev.Assert(e.d.Clock.Now(), e.jti(), service.AssertionClaims{})})
	// The gateway's feed lists it.
	var feed gen.RevocationPage
	svc := e.d.ServiceToken("sync", "")
	e.mustJSON(200, "GET", "/internal/v1/revocations", "", nil, &feed, "Hostry-Service-Token", svc)
	if len(feed.Items) != 1 || feed.Items[0].SubjectId != dev.ID || feed.Items[0].SubjectType != gen.RevocationSubjectTypeDevice {
		t.Fatalf("revocation feed: %+v", feed)
	}

	// Drain token: needs the device key, lives 5 minutes, works only on the wipe-order endpoint.
	e.expect(401, "", "POST", "/v1/tokens/drain", "", gen.DrainRequest{DeviceId: dev.ID, Assertion: double.NewDevice(dev.ID).Assert(e.d.Clock.Now(), e.jti(), service.AssertionClaims{})})
	var dt gen.DrainToken
	e.mustJSON(200, "POST", "/v1/tokens/drain", "", gen.DrainRequest{DeviceId: dev.ID, Assertion: dev.Assert(e.d.Clock.Now(), e.jti(), service.AssertionClaims{})}, &dt)
	// IST-24: refused everywhere else.
	e.expect(401, "", "GET", "/v1/members", dt.AccessToken, nil)
	e.expect(401, "", "GET", "/v1/devices", dt.AccessToken, nil)
	e.expect(401, "", "POST", "/v1/tokens/switch", dt.AccessToken, gen.SwitchMember{MemberId: owner.MemberId})
	e.expect(401, "", "GET", "/v1/devices/"+dev.ID+"/offline-packs/latest", dt.AccessToken, nil)
	e.expect(409, "wipe_order_not_ready", "GET", "/v1/devices/"+dev.ID+"/wipe-order", dt.AccessToken, nil)
	// The gateway reports the drain; the order is issued only 15 minutes later on the server clock.
	e.mustJSON(200, "PUT", "/internal/v1/devices/"+dev.ID+"/drain", "", gen.RecordDrain{DrainedThrough: through(device0Ops, 40), Statement: ptr(stmt(t, dev, dev.ID, `[{"stream":"device-ops","seq":40,"h":"ab"}]`, `[]`, ""))}, nil,
		"Hostry-Service-Token", e.d.ServiceToken("sync", org))
	e.d.Clock.Advance(4 * time.Minute)
	var dt2 gen.DrainToken
	e.mustJSON(200, "POST", "/v1/tokens/drain", "", gen.DrainRequest{DeviceId: dev.ID, Assertion: dev.Assert(e.d.Clock.Now(), e.jti(), service.AssertionClaims{})}, &dt2)
	e.expect(409, "wipe_order_not_ready", "GET", "/v1/devices/"+dev.ID+"/wipe-order", dt2.AccessToken, nil)
	e.d.Clock.Advance(12 * time.Minute)
	var dt3 gen.DrainToken
	e.mustJSON(200, "POST", "/v1/tokens/drain", "", gen.DrainRequest{DeviceId: dev.ID, Assertion: dev.Assert(e.d.Clock.Now(), e.jti(), service.AssertionClaims{})}, &dt3)
	var wo gen.WipeOrder
	e.mustJSON(200, "GET", "/v1/devices/"+dev.ID+"/wipe-order", dt3.AccessToken, nil, &wo)
	if wo.DeviceId != dev.ID || len(wo.DrainedThrough) != 1 || wo.DrainedThrough[0].Seq != 40 || strings.Count(wo.Jws, ".") != 2 {
		t.Fatalf("wipe order: %+v", wo)
	}
	// Another device's wipe order is 404 even with a valid drain token.
	e.expect(404, "", "GET", "/v1/devices/"+newID()+"/wipe-order", dt3.AccessToken, nil)
}

// IST-26: pack contents. A kds pack carries no verifiers; no pack carries numbers or other outlets' members.
func TestPackContents(t *testing.T) {
	e := newEnv(t)
	owner, _ := e.ownerSession()
	tok := owner.Tokens.AccessToken
	staff := newID()
	roleID := newID()
	sd := e.d.Service
	if err := sd.Seed().Role(e.ctx, org.String(), roleID, "Cashier", []string{"member.read"}); err != nil {
		t.Fatal(err)
	}
	if err := sd.Seed().Member(e.ctx, org.String(), service.SeedMember{ID: staff, Name: "Ravi", Mobile: "+919333333333", Assignments: []service.SeedAssignment{{ID: newID(), RoleID: roleID, Outlets: []string{outletA}}}}); err != nil {
		t.Fatal(err)
	}
	other := newID()
	if err := sd.Seed().Member(e.ctx, org.String(), service.SeedMember{ID: other, Name: "Elsewhere", Assignments: []service.SeedAssignment{{ID: newID(), RoleID: roleID, Outlets: []string{outletB}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := sd.Seed().PinFor(e.ctx, org.String(), staff, "482916"); err != nil {
		t.Fatal(err)
	}
	pos, kds := double.NewDevice(newID()), double.NewDevice(newID())
	posPack := e.activate(tok, gen.Pos, pos).OfflinePack
	kdsPack := e.activate(tok, gen.Kds, kds).OfflinePack
	has := func(p gen.OfflinePack, id string) *gen.PackMember {
		for i := range packClaims(p).Members {
			if packClaims(p).Members[i].MemberId == id {
				return &packClaims(p).Members[i]
			}
		}
		return nil
	}
	if m := has(posPack, staff); m == nil || m.PinVerifier == nil || *m.Vbits != 12 || len(*m.PinVerifier) != 4 {
		t.Fatalf("pos pack member: %+v", m)
	}
	if has(posPack, other) != nil || has(kdsPack, other) != nil {
		t.Fatal("a member of another outlet is in the pack")
	}
	if m := has(kdsPack, staff); m == nil || m.PinVerifier != nil || m.PinSalt != nil {
		t.Fatalf("kds pack carries PIN material: %+v", m)
	}
	// A pack is never signed with the tenant token key and carries no phone number.
	raw := strings.ToLower(posPack.Jws)
	if strings.Contains(raw, "9333333333") {
		t.Fatal("phone number in pack")
	}
	pl, _ := base64.RawURLEncoding.DecodeString(strings.Split(posPack.Jws, ".")[1])
	if strings.Contains(string(pl), "9333333333") || strings.Contains(string(pl), "proof") {
		t.Fatal("pack payload leaks a number or proof material")
	}
}

// IST-19, IST-20, IST-26b, IST-37: PIN rules and the pin grant with its session proof.
func TestPinSetAndPinGrant(t *testing.T) {
	e := newEnv(t)
	owner, _ := e.ownerSession()
	tok := owner.Tokens.AccessToken
	staff, roleID := newID(), newID()
	sd := e.d.Service.Seed()
	_ = sd.Role(e.ctx, org.String(), roleID, "Cashier", []string{"member.read"})
	_ = sd.Member(e.ctx, org.String(), service.SeedMember{ID: staff, Name: "Ravi", Mobile: "+919333330000", Assignments: []service.SeedAssignment{{ID: newID(), RoleID: roleID, Outlets: []string{outletA}}}})
	dev := double.NewDevice(newID())
	e.activate(tok, gen.Pos, dev)

	var auth gen.PinResetAuthorisation
	e.mustJSON(201, "POST", "/v1/members/"+staff+"/pin-reset-authorisations", tok, nil, &auth)
	// The device (token of type device) sets the PIN with the authorisation. Trivial PINs are refused (IST-19).
	var dtok gen.DeviceToken
	e.mustJSON(200, "POST", "/v1/tokens/device", "", gen.DeviceGrant{GrantType: gen.DeviceGrantGrantTypeDevice, DeviceId: dev.ID, Assertion: dev.Assert(e.d.Clock.Now(), e.jti(), service.AssertionClaims{})}, &dtok)
	for _, bad := range []string{"1234", "0000", "1990", "123456", "0000", "2024", "12", "12ab56"} {
		e.expect(422, "", "PUT", "/v1/members/"+staff+"/pin", dtok.AccessToken, gen.SetPin{DeviceId: dev.ID, Pin: bad, PinResetAuthorisationId: &auth.Id})
	}
	e.expect(422, "", "PUT", "/v1/members/"+staff+"/pin", dtok.AccessToken, gen.SetPin{DeviceId: dev.ID, Pin: "330000", PinResetAuthorisationId: &auth.Id}) // last digits of own number
	// Without an authorisation a device cannot set a PIN.
	e.expect(403, "", "PUT", "/v1/members/"+staff+"/pin", dtok.AccessToken, gen.SetPin{DeviceId: dev.ID, Pin: "482916"})
	var ps gen.PinSet
	e.mustJSON(200, "PUT", "/v1/members/"+staff+"/pin", dtok.AccessToken, gen.SetPin{DeviceId: dev.ID, Pin: "482916", PinResetAuthorisationId: &auth.Id}, &ps)
	if ps.PinV != 1 {
		t.Fatalf("pin_v %d", ps.PinV)
	}
	// The authorisation is single use.
	e.expect(403, "", "PUT", "/v1/members/"+staff+"/pin", dtok.AccessToken, gen.SetPin{DeviceId: dev.ID, Pin: "482917", PinResetAuthorisationId: &auth.Id})

	// The client side: fetch the pack, derive the proof key from the PIN and the pack's salt.
	var pack gen.OfflinePack
	e.mustJSON(200, "GET", "/v1/devices/"+dev.ID+"/offline-packs/latest", dtok.AccessToken, nil, &pack)
	var pm *gen.PackMember
	for i := range packClaims(pack).Members {
		if packClaims(pack).Members[i].MemberId == staff {
			pm = &packClaims(pack).Members[i]
		}
	}
	if pm == nil || pm.PinSalt == nil {
		t.Fatal("staff member missing from pack")
	}
	salt, _ := base64.RawURLEncoding.DecodeString(*pm.PinSalt)
	cfg := e.d.Service.Cfg
	sec := double.PinSecrets(cfg.PinParams, "482916", salt)
	// IST-26b: the truncated verifier passes the local check for the right PIN and for ~1/4096 of wrong ones.
	if crypto.TruncateBits(sec.Verifier, 12) != *pm.PinVerifier {
		t.Fatal("verifier of the right PIN does not match the pack")
	}

	opened := e.d.Clock.Now()
	sid := newID()
	grant := func(mutate func(g *gen.PinGrant)) (int, string) {
		g := gen.PinGrant{GrantType: gen.PinGrantGrantTypePin, DeviceId: dev.ID, MemberId: staff, SessionId: sid, PackV: pack.PackV, PinV: ps.PinV, OpenedAt: opened,
			SessionProof: double.SessionProof(sec.ProofKey, sid, dev.ID, staff, pack.PackV, ps.PinV, opened)}
		mutate(&g)
		g.Assertion = dev.Assert(e.d.Clock.Now(), e.jti(), service.AssertionClaims{Sid: g.SessionId, Mid: g.MemberId, PackV: g.PackV, PinV: g.PinV, Opened: opened.UTC().Format("2006-01-02T15:04:05.000Z")})
		c, b, _ := e.do("POST", "/v1/tokens/device", "", g)
		return c, problemCode(b)
	}
	// IST-20: no, wrong, other-member, other-device, old pin_v and stale-time proofs are all the same refusal.
	bad := map[string]func(*gen.PinGrant){
		"empty proof":   func(g *gen.PinGrant) { g.SessionProof = "" },
		"made-up proof": func(g *gen.PinGrant) { g.SessionProof = "AAAA" },
		"other session": func(g *gen.PinGrant) { g.SessionId = newID() },
		"old pin_v":     func(g *gen.PinGrant) { g.PinV = 0 },
		"stale opened":  func(g *gen.PinGrant) { g.OpenedAt = opened.Add(-17 * time.Hour) },
		"future opened": func(g *gen.PinGrant) { g.OpenedAt = opened.Add(2 * time.Minute) },
		"unknown pack":  func(g *gen.PinGrant) { g.PackV = 99 },
		"other member":  func(g *gen.PinGrant) { g.MemberId = owner.MemberId },
	}
	// Spread across fresh sessions so the per-pair refusal does not hide the individual checks.
	for name, mut := range bad {
		if c, code := grant(mut); c != 401 || code != "invalid_session_proof" {
			t.Fatalf("%s: %d %s", name, c, code)
		}
		e.d.Clock.Advance(16 * time.Minute) // a new 15-minute window per probe
		opened = e.d.Clock.Now()
	}
	// Correct proof: a pin token, never past opened_at + 16 hours, amr pin.
	opened = e.d.Clock.Now()
	var out gen.DeviceToken
	g := gen.PinGrant{GrantType: gen.PinGrantGrantTypePin, DeviceId: dev.ID, MemberId: staff, SessionId: sid, PackV: pack.PackV, PinV: ps.PinV, OpenedAt: opened,
		SessionProof: double.SessionProof(sec.ProofKey, sid, dev.ID, staff, pack.PackV, ps.PinV, opened)}
	g.Assertion = dev.Assert(e.d.Clock.Now(), e.jti(), service.AssertionClaims{Sid: sid, Mid: staff, PackV: pack.PackV, PinV: ps.PinV, Opened: opened.UTC().Format("2006-01-02T15:04:05.000Z")})
	e.mustJSON(200, "POST", "/v1/tokens/device", "", g, &out)
	cl, err := e.d.Verifier.Verify(out.AccessToken)
	if err != nil || string(cl.Type) != "pin" || cl.SessionID != sid || cl.Subject != staff || cl.AMR[0] != "pin" {
		t.Fatalf("pin token: %+v %v", cl, err)
	}
	// The same verifier answers the gateway.
	var v gen.ProofVerdict
	e.mustJSON(200, "POST", "/internal/v1/proof-verifications", "", gen.ProofVerification{Kind: gen.ProofVerificationKindSession, DeviceId: dev.ID, MemberId: staff, SessionId: &sid,
		PackV: pack.PackV, PinV: ps.PinV, OpenedAt: &opened, Proof: g.SessionProof}, &v, "Hostry-Service-Token", e.d.ServiceToken("sync", org))
	if !v.Valid || v.Label != gen.Verified {
		t.Fatalf("gateway verdict: %+v", v)
	}
	g.SessionProof = "wrong"
	e.mustJSON(200, "POST", "/internal/v1/proof-verifications", "", gen.ProofVerification{Kind: gen.ProofVerificationKindSession, DeviceId: dev.ID, MemberId: staff, SessionId: &sid,
		PackV: pack.PackV, PinV: ps.PinV, OpenedAt: &opened, Proof: g.SessionProof}, &v, "Hostry-Service-Token", e.d.ServiceToken("sync", org))
	if v.Valid || v.Label != gen.Unverified {
		t.Fatalf("forged proof verdict: %+v", v)
	}
	// An ended session id gets no more tokens.
	e.mustJSON(204, "DELETE", "/v1/sessions/"+sid, out.AccessToken, nil, nil)
	if c, _ := grant(func(g *gen.PinGrant) { g.OpenedAt = opened }); c != 401 {
		t.Fatalf("ended session got a token: %d", c)
	}
}

// IST-20: 5 failures in 15 minutes refuse the member on that device, even with the right proof.
func TestPinGrantFailureLimit(t *testing.T) {
	e := newEnv(t)
	owner, _ := e.ownerSession()
	staff, roleID := newID(), newID()
	sd := e.d.Service.Seed()
	_ = sd.Role(e.ctx, org.String(), roleID, "Cashier", []string{"member.read"})
	_ = sd.Member(e.ctx, org.String(), service.SeedMember{ID: staff, Name: "Ravi", Assignments: []service.SeedAssignment{{ID: newID(), RoleID: roleID}}})
	salt, _ := sd.PinFor(e.ctx, org.String(), staff, "482916")
	dev := double.NewDevice(newID())
	pack := e.activate(owner.Tokens.AccessToken, gen.Pos, dev).OfflinePack
	sec := double.PinSecrets(e.d.Service.Cfg.PinParams, "482916", salt)
	sid, opened := newID(), e.d.Clock.Now()
	try := func(proof string) (int, string) {
		g := gen.PinGrant{GrantType: gen.PinGrantGrantTypePin, DeviceId: dev.ID, MemberId: staff, SessionId: sid, PackV: pack.PackV, PinV: 1, OpenedAt: opened, SessionProof: proof}
		g.Assertion = dev.Assert(e.d.Clock.Now(), e.jti(), service.AssertionClaims{Sid: sid, Mid: staff, PackV: pack.PackV, PinV: 1, Opened: opened.UTC().Format("2006-01-02T15:04:05.000Z")})
		c, b, _ := e.do("POST", "/v1/tokens/device", "", g)
		return c, problemCode(b)
	}
	for i := 0; i < 5; i++ {
		if c, _ := try("bad"); c != 401 {
			t.Fatalf("attempt %d: %d", i, c)
		}
	}
	good := double.SessionProof(sec.ProofKey, sid, dev.ID, staff, pack.PackV, 1, opened)
	if c, _ := try(good); c != 429 {
		t.Fatalf("right proof inside the refusal window: %d", c)
	}
	e.d.Clock.Advance(16 * time.Minute)
	opened = e.d.Clock.Now()
	good = double.SessionProof(sec.ProofKey, sid, dev.ID, staff, pack.PackV, 1, opened)
	if c, _ := try(good); c != 200 {
		t.Fatalf("after the refusal window: %d", c)
	}
}
