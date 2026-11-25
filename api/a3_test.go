package api_test

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/svc-identity/double"
	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/service"
)

// ADR-0005 Amendment A3: the gateway's directory questions (A3.2) and the drain statement (A3.3).

const device0Ops = "device-ops"

func ptr[T any](v T) *T { return &v }

func orgID(s string) ids.ID { return ids.ID(s) }

// stmt builds a drain statement from its JSON (the anonymous element types of the generated struct make a
// literal unreadable) and signs it as signer (the shell's work).
func stmt(t *testing.T, signer *double.Device, origin string, streams, series, rec string) gen.DrainStatement {
	t.Helper()
	r := ""
	if rec != "" {
		r = fmt.Sprintf(`,"rec":%q`, rec)
	}
	js := fmt.Sprintf(`{"origin":%q,"streams":%s,"series":%s,"by":%q%s,"kid":"x","at":"2026-11-24T13:20:00.000Z","sig":"x"}`, origin, streams, series, signer.ID, r)
	var st gen.DrainStatement
	if err := json.Unmarshal([]byte(js), &st); err != nil {
		t.Fatal(err)
	}
	return signer.SignDrainStatement(st)
}

func (e *env) drain(status int, dev string, body gen.RecordDrain, tenant string) []byte {
	e.t.Helper()
	code, b, _ := e.do("PUT", "/internal/v1/devices/"+dev+"/drain", "", body, "Hostry-Service-Token", e.d.ServiceToken("sync", orgID(tenant)))
	if code != status {
		e.t.Fatalf("drain: status %d, want %d: %s", code, status, b)
	}
	return b
}

func (e *env) drainedEvents() []map[string]any {
	var out []map[string]any
	for _, ev := range e.d.Memory.Events() {
		if ev.Type == "identity.device.drained" {
			var m map[string]any
			_ = json.Unmarshal(ev.Data, &m)
			out = append(out, m)
		}
	}
	return out
}

func through(stream string, seq int) []gen.StreamSequence {
	return []gen.StreamSequence{{Stream: stream, Seq: seq}}
}

func (e *env) revokedPos(tok string) *double.Device {
	e.t.Helper()
	dev := double.NewDevice(newID())
	e.activate(tok, gen.Pos, dev)
	e.mustJSON(200, "PUT", "/v1/devices/"+dev.ID+"/revocation", tok, gen.RevokeDevice{Reason: gen.RevokeDeviceReasonLost}, &gen.Device{})
	return dev
}

// A3.3: nothing is recorded, and nothing published, unless the device's own signed statement is verified.
func TestDrainNeedsTheDevicesOwnVerifiedStatement(t *testing.T) {
	e := newEnv(t)
	owner, _ := e.ownerSession()
	tok := owner.Tokens.AccessToken
	dev := e.revokedPos(tok)
	other := double.NewDevice(dev.ID) // same id, a different key: a forged statement
	heads := `[{"stream":"device-ops","seq":40,"h":"ab"}]`
	good := stmt(t, dev, dev.ID, heads, `[]`, "")

	cases := []struct {
		name string
		body gen.RecordDrain
		code string
	}{
		{"no statement", gen.RecordDrain{DrainedThrough: through(device0Ops, 40)}, "drain.statement_required"},
		{"signed with another key", gen.RecordDrain{DrainedThrough: through(device0Ops, 40), Statement: ptr(stmt(t, other, dev.ID, heads, `[]`, ""))}, "drain.statement_invalid"},
		{"names another origin", gen.RecordDrain{DrainedThrough: through(device0Ops, 40), Statement: ptr(stmt(t, dev, newID(), heads, `[]`, ""))}, "drain.statement_invalid"},
		{"tampered after signing", gen.RecordDrain{DrainedThrough: through(device0Ops, 40), Statement: ptr(func() gen.DrainStatement { s := good; s.At = "2026-11-24T13:21:00.000Z"; return s }())}, "drain.statement_invalid"},
		{"stream head differs from what the gateway holds", gen.RecordDrain{DrainedThrough: through(device0Ops, 39), Statement: &good}, "drain.streams_mismatch"},
		{"series the device never held", gen.RecordDrain{DrainedThrough: through(device0Ops, 40),
			Statement: ptr(stmt(t, dev, dev.ID, heads, `[{"series_id":"`+newID()+`","code":"ZZZ","fy":"2627","last_number":9}]`, ""))}, "drain.series_mismatch"},
	}
	for _, c := range cases {
		b := e.drain(422, dev.ID, c.body, org.String())
		var p struct{ Code string }
		_ = json.Unmarshal(b, &p)
		if p.Code != c.code {
			t.Errorf("%s: code %q, want %q", c.name, p.Code, c.code)
		}
	}
	var d gen.Device
	e.mustJSON(200, "GET", "/v1/devices/"+dev.ID, tok, nil, &d)
	if d.State != gen.DeviceStateRevoked || len(e.drainedEvents()) != 0 {
		t.Fatalf("a refused report must leave the device revoked and publish nothing: %s, %d events", d.State, len(e.drainedEvents()))
	}
	e.drain(200, dev.ID, gen.RecordDrain{DrainedThrough: through(device0Ops, 40), Statement: &good}, org.String())
	e.mustJSON(200, "GET", "/v1/devices/"+dev.ID, tok, nil, &d)
	if d.State != gen.DeviceStateDrained {
		t.Fatalf("state %s", d.State)
	}
}

// A3.3 items 4 to 6: the series numbers in the event are the device's, a repeat is harmless, a second different
// statement is refused, and the wipe order quotes the statement hash.
func TestDrainEventCopiesTheStatementAndWipeOrderQuotesIt(t *testing.T) {
	e, tok := tenancyEnv(t, "series-issued")
	dev := double.NewDevice("0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5e") // tenancy's world already issued it series A7K (4a6c)
	if status, _ := e.activateAt(tok, tenOutlet, gen.Pos, dev); status != 201 {
		t.Fatalf("activation %d", status)
	}
	e.mustJSON(200, "PUT", "/v1/devices/"+dev.ID+"/revocation", tok, gen.RevokeDevice{Reason: gen.RevokeDeviceReasonLost}, &gen.Device{})
	const sid = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a6c"
	heads := `[{"stream":"device-ops","seq":1842,"h":"ab"}]`
	const cn = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a95" // the credit_note series of the pair
	pairJSON := func(last int) string {
		return fmt.Sprintf(`[{"series_id":"%s","code":"A7K","fy":"2627","last_number":%d},{"series_id":"%s","code":"A7M","fy":"2627","last_number":0}]`, sid, last, cn)
	}
	st := stmt(t, dev, dev.ID, heads, pairJSON(123), "")
	body := gen.RecordDrain{DrainedThrough: through(device0Ops, 1842), Statement: &st}
	// The gateway's own list of numbers must agree with the statement; a made-up number is refused.
	liar := []gen.DrainSeries{{SeriesId: sid, Fy: "2627", LastNumber: 124}, {SeriesId: cn, Fy: "2627", LastNumber: 0}}
	e.drain(422, dev.ID, gen.RecordDrain{DrainedThrough: body.DrainedThrough, Statement: &st, Series: &liar}, tenOrg)
	e.drain(200, dev.ID, body, tenOrg)
	e.drain(200, dev.ID, body, tenOrg) // a repeat of the same statement adds nothing
	evs := e.drainedEvents()
	if len(evs) != 1 {
		t.Fatalf("events: %d, want 1", len(evs))
	}
	sj, _ := json.Marshal(evs[0]["series"])
	if string(sj) != `[{"fy":"2627","last_number":123,"series_id":"`+sid+`"},{"fy":"2627","last_number":0,"series_id":"`+cn+`"}]` {
		t.Fatalf("event series: %s", sj)
	}
	// A second, different statement is refused.
	again := stmt(t, dev, dev.ID, heads, pairJSON(999), "")
	e.drain(409, dev.ID, gen.RecordDrain{DrainedThrough: through(device0Ops, 1842), Statement: &again}, tenOrg)

	e.d.Clock.Advance(16 * time.Minute)
	var dt gen.DrainToken
	e.mustJSON(200, "POST", "/v1/tokens/drain", "", gen.DrainRequest{DeviceId: dev.ID, Assertion: dev.Assert(e.d.Clock.Now(), e.jti(), service.AssertionClaims{})}, &dt)
	var wo gen.WipeOrder
	e.mustJSON(200, "GET", "/v1/devices/"+dev.ID+"/wipe-order", dt.AccessToken, nil, &wo)
	want, _ := service.StatementHash(st)
	if wo.StatementHash == nil || *wo.StatementHash != want {
		t.Fatalf("wipe order statement_hash %v, want %s", wo.StatementHash, want)
	}
}

// A3.3 item 1, key loss: the adopting device signs with its own key and the recovery id; the old device has no wipe
// order; the recovery closes when the drain is recorded.
func TestKeyLossDrainIsSignedByTheAdoptingDevice(t *testing.T) {
	e := newEnv(t)
	owner, _ := e.ownerSession()
	tok := owner.Tokens.AccessToken
	oldDev, newDev := double.NewDevice(newID()), double.NewDevice(newID())
	e.activate(tok, gen.Pos, oldDev)
	e.activate(tok, gen.Pos, newDev)
	rec := newID()
	if err := e.d.Service.Seed().KeyLossRecovery(e.ctx, org.String(), rec, oldDev.ID, newDev.ID, owner.MemberId); err != nil {
		t.Fatal(err)
	}
	heads := `[{"stream":"device-ops","seq":7,"h":"cd"}]`
	body := func(s gen.DrainStatement) gen.RecordDrain {
		return gen.RecordDrain{DrainedThrough: through(device0Ops, 7), Statement: &s}
	}
	e.drain(422, oldDev.ID, body(stmt(t, newDev, oldDev.ID, heads, `[]`, "")), org.String())      // no recovery id
	e.drain(422, oldDev.ID, body(stmt(t, newDev, oldDev.ID, heads, `[]`, newID())), org.String()) // not this device's recovery
	e.drain(422, oldDev.ID, body(stmt(t, double.NewDevice(newID()), oldDev.ID, heads, `[]`, rec)), org.String())
	e.drain(200, oldDev.ID, body(stmt(t, newDev, oldDev.ID, heads, `[]`, rec)), org.String())

	var r gen.DeviceRecovery
	e.mustJSON(200, "GET", "/internal/v1/devices/"+oldDev.ID+"/recovery", "", nil, &r, "Hostry-Service-Token", e.d.ServiceToken("sync", org))
	if r.Id != rec || r.State != gen.DeviceRecoveryStateClosed || r.NewDeviceId != newDev.ID {
		t.Fatalf("recovery: %+v", r)
	}
	e.d.Clock.Advance(16 * time.Minute)
	var dt gen.DrainToken
	e.mustJSON(200, "POST", "/v1/tokens/drain", "", gen.DrainRequest{DeviceId: oldDev.ID, Assertion: oldDev.Assert(e.d.Clock.Now(), e.jti(), service.AssertionClaims{})}, &dt)
	e.expect(404, "", "GET", "/v1/devices/"+oldDev.ID+"/wipe-order", dt.AccessToken, nil)
}

// A3.2 rows 1, 4, 5: credential, recovery record and the revocation feed's reason.
func TestDirectoryCredentialRecoveryAndRevocationReason(t *testing.T) {
	e := newEnv(t)
	owner, _ := e.ownerSession()
	tok := owner.Tokens.AccessToken
	oldDev, newDev := double.NewDevice(newID()), double.NewDevice(newID())
	e.activate(tok, gen.Pos, oldDev)
	e.activate(tok, gen.Pos, newDev)
	svc := func(tenant string) []string {
		return []string{"Hostry-Service-Token", e.d.ServiceToken("sync", orgID(tenant))}
	}

	var c gen.DeviceCredential
	e.mustJSON(200, "GET", "/internal/v1/devices/"+newDev.ID+"/credential", "", nil, &c, svc(org.String())...)
	k := crypto.JWK{X: newDev.JWK().X, Y: newDev.JWK().Y}
	if want, _ := service.PubX962(k); c.Pub != want || c.Kid != newDev.KID() || c.OutletId != outletA || c.Kind != gen.Pos || c.TenantId != org.String() || c.Recovers != nil {
		t.Fatalf("credential: %+v", c)
	}
	// Tenant isolation: another organisation's gateway token cannot see it, and an unknown device is 404.
	e.expect(404, "", "GET", "/internal/v1/devices/"+newDev.ID+"/credential", "", nil, svc(newID())...)
	e.expect(404, "", "GET", "/internal/v1/devices/"+newID()+"/credential", "", nil, svc(org.String())...)
	e.expect(404, "", "GET", "/internal/v1/devices/"+oldDev.ID+"/recovery", "", nil, svc(org.String())...)

	rec := newID()
	if err := e.d.Service.Seed().KeyLossRecovery(e.ctx, org.String(), rec, oldDev.ID, newDev.ID, owner.MemberId); err != nil {
		t.Fatal(err)
	}
	e.mustJSON(200, "GET", "/internal/v1/devices/"+newDev.ID+"/credential", "", nil, &c, svc(org.String())...)
	if c.Recovers == nil || *c.Recovers != oldDev.ID {
		t.Fatalf("the adopting credential must name the device it recovers: %+v", c)
	}
	e.mustJSON(200, "GET", "/internal/v1/devices/"+oldDev.ID+"/credential", "", nil, &c, svc(org.String())...) // any state
	var r gen.DeviceRecovery
	e.mustJSON(200, "GET", "/internal/v1/devices/"+oldDev.ID+"/recovery", "", nil, &r, svc(org.String())...)
	if r.State != gen.DeviceRecoveryStateOpen || r.ApproverId != owner.MemberId {
		t.Fatalf("recovery: %+v", r)
	}
	e.expect(404, "", "GET", "/internal/v1/devices/"+oldDev.ID+"/recovery", "", nil, svc(newID())...)

	// Revocation feed: key_lost carries the recovery id; an ordinary revocation says revoked.
	third := double.NewDevice(newID())
	e.activate(tok, gen.Pos, third)
	e.mustJSON(200, "PUT", "/v1/devices/"+third.ID+"/revocation", tok, gen.RevokeDevice{Reason: gen.RevokeDeviceReasonStolen}, &gen.Device{})
	var feed gen.RevocationPage
	e.mustJSON(200, "GET", "/internal/v1/revocations", "", nil, &feed, "Hostry-Service-Token", e.d.ServiceToken("sync", ""))
	got := map[string]gen.Revocation{}
	for _, it := range feed.Items {
		got[it.SubjectId] = it
	}
	lost, ord := got[oldDev.ID], got[third.ID]
	if lost.Reason == nil || *lost.Reason != gen.RevocationReasonKeyLost || lost.RecoveryId == nil || *lost.RecoveryId != rec {
		t.Fatalf("key_lost row: %+v", lost)
	}
	if ord.Reason == nil || *ord.Reason != gen.RevocationReasonRevoked || ord.RecoveryId != nil {
		t.Fatalf("revoked row: %+v", ord)
	}
}

// A3.2 rows 2, 3, 7: the permission sets of each pack version are kept; member grants are current; a pack_v-less
// history check means any pack ever issued.
func TestDirectoryPackGrantsAndMemberGrants(t *testing.T) {
	e := newEnv(t)
	owner, _ := e.ownerSession()
	tok := owner.Tokens.AccessToken
	sd := e.d.Service.Seed()
	roleID, staff := newID(), newID()
	if err := sd.Role(e.ctx, org.String(), roleID, "Cashier", []string{"member.read"}); err != nil {
		t.Fatal(err)
	}
	if err := sd.Member(e.ctx, org.String(), service.SeedMember{ID: staff, Name: "Ravi", Mobile: "+919333333333", Assignments: []service.SeedAssignment{{ID: newID(), RoleID: roleID, Outlets: []string{outletA}}}}); err != nil {
		t.Fatal(err)
	}
	dev := double.NewDevice(newID())
	act := e.activate(tok, gen.Pos, dev)
	v1 := act.OfflinePack.PackV
	svc := []string{"Hostry-Service-Token", e.d.ServiceToken("sync", org)}
	grants := func(v int) (int, gen.PackGrants) {
		code, b, _ := e.do("GET", fmt.Sprintf("/internal/v1/devices/%s/packs/%d/grants", dev.ID, v), "", nil, svc...)
		var g gen.PackGrants
		if code == 200 {
			mustUnmarshal(e.t, b, &g)
		}
		return code, g
	}
	permsOf := func(g gen.PackGrants, m string) []string {
		for _, x := range g.Members {
			if x.MemberId == m {
				return x.Permissions
			}
		}
		return nil
	}
	_, g1 := grants(v1)
	if !slices.Contains(permsOf(g1, staff), "member.read") || !g1.OfflineValidUntil.After(g1.IssuedAt) || g1.PackV != v1 {
		t.Fatalf("pack %d grants: %+v", v1, g1)
	}
	// A new member changes the pack: version 2 lists her, version 1 still answers what it granted then.
	late := newID()
	if err := sd.Member(e.ctx, org.String(), service.SeedMember{ID: late, Name: "Latha", Mobile: "+919444444444", Assignments: []service.SeedAssignment{{ID: newID(), RoleID: roleID, Outlets: []string{outletA}}}}); err != nil {
		t.Fatal(err)
	}
	var dtok gen.DeviceToken
	e.mustJSON(200, "POST", "/v1/tokens/device", "", gen.DeviceGrant{GrantType: gen.DeviceGrantGrantTypeDevice, DeviceId: dev.ID, Assertion: dev.Assert(e.d.Clock.Now(), e.jti(), service.AssertionClaims{})}, &dtok)
	var p2 gen.OfflinePack
	e.mustJSON(200, "GET", "/v1/devices/"+dev.ID+"/offline-packs/latest", dtok.AccessToken, nil, &p2)
	if p2.PackV != v1+1 {
		t.Fatalf("pack_v %d, want %d", p2.PackV, v1+1)
	}
	_, g2 := grants(p2.PackV)
	_, g1again := grants(v1)
	if permsOf(g2, late) == nil || permsOf(g1again, late) != nil || permsOf(g1again, staff) == nil {
		t.Fatalf("history: v2 %+v v1 %+v", g2, g1again)
	}
	// An unknown version, and another organisation's device, are 404.
	if code, _ := grants(p2.PackV + 5); code != 404 {
		t.Fatalf("unknown pack_v: %d", code)
	}
	e.expect(404, "", "GET", fmt.Sprintf("/internal/v1/devices/%s/packs/%d/grants", dev.ID, v1), "", nil, "Hostry-Service-Token", e.d.ServiceToken("sync", orgID(newID())))

	// Member grants are the present ones, at the outlet; a suspended member holds nothing.
	var mg gen.MemberGrants
	e.mustJSON(200, "GET", "/internal/v1/members/"+staff+"/grants?outlet_id="+outletA, "", nil, &mg, svc...)
	if mg.Status != "active" || !slices.Contains(mg.Permissions, "member.read") {
		t.Fatalf("member grants: %+v", mg)
	}
	e.mustJSON(200, "GET", "/internal/v1/members/"+staff+"/grants?outlet_id="+outletB, "", nil, &mg, svc...)
	if len(mg.Permissions) != 0 {
		t.Fatalf("a role scoped to another outlet grants nothing here: %+v", mg)
	}
	e.mustJSON(200, "PATCH", "/v1/members/"+staff, tok, gen.UpdateMember{Status: statusPtr(gen.UpdateMemberStatusSuspended)}, &gen.Member{})
	e.mustJSON(200, "GET", "/internal/v1/members/"+staff+"/grants?outlet_id="+outletA, "", nil, &mg, svc...)
	if mg.Status != "suspended" || len(mg.Permissions) != 0 {
		t.Fatalf("suspended member: %+v", mg)
	}
	e.expect(404, "", "GET", "/internal/v1/members/"+staff+"/grants?outlet_id="+outletA, "", nil, "Hostry-Service-Token", e.d.ServiceToken("sync", orgID(newID())))

	// checkPackHistory without pack_v: any pack issued to the device; with it, that one only.
	check := func(in gen.PackHistoryCheck) gen.PackHistoryVerdict {
		var v gen.PackHistoryVerdict
		e.mustJSON(200, "POST", "/internal/v1/pack-history-checks", "", in, &v, svc...)
		return v
	}
	if v := check(gen.PackHistoryCheck{DeviceId: dev.ID, MemberId: &late}); !v.PackKnown || !v.MemberInPack {
		t.Fatalf("any pack lists the late member: %+v", v)
	}
	if v := check(gen.PackHistoryCheck{DeviceId: dev.ID, MemberId: &late, PackV: &v1}); !v.PackKnown || v.MemberInPack {
		t.Fatalf("pack %d does not list her: %+v", v1, v)
	}
	if v := check(gen.PackHistoryCheck{DeviceId: newID()}); v.PackKnown {
		t.Fatalf("a device with no packs: %+v", v)
	}
}

// A3.2 row 6: a strong session's fixed facts; its end is dated; another tenant's session is 404.
func TestDirectorySessionFacts(t *testing.T) {
	e := newEnv(t)
	owner, dev := e.ownerSession()
	svc := []string{"Hostry-Service-Token", e.d.ServiceToken("sync", org)}
	var f gen.SessionFacts
	e.mustJSON(200, "GET", "/internal/v1/sessions/"+owner.SessionId, "", nil, &f, svc...)
	if f.MemberId != owner.MemberId || f.DeviceId == nil || *f.DeviceId != dev.ID || f.EndedAt != nil {
		t.Fatalf("facts: %+v", f)
	}
	e.expect(404, "", "GET", "/internal/v1/sessions/"+owner.SessionId, "", nil, "Hostry-Service-Token", e.d.ServiceToken("sync", orgID(newID())))
	e.expect(404, "", "GET", "/internal/v1/sessions/"+newID(), "", nil, svc...)
	e.d.Clock.Advance(time.Minute)
	svc = []string{"Hostry-Service-Token", e.d.ServiceToken("sync", org)}
	e.expect(204, "", "DELETE", "/v1/sessions/"+owner.SessionId, owner.Tokens.AccessToken, nil)
	e.mustJSON(200, "GET", "/internal/v1/sessions/"+owner.SessionId, "", nil, &f, svc...)
	if f.EndedAt == nil || !f.EndedAt.Equal(e.d.Clock.Now()) {
		t.Fatalf("ended_at %v, want %v", f.EndedAt, e.d.Clock.Now())
	}
	var feed gen.RevocationPage
	e.mustJSON(200, "GET", "/internal/v1/revocations", "", nil, &feed, "Hostry-Service-Token", e.d.ServiceToken("sync", ""))
	if len(feed.Items) != 1 || feed.Items[0].SubjectType != gen.RevocationSubjectTypeSession || feed.Items[0].SubjectId != owner.SessionId {
		t.Fatalf("the end of a session arrives on the revocation feed: %+v", feed.Items)
	}
}
