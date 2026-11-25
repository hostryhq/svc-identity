package api_test

import (
	"testing"
	"time"

	"github.com/hostryhq/svc-identity/double"
	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/service"
)

type pinFixture struct {
	e     *env
	staff string
	dev   *double.Device
	pack  gen.OfflinePack
	sec   crypto.PinSecrets
}

func newPinFixture(t *testing.T) *pinFixture {
	e := newEnv(t)
	owner, _ := e.ownerSession()
	staff, roleID := newID(), newID()
	sd := e.d.Service.Seed()
	_ = sd.Role(e.ctx, org.String(), roleID, "Cashier", []string{"member.read"})
	_ = sd.Member(e.ctx, org.String(), service.SeedMember{ID: staff, Name: "Ravi", Assignments: []service.SeedAssignment{{ID: newID(), RoleID: roleID}}})
	salt, _ := sd.PinFor(e.ctx, org.String(), staff, "482916")
	dev := double.NewDevice(newID())
	pack := e.activate(owner.Tokens.AccessToken, gen.Pos, dev).OfflinePack
	return &pinFixture{e: e, staff: staff, dev: dev, pack: pack, sec: double.PinSecrets(e.d.Service.Cfg.PinParams, "482916", salt)}
}

func (f *pinFixture) grant(sid string, opened time.Time, proof string) int {
	g := gen.PinGrant{GrantType: gen.PinGrantGrantTypePin, DeviceId: f.dev.ID, MemberId: f.staff, SessionId: sid, PackV: f.pack.PackV, PinV: 1, OpenedAt: opened, SessionProof: proof}
	g.Assertion = f.dev.Assert(f.e.d.Clock.Now(), f.e.jti(), service.AssertionClaims{Sid: sid, Mid: f.staff, PackV: f.pack.PackV, PinV: 1, Opened: opened.UTC().Format("2006-01-02T15:04:05.000Z")})
	c, _, _ := f.e.do("POST", "/v1/tokens/device", "", g)
	return c
}

func (f *pinFixture) good(sid string, opened time.Time) string {
	return double.SessionProof(f.sec.ProofKey, sid, f.dev.ID, f.staff, f.pack.PackV, 1, opened)
}

// verify asks the gateway's question about a proof.
func (f *pinFixture) verify(sid string, opened time.Time, proof string) gen.ProofVerdict {
	var v gen.ProofVerdict
	f.e.mustJSON(200, "POST", "/internal/v1/proof-verifications", "", gen.ProofVerification{Kind: gen.ProofVerificationKindSession, DeviceId: f.dev.ID, MemberId: f.staff,
		SessionId: &sid, PackV: f.pack.PackV, PinV: 1, OpenedAt: &opened, Proof: proof}, &v, "Hostry-Service-Token", f.e.d.ServiceToken("sync", org))
	return v
}

// SR-H5: an honest login between failures clears only the 15-minute window. The 24-hour count
// stays, so a dishonest user who tries 4 wrong proofs per window between honest logins is locked
// at the tenth failure (ADR-0005 A2.1 item 5).
func TestSuccessfulPinLoginDoesNotResetTheDailyFailureCount(t *testing.T) {
	f := newPinFixture(t)
	e := f.e
	for round := 0; round < 3; round++ {
		for i := 0; i < 4; i++ {
			if round == 2 && i == 2 {
				break // the tenth failure is the second of round three
			}
			if c := f.grant(newID(), e.d.Clock.Now(), "bad"); c != 401 {
				t.Fatalf("round %d try %d: %d", round, i, c)
			}
		}
		e.d.Clock.Advance(16 * time.Minute)
		sid, opened := newID(), e.d.Clock.Now()
		c := f.grant(sid, opened, f.good(sid, opened))
		if round < 2 && c != 200 {
			t.Fatalf("round %d honest login: %d", round, c)
		}
		if round == 2 && c != 429 {
			t.Fatalf("locked after 10 failures in 24 hours, the right proof is refused: %d", c)
		}
	}
	// Still locked an hour later; an administrator clears it.
	e.d.Clock.Advance(time.Hour)
	sid, opened := newID(), e.d.Clock.Now()
	if c := f.grant(sid, opened, f.good(sid, opened)); c != 429 {
		t.Fatalf("lock must hold until cleared: %d", c)
	}
}

// SR-H5: the gateway's proof check counts failures once per session id and is answered "locked"
// without a check, so it cannot be used as an unlimited oracle for the truncated verifier.
func TestVerifyProofCountsFailuresAndAnswersLocked(t *testing.T) {
	f := newPinFixture(t)
	e := f.e
	opened := e.d.Clock.Now()
	sid := newID()
	for i := 0; i < 3; i++ { // the same session id counts once
		if v := f.verify(sid, opened, "wrong"); v.Valid || (v.Locked != nil && *v.Locked) {
			t.Fatalf("early verdict: %+v", v)
		}
	}
	for i := 0; i < 9; i++ { // nine more sessions: ten failures in total
		e.d.Clock.Advance(16 * time.Minute) // keep clear of the 5-in-15-minutes refusal
		if v := f.verify(newID(), e.d.Clock.Now(), "wrong"); v.Valid {
			t.Fatal("forged proof verified")
		}
	}
	sid2, opened2 := newID(), e.d.Clock.Now()
	v := f.verify(sid2, opened2, f.good(sid2, opened2))
	if v.Valid || v.Locked == nil || !*v.Locked {
		t.Fatalf("a locked pair is answered locked, never checked: %+v", v)
	}
	// The pin grant shares the counter.
	if c := f.grant(sid2, opened2, f.good(sid2, opened2)); c != 429 {
		t.Fatalf("pin grant on a pair locked at the gateway: %d", c)
	}
}
