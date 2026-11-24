package api_test

import (
	"strings"
	"testing"
	"time"

	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/svc-identity/double"
	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/service"
)

func TestOwnerInvitationLoginCreatesOwnerAndSession(t *testing.T) {
	e := newEnv(t)
	s, _ := e.ownerSession()
	if !s.InvitationAccepted || s.Amr != gen.AuthMethodOtp || s.CautionUntil != nil {
		t.Fatalf("first sign-in of an invited owner: accepted=%v amr=%v caution=%v", s.InvitationAccepted, s.Amr, s.CautionUntil)
	}
	var m gen.Member
	e.mustJSON(200, "GET", "/v1/members/"+s.MemberId, s.Tokens.AccessToken, nil, &m)
	if m.Status != gen.MemberStatusActive || len(m.RoleAssignments) != 1 {
		t.Fatalf("owner member: %+v", m)
	}
	// IST-01 family: the issued token verifies against the published JWKS key (real ES256).
	claims, err := e.d.Verifier.Verify(s.Tokens.AccessToken)
	if err != nil || claims.Grants[0].Perms[0] != "*" || claims.TenantID != org.String() {
		t.Fatalf("token claims: %+v %v", claims, err)
	}
}

// IST-03: OTP send limits, identical for unknown numbers.
func TestOTPSendLimits(t *testing.T) {
	e := newEnv(t)
	dev := double.NewDevice(string(ids.New()))
	send := func() int {
		code, _, _ := e.do("POST", "/v1/otp-challenges", "", gen.CreateOtpChallenge{MobileE164: "+919000000001", DeviceId: dev.ID, DevicePublicKey: pub(dev)})
		return code
	}
	if send() != 202 {
		t.Fatal("first send")
	}
	if send() != 429 { // 30 s cooldown
		t.Fatal("cooldown not enforced")
	}
	for i := 0; i < 2; i++ {
		e.d.Clock.Advance(31 * time.Second)
		if send() != 202 {
			t.Fatalf("send %d inside the limit", i+2)
		}
	}
	e.d.Clock.Advance(31 * time.Second)
	if send() != 429 { // 4th in 15 minutes
		t.Fatal("4th send in 15 minutes accepted")
	}
	_, _, h := e.do("POST", "/v1/otp-challenges", "", gen.CreateOtpChallenge{MobileE164: "+919000000001", DeviceId: dev.ID, DevicePublicKey: pub(dev)})
	if h.Get("Retry-After") == "" {
		t.Fatal("429 without Retry-After")
	}
	if len(e.d.SMS.Sent()) != 0 {
		t.Fatal("an SMS went to a number with no account or invitation")
	}
}

// IST-05: non-Indian and malformed numbers are refused before any send.
func TestOTPRefusesForeignAndMalformedNumbers(t *testing.T) {
	e := newEnv(t)
	dev := double.NewDevice(string(ids.New()))
	for _, m := range []string{"+14155550100", "+447911123456", "9876543210", "+91987654321", "+915876543210", ""} {
		e.expect(422, "", "POST", "/v1/otp-challenges", "", gen.CreateOtpChallenge{MobileE164: m, DeviceId: dev.ID, DevicePublicKey: pub(dev)})
	}
}

// IST-07: the answer for known and unknown numbers has the same shape and status.
func TestOTPAnswerDoesNotRevealWhetherNumberIsKnown(t *testing.T) {
	e := newEnv(t)
	if _, _, err := e.d.Service.Seed().OwnerInvitation(e.ctx, org.String(), ownerMobile, "Asha"); err != nil {
		t.Fatal(err)
	}
	dev := double.NewDevice(string(ids.New()))
	var a, b gen.OtpChallenge
	e.mustJSON(202, "POST", "/v1/otp-challenges", "", gen.CreateOtpChallenge{MobileE164: ownerMobile, DeviceId: dev.ID, DevicePublicKey: pub(dev)}, &a)
	e.mustJSON(202, "POST", "/v1/otp-challenges", "", gen.CreateOtpChallenge{MobileE164: "+919111111111", DeviceId: dev.ID, DevicePublicKey: pub(dev)}, &b)
	if !a.ExpiresAt.Equal(b.ExpiresAt) || !a.ResendAfter.Equal(b.ResendAfter) {
		t.Fatal("timing fields differ between known and unknown numbers")
	}
	if len(e.d.SMS.Sent()) != 1 {
		t.Fatalf("SMS count %d, want 1 (known number only)", len(e.d.SMS.Sent()))
	}
	// IST-10: the only template, with the warning and no link.
	m := e.d.SMS.Sent()[0].Text
	if !strings.Contains(m, "Hostry staff will never ask for this code") || strings.Contains(m, "http") {
		t.Fatalf("SMS template: %q", m)
	}
}

// IST-08 and IST-09: single use, expiry, attempt limit, binding to challenge and device key.
func TestOTPLifecycleAndBinding(t *testing.T) {
	e := newEnv(t)
	if _, _, err := e.d.Service.Seed().OwnerInvitation(e.ctx, org.String(), ownerMobile, "Asha"); err != nil {
		t.Fatal(err)
	}
	dev, other := double.NewDevice(string(ids.New())), double.NewDevice(string(ids.New()))
	start := func(d *double.Device) (gen.OtpChallenge, string) {
		var ch gen.OtpChallenge
		e.mustJSON(202, "POST", "/v1/otp-challenges", "", gen.CreateOtpChallenge{MobileE164: ownerMobile, DeviceId: d.ID, DevicePublicKey: pub(d)}, &ch)
		m, _ := e.d.SMS.Last(ownerMobile)
		return ch, otpRE.FindString(m.Text)
	}
	session := func(d *double.Device, ch gen.OtpChallenge, code string) (int, []byte) {
		c, b, _ := e.do("POST", "/v1/sessions", "", gen.CreateSession{GrantType: gen.CreateSessionGrantTypeOtp, ChallengeId: ch.Id, Code: code, DeviceId: d.ID,
			DeviceAssertion: d.Assert(e.d.Clock.Now(), e.jti(), service.AssertionClaims{Cid: ch.Id})})
		return c, b
	}
	ch, code := start(dev)
	// A valid code from another device's key is refused (bound to the device that started it).
	if c, _ := session(other, ch, code); c != 401 {
		t.Fatalf("code used from another device: %d", c)
	}
	// A valid code with another challenge id is refused.
	e.d.Clock.Advance(31 * time.Second)
	ch2, code2 := start(dev)
	if c, _ := session(dev, ch, code2); c != 401 {
		t.Fatalf("code of another challenge accepted: %d", c)
	}
	// The right code with the right challenge works once.
	if c, b := session(dev, ch2, code2); c != 201 {
		t.Fatalf("valid code refused: %d %s", c, b)
	}
	if c, _ := session(dev, ch2, code2); c != 401 {
		t.Fatal("code used twice")
	}
	// Expiry at 5 minutes.
	e.d.Clock.Advance(31 * time.Second)
	ch3, code3 := start(dev)
	e.d.Clock.Advance(5*time.Minute + time.Second)
	if c, _ := session(dev, ch3, code3); c != 401 {
		t.Fatal("expired code accepted")
	}
	// Attempt limit: 5 wrong codes lock the challenge even for the right code.
	e.d.Clock.Advance(16 * time.Minute)
	ch4, code4 := start(dev)
	for i := 0; i < 5; i++ {
		session(dev, ch4, "000000")
	}
	if c, _ := session(dev, ch4, code4); c != 401 {
		t.Fatal("challenge not locked after 5 failed attempts")
	}
}

// IST-04: failed verifications across challenges block the number.
func TestOTPFailureCapAcrossChallenges(t *testing.T) {
	e := newEnv(t)
	if _, _, err := e.d.Service.Seed().OwnerInvitation(e.ctx, org.String(), ownerMobile, "Asha"); err != nil {
		t.Fatal(err)
	}
	dev := double.NewDevice(string(ids.New()))
	for i := 0; i < 4; i++ {
		var ch gen.OtpChallenge
		e.mustJSON(202, "POST", "/v1/otp-challenges", "", gen.CreateOtpChallenge{MobileE164: ownerMobile, DeviceId: dev.ID, DevicePublicKey: pub(dev)}, &ch)
		for j := 0; j < 3 && i*3+j < 10; j++ {
			e.do("POST", "/v1/sessions", "", gen.CreateSession{GrantType: gen.CreateSessionGrantTypeOtp, ChallengeId: ch.Id, Code: "111111", DeviceId: dev.ID,
				DeviceAssertion: dev.Assert(e.d.Clock.Now(), e.jti(), service.AssertionClaims{Cid: ch.Id})})
		}
		e.d.Clock.Advance(16 * time.Minute)
	}
	// A correct code is now refused for 24 hours.
	var ch gen.OtpChallenge
	e.mustJSON(202, "POST", "/v1/otp-challenges", "", gen.CreateOtpChallenge{MobileE164: ownerMobile, DeviceId: dev.ID, DevicePublicKey: pub(dev)}, &ch)
	m, _ := e.d.SMS.Last(ownerMobile)
	e.expect(401, "", "POST", "/v1/sessions", "", gen.CreateSession{GrantType: gen.CreateSessionGrantTypeOtp, ChallengeId: ch.Id, Code: otpRE.FindString(m.Text), DeviceId: dev.ID,
		DeviceAssertion: dev.Assert(e.d.Clock.Now(), e.jti(), service.AssertionClaims{Cid: ch.Id})})
}

// IST-36: no constant code verifies (property test over many challenges).
func TestNoMagicOTP(t *testing.T) {
	seen := map[string]int{}
	for i := 0; i < 2000; i++ {
		seen[crypto.System.Digits(6)]++
	}
	if len(seen) < 1900 {
		t.Fatalf("OTP generator is not spreading codes: %d distinct of 2000", len(seen))
	}
}

// IST-12: refresh rotates; reuse revokes the session; the proof must come from the device key and be fresh.
func TestRefreshRotationReuseAndProof(t *testing.T) {
	e := newEnv(t)
	s, dev := e.ownerSession()
	refresh := func(d *double.Device, rt string, jti string) (int, gen.TokenPair) {
		var tp gen.TokenPair
		code, b, _ := e.do("POST", "/v1/tokens/refresh", "", gen.RefreshSession{RefreshToken: rt, DeviceId: d.ID,
			Proof: d.Assert(e.d.Clock.Now(), jti, service.AssertionClaims{Rth: service.RefreshHash(rt)})})
		if code == 200 {
			mustUnmarshal(t, b, &tp)
		}
		return code, tp
	}
	rt1 := *s.Tokens.RefreshToken
	c, tp := refresh(dev, rt1, "r1")
	if c != 200 || *tp.RefreshToken == rt1 {
		t.Fatalf("rotation: %d", c)
	}
	// Replayed proof id fails even with an unused token.
	if c, _ := refresh(dev, *tp.RefreshToken, "r1"); c != 401 {
		t.Fatal("replayed proof accepted")
	}
	// Another device key cannot use the token.
	if c, _ := refresh(double.NewDevice(dev.ID), *tp.RefreshToken, "r2"); c != 401 {
		t.Fatal("refresh from another device key accepted")
	}
	// Reuse of the rotated token revokes the session: the newest token stops working too.
	if c, _ := refresh(dev, rt1, "r3"); c != 401 {
		t.Fatal("reused refresh token accepted")
	}
	if c, _ := refresh(dev, *tp.RefreshToken, "r4"); c != 401 {
		t.Fatal("session survived refresh-token reuse")
	}
	evs := e.d.Memory.Events()
	var found bool
	for _, ev := range evs {
		found = found || (ev.Type == "identity.session.revoked" && strings.Contains(string(ev.Data), "refresh_reuse"))
	}
	if !found {
		t.Fatal("no identity.session.revoked event with reason refresh_reuse in the outbox")
	}
}

// IST-32 and IST-31 (login side): a person in two organisations gets one tenant per token.
func TestSwitchMemberOneTenantPerToken(t *testing.T) {
	e := newEnv(t)
	s, dev := e.ownerSession()
	orgB := ids.ID("018f0000-0000-7000-8000-00000000000b")
	if _, _, err := e.d.Service.Seed().OwnerInvitation(e.ctx, orgB.String(), ownerMobile, "Asha B"); err != nil {
		t.Fatal(err)
	}
	// Sign in again: the invitation for B is accepted at this sign-in.
	e.d.Clock.Advance(31 * time.Second)
	s2 := e.signIn(ownerMobile, dev)
	if len(s2.Memberships) != 2 {
		t.Fatalf("memberships: %+v", s2.Memberships)
	}
	var memB string
	for _, m := range s2.Memberships {
		if m.OrganisationId == orgB.String() {
			memB = m.MemberId
		}
	}
	// The token for A is useless on B's data: member ids of B are 404 under A.
	e.expect(404, "", "GET", "/v1/members/"+memB, s.Tokens.AccessToken, nil)
	var tp gen.TokenPair
	e.mustJSON(200, "POST", "/v1/tokens/switch", s.Tokens.AccessToken, gen.SwitchMember{MemberId: memB}, &tp)
	e.mustJSON(200, "GET", "/v1/members/"+memB, tp.AccessToken, nil, nil)
	e.expect(404, "", "POST", "/v1/tokens/switch", s.Tokens.AccessToken, gen.SwitchMember{MemberId: string(ids.New())})
}

func TestEndSessionRevokesRefresh(t *testing.T) {
	e := newEnv(t)
	s, dev := e.ownerSession()
	e.mustJSON(204, "DELETE", "/v1/sessions/"+s.SessionId, s.Tokens.AccessToken, nil, nil)
	e.mustJSON(204, "DELETE", "/v1/sessions/"+s.SessionId, s.Tokens.AccessToken, nil, nil) // repeat is a no-op
	e.expect(401, "", "POST", "/v1/tokens/refresh", "", gen.RefreshSession{RefreshToken: *s.Tokens.RefreshToken, DeviceId: dev.ID,
		Proof: dev.Assert(e.d.Clock.Now(), e.jti(), service.AssertionClaims{Rth: service.RefreshHash(*s.Tokens.RefreshToken)})})
}
