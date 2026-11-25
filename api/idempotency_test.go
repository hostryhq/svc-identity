package api_test

import (
	"strings"
	"testing"
	"time"

	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/service"
)

// SR-H4: a response that carries a one-time secret is never stored for replay. The replay is 409
// idempotency.replay_secret and the body does not contain the secret; a response without secrets
// still replays byte for byte.
func TestIdempotencyNeverStoresOrReplaysSecrets(t *testing.T) {
	e := newEnv(t)
	owner, _ := e.ownerSession()
	tok := owner.Tokens.AccessToken

	body := gen.CreateActivationCode{OutletId: outletA, Kind: gen.Pos}
	var code gen.ActivationCode
	e.mustJSON(201, "POST", "/v1/activation-codes", tok, body, &code, "Idempotency-Key", "ac-1")
	c, b, _ := e.do("POST", "/v1/activation-codes", tok, body, "Idempotency-Key", "ac-1")
	if c != 409 || problemCode(b) != "idempotency.replay_secret" || strings.Contains(string(b), code.Code) {
		t.Fatalf("replay of an activation code: %d %s", c, b)
	}

	role := gen.RoleInput{Name: "Cashier", Permissions: []string{"member.read"}}
	c1, b1, _ := e.do("POST", "/v1/roles", tok, role, "Idempotency-Key", "role-1")
	c2, b2, _ := e.do("POST", "/v1/roles", tok, role, "Idempotency-Key", "role-1")
	if c1 != 201 || c2 != 201 || string(b1) != string(b2) {
		t.Fatalf("a response without secrets still replays: %d %d", c1, c2)
	}
}

// SR-H4: a replayed refresh is not answered from a stored response; it runs again and meets reuse
// detection, which ends the lineage (ADR-0005 section 2).
func TestReplayedRefreshGoesThroughReuseDetection(t *testing.T) {
	e := newEnv(t)
	owner, dev := e.ownerSession()
	old := *owner.Tokens.RefreshToken
	refresh := func(rt string) (int, []byte) {
		c, b, _ := e.do("POST", "/v1/tokens/refresh", "", gen.RefreshSession{RefreshToken: rt, DeviceId: dev.ID,
			Proof: dev.Assert(e.d.Clock.Now(), e.jti(), service.AssertionClaims{Rth: service.RefreshHash(rt)})}, "Idempotency-Key", "refresh-1")
		return c, b
	}
	e.d.Clock.Advance(time.Minute)
	c, b := refresh(old)
	if c != 200 {
		t.Fatalf("first refresh: %d %s", c, b)
	}
	var tp gen.TokenPair
	mustUnmarshal(t, b, &tp)
	c, b = refresh(old) // the captured request replayed with the same key
	if c != 401 || strings.Contains(string(b), "refresh_token") {
		t.Fatalf("replayed refresh must be refused by reuse detection: %d %s", c, b)
	}
	if c, _ := refresh(*tp.RefreshToken); c != 401 {
		t.Fatalf("reuse must end the lineage: %d", c)
	}
}
