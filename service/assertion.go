package service

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"time"

	"github.com/hostryhq/svc-identity/internal/crypto"
)

// AssertionAudience is the aud of every device assertion.
const AssertionAudience = "hostry-identity"

// AssertionClaims are the claims of a device-key assertion. Which fields a flow needs depends on
// the flow: a session assertion names the challenge, a refresh proof the refresh-token hash, a pin
// grant the fields of the session.open record (ADR-0005 A2.1).
type AssertionClaims struct {
	Aud    string `json:"aud"`
	Did    string `json:"did"`
	Jti    string `json:"jti"`
	Iat    int64  `json:"iat"`
	Cid    string `json:"cid,omitempty"` // OTP challenge id
	Rth    string `json:"rth,omitempty"` // refresh token hash
	Sid    string `json:"sid,omitempty"` // pin session id
	Mid    string `json:"mid,omitempty"` // member id
	PackV  int    `json:"pack_v,omitempty"`
	PinV   int    `json:"pin_v,omitempty"`
	Opened string `json:"opened_at,omitempty"`
	// Trusted is never read from the wire. Only the literal-example verifier used by contract
	// tests sets it; it makes the flows skip claim-versus-request binding checks.
	Trusted bool `json:"-"`
}

// ErrAssertion is returned for any assertion failure; callers learn nothing more (A2.1 item 5).
var ErrAssertion = errors.New("service: assertion refused")

// ES256Assertions verifies assertions signed with the device key.
type ES256Assertions struct {
	Skew time.Duration
}

// Verify implements AssertionVerifier.
func (v ES256Assertions) Verify(assertion string, key crypto.JWK, now time.Time) (AssertionClaims, error) {
	pub, err := crypto.FromJWK(key)
	if err != nil {
		return AssertionClaims{}, ErrAssertion
	}
	return verifyWith(assertion, pub, now, v.skew())
}

func (v ES256Assertions) skew() time.Duration {
	if v.Skew == 0 {
		return 60 * time.Second
	}
	return v.Skew
}

func verifyWith(assertion string, pub *ecdsa.PublicKey, now time.Time, skew time.Duration) (AssertionClaims, error) {
	pl, err := crypto.VerifyES256(assertion, pub)
	if err != nil {
		return AssertionClaims{}, ErrAssertion
	}
	var c AssertionClaims
	if json.Unmarshal(pl, &c) != nil || c.Aud != AssertionAudience || c.Jti == "" || c.Did == "" {
		return AssertionClaims{}, ErrAssertion
	}
	iat := time.Unix(c.Iat, 0)
	if iat.After(now.Add(skew)) || iat.Before(now.Add(-skew)) {
		return AssertionClaims{}, ErrAssertion
	}
	return c, nil
}
