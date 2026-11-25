// Package crypto holds the small, standard-library-only primitives identity needs: ES256 JWS,
// JWK conversion, HMAC and keyed hashes, TOTP and constant-time helpers. Token verification for
// requests is go-auth's job; this package signs tokens and verifies device assertions.
package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
)

var b64 = base64.RawURLEncoding

// B64 encodes to unpadded base64url.
func B64(b []byte) string { return b64.EncodeToString(b) }

// UnB64 decodes unpadded base64url.
func UnB64(s string) ([]byte, error) { return b64.DecodeString(s) }

// SignES256 returns a compact JWS over claims, signed with key, header carrying kid and typ.
func SignES256(key *ecdsa.PrivateKey, kid, typ string, claims any) (string, error) {
	h, err := json.Marshal(map[string]string{"alg": "ES256", "kid": kid, "typ": typ})
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	in := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	sum := sha256.Sum256([]byte(in))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return in + "." + b64.EncodeToString(sig), nil
}

// ErrBadJWS is returned for any malformed or unverifiable JWS; callers learn nothing more.
var ErrBadJWS = errors.New("crypto: bad jws")

// VerifyES256 verifies a compact JWS against pub and returns its payload. Only alg ES256 is
// accepted and header fields that redirect key lookup (jku, x5u, x5c, jwk, crit) are refused.
func VerifyES256(tok string, pub *ecdsa.PublicKey) (payload []byte, err error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || len(tok) > 8192 {
		return nil, ErrBadJWS
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, ErrBadJWS
	}
	var h map[string]any
	if json.Unmarshal(hb, &h) != nil || h["alg"] != "ES256" {
		return nil, ErrBadJWS
	}
	for _, f := range []string{"jku", "x5u", "x5c", "jwk", "crit"} {
		if _, bad := h[f]; bad {
			return nil, ErrBadJWS
		}
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, ErrBadJWS
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, ErrBadJWS
	}
	pl, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, ErrBadJWS
	}
	return pl, nil
}

// VerifyRaw verifies a raw r||s ES256 signature over msg (used for the registration nonce).
func VerifyRaw(pub *ecdsa.PublicKey, msg []byte, sigB64 string) bool {
	sig, err := b64.DecodeString(sigB64)
	if err != nil || len(sig) != 64 {
		return false
	}
	sum := sha256.Sum256(msg)
	return ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
}

// SignRaw produces the raw signature VerifyRaw accepts (tests and the double's client helpers).
func SignRaw(key *ecdsa.PrivateKey, msg []byte) (string, error) {
	sum := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return b64.EncodeToString(sig), nil
}

// JWK is a P-256 public key in JWK form.
type JWK struct {
	Kty, Crv, X, Y string
}

// ToJWK converts a public key.
func ToJWK(pub *ecdsa.PublicKey) JWK {
	x := make([]byte, 32)
	y := make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	return JWK{Kty: "EC", Crv: "P-256", X: b64.EncodeToString(x), Y: b64.EncodeToString(y)}
}

// FromJWK parses a P-256 public key and checks that the point is on the curve.
func FromJWK(j JWK) (*ecdsa.PublicKey, error) {
	if j.Kty != "EC" || j.Crv != "P-256" {
		return nil, ErrBadJWS
	}
	x, err1 := b64.DecodeString(j.X)
	y, err2 := b64.DecodeString(j.Y)
	if err1 != nil || err2 != nil || len(x) != 32 || len(y) != 32 {
		return nil, ErrBadJWS
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if _, err := pub.ECDH(); err != nil { // validates the point is on the curve
		return nil, ErrBadJWS
	}
	return pub, nil
}

// Thumbprint is the RFC 7638 SHA-256 thumbprint of a P-256 key, used to bind keys to records.
func Thumbprint(j JWK) string {
	s := `{"crv":"P-256","kty":"EC","x":"` + j.X + `","y":"` + j.Y + `"}`
	sum := sha256.Sum256([]byte(s))
	return b64.EncodeToString(sum[:])
}
