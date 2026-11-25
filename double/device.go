package double

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"time"

	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/service"
)

// Device is a client-side device key for tests: it signs assertions, nonces and proofs the way
// the shell does (ADR-0005 sections 5 to 7).
type Device struct {
	ID   string
	Priv *ecdsa.PrivateKey
}

// NewDevice generates a device key.
func NewDevice(id string) *Device {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return &Device{ID: id, Priv: k}
}

// JWK is the device's public key.
func (d *Device) JWK() crypto.JWK { return crypto.ToJWK(&d.Priv.PublicKey) }

// Assert signs an assertion with the given claims; aud, did, jti and iat are filled in.
func (d *Device) Assert(now time.Time, jti string, c service.AssertionClaims) string {
	c.Aud, c.Did, c.Jti, c.Iat = service.AssertionAudience, d.ID, jti, now.Unix()
	s, err := crypto.SignES256(d.Priv, "device", "JWT", c)
	if err != nil {
		panic(err)
	}
	return s
}

// SignNonce signs a registration nonce.
func (d *Device) SignNonce(nonce string) string {
	s, err := crypto.SignRaw(d.Priv, []byte(nonce))
	if err != nil {
		panic(err)
	}
	return s
}

// PinSecrets derives the verifier and proof key for a PIN with the given salt, as the shell does.
func PinSecrets(p crypto.PinParams, pin string, salt []byte) crypto.PinSecrets {
	s, err := crypto.DerivePin(p, pin, salt)
	if err != nil {
		panic(err)
	}
	return s
}

// KID is the key id identity gives the device's key (the credential's kid).
func (d *Device) KID() string { return service.DeviceKID(d.ID) }

// SignDrainStatement sets the key id and signs a drain statement the way the shell does (ADR-0005 A3.3):
// ES256, raw r||s, over "hostry-drain-v1\n" + the canonical JSON of the statement without its signature.
func (d *Device) SignDrainStatement(st gen.DrainStatement) gen.DrainStatement {
	st.Kid, st.Sig = d.KID(), ""
	msg, err := service.StatementMessage(st)
	if err != nil {
		panic(err)
	}
	if st.Sig, err = crypto.SignRaw(d.Priv, msg); err != nil {
		panic(err)
	}
	return st
}

// SessionProof makes the session proof for a pin session.
func SessionProof(proofKey []byte, sid, did, mid string, packV, pinV int, opened time.Time) string {
	return service.Proof(proofKey, service.SessionProofMessage(sid, did, mid, packV, pinV, opened))
}
