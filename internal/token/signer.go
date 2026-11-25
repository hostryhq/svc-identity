// Package token signs identity's tokens with ES256 (ADR-0005 section 2) and publishes the keys.
// Verification of incoming tokens is go-auth's job; this package only issues.
package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/service"
)

// Issuer and audience names of the two realms (separate keys, issuers and audiences, section 10).
const (
	TenantIssuer   = "hostry-identity"
	TenantAudience = "hostry-tenant"
	VendorIssuer   = service.GrantIssuer
	VendorAudience = "hostry-vendor"
)

// Key is a signing key with its id.
type Key struct {
	Kid  string
	Priv *ecdsa.PrivateKey
}

// Signer implements service.TokenIssuer with three independent keys: tenant realm, vendor realm
// and the pack-signing key. NextTenant, when set, is published in the JWKS and in packs at least
// 30 days before it first signs (rotation, section 2).
type Signer struct {
	TenantKey, VendorKey Key
	NextTenant           *Key
	Random               crypto.Random
}

// NewEphemeral generates fresh keys; used by tests, the double and dev runs without key files.
func NewEphemeral(r crypto.Random) (*Signer, error) {
	gen := func(kid string) (Key, error) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		return Key{Kid: kid, Priv: k}, err
	}
	var s Signer
	var err error
	if s.TenantKey, err = gen("k-tenant-1"); err != nil {
		return nil, err
	}
	if s.VendorKey, err = gen("v-vendor-1"); err != nil {
		return nil, err
	}
	n, err := gen("k-tenant-2")
	if err != nil {
		return nil, err
	}
	s.NextTenant = &n
	s.Random = r
	return &s, nil
}

// LoadKey reads a PKCS#8 PEM private key from a file (the path comes from configuration; the key
// itself is a secret referenced by name only).
func LoadKey(kid, path string) (Key, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Key{}, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return Key{}, errors.New("token: no PEM block in " + path)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return Key{}, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return Key{}, fmt.Errorf("token: %s is not a P-256 key", path)
	}
	return Key{Kid: kid, Priv: ec}, nil
}

func (s *Signer) sign(k Key, typ string, c auth.Claims, iss, aud string, realm auth.Realm) (string, error) {
	c.Issuer, c.Audience, c.Realm = iss, auth.Audience{aud}, realm
	return crypto.SignES256(k.Priv, k.Kid, typ, c)
}

// Access signs a tenant-realm token.
func (s *Signer) Access(c auth.Claims) (string, error) {
	return s.sign(s.TenantKey, "JWT", c, TenantIssuer, TenantAudience, auth.RealmTenant)
}

// Vendor signs a vendor-realm token.
func (s *Signer) Vendor(c auth.Claims) (string, error) {
	return s.sign(s.VendorKey, "JWT", c, VendorIssuer, VendorAudience, auth.RealmVendor)
}

// Opaque returns a 256-bit refresh token.
func (s *Signer) Opaque() string { return s.Random.Token() }

// VendorGrant signs a vendor approval grant with the vendor-realm key (ADR-0014 A1.3). Its claims are
// not go-auth's Claims: the executing service verifies the grant against the vendor JWKS.
func (s *Signer) VendorGrant(claims any) (string, error) {
	return crypto.SignES256(s.VendorKey.Priv, s.VendorKey.Kid, "JWT", claims)
}

// PackTyp is the JWS header type of an offline pack.
const PackTyp = "hostry-pack+jws"

// Wipe signs a wipe order with the identity key (the same published key as packs), header type "pack" as before.
func (s *Signer) Wipe(claims any) (string, error) {
	return crypto.SignES256(s.TenantKey.Priv, s.TenantKey.Kid, "pack", claims)
}

// Pack signs an offline pack with the current identity (tenant realm) key, one of the pack's own
// `identity_public_keys` (also served by the JWKS), under the header type hostry-pack+jws.
func (s *Signer) Pack(claims any) (string, error) {
	return crypto.SignES256(s.TenantKey.Priv, s.TenantKey.Kid, PackTyp, claims)
}

// Credential signs a device's LAN credential with the current identity (tenant realm) key, the key a
// pack publishes as identity_public_keys, under the header type hostry-cred+jws.
func (s *Signer) Credential(claims any) (string, error) {
	return crypto.SignES256(s.TenantKey.Priv, s.TenantKey.Kid, service.CredentialTyp, claims)
}

// JWKS lists the published keys of a realm: the current key and, for the tenant realm, the
// pre-published next key.
func (s *Signer) JWKS(vendor bool) []service.KeyInfo {
	if vendor {
		return []service.KeyInfo{{Kid: s.VendorKey.Kid, Key: crypto.ToJWK(&s.VendorKey.Priv.PublicKey)}}
	}
	out := []service.KeyInfo{{Kid: s.TenantKey.Kid, Key: crypto.ToJWK(&s.TenantKey.Priv.PublicKey)}}
	if s.NextTenant != nil {
		out = append(out, service.KeyInfo{Kid: s.NextTenant.Kid, Key: crypto.ToJWK(&s.NextTenant.Priv.PublicKey)})
	}
	return out
}

// TenantKeys and VendorKeys are the verification key sets of this service's own verifiers.
func (s *Signer) TenantKeys() *auth.StaticKeySet {
	m := map[string]*ecdsa.PublicKey{s.TenantKey.Kid: &s.TenantKey.Priv.PublicKey}
	if s.NextTenant != nil {
		m[s.NextTenant.Kid] = &s.NextTenant.Priv.PublicKey
	}
	return auth.NewStaticKeySet(auth.KeyDoc{Keys: m})
}

// VendorKeys is the vendor-realm key set.
func (s *Signer) VendorKeys() *auth.StaticKeySet {
	return auth.NewStaticKeySet(auth.KeyDoc{Keys: map[string]*ecdsa.PublicKey{s.VendorKey.Kid: &s.VendorKey.Priv.PublicKey}})
}

var _ service.TokenIssuer = (*Signer)(nil)
