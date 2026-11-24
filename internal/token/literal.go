package token

import (
	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/svc-identity/service"
)

// Literal wraps a Signer and returns the literal tokens of the API specification's examples
// ("tok_example_access"). The contract requires a double to serve the spec's examples, which are
// not verifiable tokens; this issuer exists for that contract run only and is never wired into
// the real service.
type Literal struct{ Inner *Signer }

// Access implements service.TokenIssuer.
func (Literal) Access(c auth.Claims) (string, error) {
	switch c.Type {
	case auth.TypeDrain:
		return "tok_example_drain", nil
	case auth.TypeApproval:
		return "tok_example_approval", nil
	case auth.TypeSupport:
		return "tok_example_support", nil
	}
	return "tok_example_access", nil
}

// Vendor implements service.TokenIssuer.
func (Literal) Vendor(auth.Claims) (string, error) { return "tok_example_vendor", nil }

// Opaque implements service.TokenIssuer.
func (Literal) Opaque() string { return "tok_example_refresh" }

// Pack implements service.TokenIssuer.
func (Literal) Pack(claims any) (string, error) {
	if m, ok := claims.(map[string]any); ok && m["typ"] == "wipe" {
		return "wipe.jws.example", nil
	}
	return "pack.jws.example", nil
}

// JWKS implements service.TokenIssuer.
func (l Literal) JWKS(vendor bool) []service.KeyInfo { return l.Inner.JWKS(vendor) }

var _ service.TokenIssuer = Literal{}
