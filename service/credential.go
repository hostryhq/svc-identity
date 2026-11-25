package service

import (
	"time"

	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/svc-identity/internal/gen"
)

// CredentialTyp is the JWS header type of the LAN credential; it separates it from the op credential
// envelope (sync/protocol-v1.md, LAN credential).
const CredentialTyp = "hostry-cred+jws"

func ptr[T any](v T) *T { return &v }

// storeOf is the store claim of a device row: a row from before the claim existed is unprotected.
func storeOf(d *device) gen.StoreProtection {
	if d.Store == string(gen.Protected) {
		return gen.Protected
	}
	return gen.Unprotected
}

// declaredStore is what the build declared at activation; absent means unprotected (ADR-0002 A3.5 item 1).
func declaredStore(in *gen.StoreProtection) string {
	if in != nil && *in == gen.Protected {
		return string(gen.Protected)
	}
	return string(gen.Unprotected)
}

// liveEnvironment reports whether the service runs for real customers: anything but dev, test and ci.
func (s *Service) liveEnvironment() bool {
	switch s.Cfg.Environment {
	case "dev", "test", "ci":
		return false
	}
	return true
}

// checkStore refuses an `unprotected` declaration (the browser build, a hub on a key file, or no
// declaration) outside HOSTRY_ENV dev, test and ci, before anything is registered or a code is spent
// (ADR-0002 A3.3 item 3, A3.5 item 1). The declaration is the build's own statement: it guards against
// a wrong build, not a modified one.
func (s *Service) checkStore(in *gen.StoreProtection) error {
	if declaredStore(in) == string(gen.Unprotected) && s.liveEnvironment() {
		return apperr.New(apperr.Validation, "store.unprotected_refused", "this build keeps its data in a store that is not protected, which is not allowed outside development and test")
	}
	return nil
}

// credentialJWS signs the device's credential for the LAN (ADR-0002 A3.4 item 1): the claims of
// getDeviceCredential plus `not_after` (unix seconds, the pack's offline_valid_until). The payload is
// a map so encoding/json emits sorted keys with no insignificant space, which is RFC 8785 for these
// ASCII members and integer.
func (s *Service) credentialJWS(d *device, notAfter time.Time) (string, error) {
	pub, err := PubX962(d.Key)
	if err != nil {
		return "", err
	}
	c := map[string]any{
		"device_id": d.ID, "tenant_id": d.TenantID, "outlet_id": d.OutletID, "brand_id": d.BrandID,
		"kind": d.Kind, "kid": DeviceKID(d.ID), "pub": pub, "store": string(storeOf(d)), "not_after": notAfter.Unix(),
	}
	if d.Recovers != "" {
		c["recovers"] = d.Recovers
	}
	return s.Tokens.Credential(c)
}
