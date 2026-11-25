package service

import (
	"sort"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/grantlimit"
	"github.com/hostryhq/svc-identity/internal/crypto"
)

type catalogueEntry struct {
	Key, Realm, Service, DescriptionKey                                string
	Sensitive, StrongOnly, SupportViewable, SupportActable, OwnerGrant bool
}

// NewCatalogue builds the go-auth permission catalogue from the generated entries, with the
// catalogue lints (strong_only implies owner_grant; support_actable refused on sensitive ones).
func NewCatalogue(extra ...string) (*auth.Catalogue, error) {
	ps := make([]auth.Permission, 0, len(catalogueEntries)+len(extra))
	for _, k := range extra {
		ps = append(ps, auth.Permission{Name: k, Owner: "product"})
	}
	for _, e := range catalogueEntries {
		ps = append(ps, auth.Permission{Name: e.Key, Owner: e.Service, Sensitive: e.Sensitive, StrongOnly: e.StrongOnly,
			SupportViewable: e.SupportViewable, SupportActable: e.SupportActable, OwnerGrant: e.OwnerGrant})
	}
	return auth.NewCatalogue(ps...)
}

// PermissionRealm returns the realm of a catalogue permission (tenant, vendor or service), or ""
// when the key is not in the catalogue.
func PermissionRealm(key string) string {
	for _, e := range catalogueEntries {
		if e.Key == key {
			return e.Realm
		}
	}
	return ""
}

// VendorPermissions returns the permissions of a vendor role.
func VendorPermissions(role string) []string {
	return append([]string(nil), vendorRolePermissions[role]...)
}

// tenantPermission reports whether key is a tenant-realm permission (what roles may contain).
func tenantPermission(key string) (catalogueEntry, bool) {
	for _, e := range catalogueEntries {
		if e.Key == key && e.Realm == "tenant" {
			return e, true
		}
	}
	return catalogueEntry{}, false
}

// ---- documents ----

type account struct {
	ID        string    `json:"id"`
	Mobile    string    `json:"mobile"` // E.164; stored in this service only, never logged
	CreatedAt time.Time `json:"created_at"`
	Email     string    `json:"email,omitempty"`
	Verified  bool      `json:"email_verified,omitempty"` // a verified email disables the vendor-assisted code
	// NoStepUpUntil is set after a vendor-assisted sign-in: no step-up challenge for 24 hours (A2.3).
	NoStepUpUntil time.Time `json:"no_step_up_until,omitempty"`
	// RecoveryNeedsAdmin: after a tenant-side cancel, a new recovery needs a platform_admin approver.
	RecoveryNeedsAdmin bool `json:"recovery_needs_admin,omitempty"`
}

type membership struct {
	MemberID  string `json:"member_id"`
	TenantID  string `json:"tenant_id"`
	AccountID string `json:"account_id"`
}

type assignment struct {
	ID      string   `json:"id"`
	RoleID  string   `json:"role_id"`
	Outlets []string `json:"outlets,omitempty"` // empty: organisation-wide
}

type proofKey struct {
	PinV  int       `json:"pin_v"`
	Enc   []byte    `json:"enc"`
	Until time.Time `json:"until,omitempty"` // zero for the current key
}

type member struct {
	ID          string       `json:"id"`
	TenantID    string       `json:"tenant_id"`
	DisplayName string       `json:"display_name"`
	Status      string       `json:"status"` // active, invited, suspended
	AccountID   string       `json:"account_id,omitempty"`
	Mobile      string       `json:"mobile,omitempty"` // for the trivial-PIN rule only; never returned
	Assignments []assignment `json:"assignments"`
	CreatedAt   time.Time    `json:"created_at"`

	PinV     int        `json:"pin_v"`
	PinSalt  string     `json:"pin_salt,omitempty"`
	PinVerif string     `json:"pin_verifier,omitempty"` // truncated to vbits; the full verifier is kept nowhere
	PinBits  int        `json:"vbits,omitempty"`
	PinLong  bool       `json:"pin_long,omitempty"` // a 6-digit PIN was set
	Proofs   []proofKey `json:"proof_keys,omitempty"`
}

type role struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	BuiltIn   bool      `json:"built_in"`
	Perms     []string  `json:"permissions"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type device struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"tenant_id"`
	OutletID   string     `json:"outlet_id"`
	Kind       string     `json:"kind"`
	Name       string     `json:"name"`
	State      string     `json:"state"` // active, revoked, drained, wiped, lost
	KeyProt    string     `json:"key_protection"`
	Billing    string     `json:"billing_capability"`
	Key        crypto.JWK `json:"key"`
	Thumb      string     `json:"thumb"`
	AccountID  string     `json:"account_id,omitempty"`    // personal devices: the holder
	Activation string     `json:"activation_id,omitempty"` // the activation code that registered it (M2)
	CreatedAt  time.Time  `json:"registered_at"`
	LastSeen   time.Time  `json:"last_contact_at,omitempty"`
	RevokedAt  time.Time  `json:"revoked_at,omitempty"`
	DrainedAt  time.Time  `json:"drained_at,omitempty"`
	DrainedThr []stream   `json:"drained_through,omitempty"`
	Lineages   []string   `json:"lineages,omitempty"` // refresh lineages seen (clone detection)
	// Series are the document-series codes tenancy issued to the device (billing kinds); RegUnverified
	// marks a billing device that registered while its outlet's tax registration was not verified.
	Series        []devSeries `json:"series,omitempty"`
	RegUnverified bool        `json:"registration_unverified,omitempty"`
}

type stream struct {
	Stream string `json:"stream"`
	Seq    int    `json:"seq"`
}

type packHist struct {
	ID      string    `json:"id"` // device id + ":" + pack_v
	Device  string    `json:"device"`
	PackV   int       `json:"pack_v"`
	Members []string  `json:"members"`
	Digest  string    `json:"digest"`
	Series  []string  `json:"series"`
	At      time.Time `json:"at"`
}

// holdings computes what a member effectively holds: per permission, the outlets (grantlimit).
func holdings(m *member, roles map[string]*role, ownerRoleID string) grantlimit.Holdings {
	h := grantlimit.Holdings{MemberID: m.ID, Perms: map[string]auth.OutletScope{}}
	type acc struct {
		all bool
		ids []string
	}
	accs := map[string]*acc{}
	for _, a := range m.Assignments {
		r := roles[a.RoleID]
		if r == nil {
			continue
		}
		if a.RoleID == ownerRoleID {
			h.Owner = true
		}
		for _, p := range r.Perms {
			if p == auth.Wildcard {
				continue
			}
			c := accs[p]
			if c == nil {
				c = &acc{}
				accs[p] = c
			}
			if len(a.Outlets) == 0 {
				c.all = true
			} else {
				c.ids = append(c.ids, a.Outlets...)
			}
		}
	}
	for p, c := range accs {
		if c.all {
			h.Perms[p] = auth.AllOutlets()
		} else {
			h.Perms[p] = auth.OnlyOutlets(c.ids...)
		}
	}
	return h
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
