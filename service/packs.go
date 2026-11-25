package service

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/repository"
)

type packVer struct {
	Latest int    `json:"latest"`
	Digest string `json:"digest"`
	// Books are the manual books of the last good tenancy answer, carried while tenancy cannot answer.
	Books []gen.PackManualBook `json:"books,omitempty"`
}

// pinDevice reports whether a device kind offers PIN login, and so receives verifiers (IC-16).
func pinDevice(kind string) bool { return kind == "pos" || kind == "waiter" || kind == "personal" }

// packPermissions returns a member's effective permissions at an outlet: the union of
// organisation-wide roles and roles for that outlet. The owner wildcard is expanded to the
// tenant permissions that are not strong_only; strong_only permissions are never exercisable in
// a pack-based session (ADR-0005 section 5), so they are not carried (IC-20).
func (s *Service) packPermissions(m *member, roles map[string]*role, outlet string) []string {
	set := map[string]bool{}
	for _, a := range m.Assignments {
		r := roles[a.RoleID]
		if r == nil || (len(a.Outlets) > 0 && !slices.Contains(a.Outlets, outlet)) {
			continue
		}
		for _, p := range r.Perms {
			if p == auth.Wildcard {
				for _, e := range catalogueEntries {
					if e.Realm == "tenant" && !e.StrongOnly {
						set[e.Key] = true
					}
				}
				continue
			}
			if def, ok := s.Cat.Get(p); ok && !def.StrongOnly {
				set[p] = true
			}
		}
	}
	return sortedKeys(set)
}

func (s *Service) buildPack(ctx context.Context, tx repository.Tx, d *device) (gen.OfflinePack, error) {
	now := s.now()
	roles, _, err := s.loadRoles(tx, d.TenantID)
	if err != nil {
		return gen.OfflinePack{}, err
	}
	ms, err := list[member](tx, kMember, d.TenantID, "", 0)
	if err != nil {
		return gen.OfflinePack{}, err
	}
	members := []gen.PackMember{}
	var memberIDs []string
	for i := range ms {
		m := &ms[i]
		if m.Status == "invited" {
			continue
		}
		perms := s.packPermissions(m, roles, d.OutletID)
		assigned := false
		for _, a := range m.Assignments {
			if len(a.Outlets) == 0 || slices.Contains(a.Outlets, d.OutletID) {
				assigned = true
			}
		}
		if !assigned {
			continue
		}
		pm := gen.PackMember{MemberId: m.ID, DisplayName: m.DisplayName, Status: gen.PackMemberStatus(m.Status), Permissions: perms}
		if pinDevice(d.Kind) && m.PinVerif != "" {
			salt, v, bits := m.PinSalt, m.PinVerif, m.PinBits
			pv := m.PinV
			pm.PinSalt, pm.PinVerifier, pm.PinV, pm.Vbits = &salt, &v, &pv, &bits
		}
		members = append(members, pm)
		memberIDs = append(memberIDs, m.ID)
	}
	ds, err := findK1Devices(tx, d.TenantID, d.OutletID)
	if err != nil {
		return gen.OfflinePack{}, err
	}
	revoked := []string{}
	for _, o := range ds {
		if o.State != "active" {
			revoked = append(revoked, o.ID)
		}
	}
	series := packSeries(d)                             // issued by tenancy (the registry is its), stored with the device
	pv, err := get[packVer](tx, kPackVer, d.TenantID, d.ID)
	if err != nil {
		return gen.OfflinePack{}, err
	}
	if pv == nil {
		pv = &packVer{}
	}
	books := s.manualBooks(ctx, d, pv.Books)            // entry-only paper books of the outlet, from tenancy (A1.6 item 4); last good on an outage
	ent, err := s.packEntitlements(ctx, tx, d.TenantID) // nil until tenancy has answered once; never blocks a pack (ADR-0014 T10)
	if err != nil {
		return gen.OfflinePack{}, err
	}
	sum := sha256.New()
	digestParts := []any{members, revoked, series, d.State, books}
	if ent != nil { // appended only when present, so a pack without a snapshot keeps its earlier digest
		digestParts = append(digestParts, ent.EntitlementsV)
	}
	_ = json.NewEncoder(sum).Encode(digestParts)
	digest := crypto.B64(sum.Sum(nil))

	until := now.Add(time.Duration(s.Cfg.OfflineDays) * 24 * time.Hour)
	if pv.Digest != digest {
		pv.Latest++
		pv.Digest, pv.Books = digest, books
		if err := put(tx, kPackVer, d.TenantID, d.ID, pv, keys{}); err != nil {
			return gen.OfflinePack{}, err
		}
		gd, err := s.storePackGrants(tx, d.TenantID, members)
		if err != nil {
			return gen.OfflinePack{}, err
		}
		h := packHist{ID: d.ID + ":" + itoa(pv.Latest), Device: d.ID, PackV: pv.Latest, Members: memberIDs, Series: seriesCodes(d), Digest: digest, At: now, Until: until, Grants: gd}
		if err := put(tx, kPackHist, d.TenantID, h.ID, h, keys{k1: d.ID}); err != nil {
			return gen.OfflinePack{}, err
		}
	} else if h, err := get[packHist](tx, kPackHist, d.TenantID, d.ID+":"+itoa(pv.Latest)); err != nil {
		return gen.OfflinePack{}, err
	} else if h != nil && until.After(h.Until) {
		// The same version fetched again is valid offline until later: the gateway judges against the latest.
		h.Until = until
		if err := put(tx, kPackHist, d.TenantID, h.ID, h, keys{k1: d.ID}); err != nil {
			return gen.OfflinePack{}, err
		}
	}
	claims := gen.OfflinePackClaims{CatalogueVersion: CatalogueVersion, IdleLockMinutes: s.Cfg.IdleLockMinutes, IntentTableVersion: 1,
		IssuedAt: now, Members: members, OfflineValidUntil: until, OrganisationId: d.TenantID, PackV: pv.Latest,
		RevokedDeviceIds: revoked, Series: series}
	if len(books) > 0 {
		claims.ManualBooks = &books
	}
	claims.Entitlements = ent
	if d.BrandID == "" && s.Tenancy != nil { // a row from before ADR-0014 A3.4 that the backfill has not reached
		return gen.OfflinePack{}, errBrandUnknown()
	}
	claims.Device.DeviceId, claims.Device.Kind, claims.Device.OutletId = d.ID, gen.DeviceKind(d.Kind), d.OutletID
	claims.Device.BrandId, claims.Device.Kid = d.BrandID, DeviceKID(d.ID)
	claims.Device.PublicKey = gen.PublicJwk{Kty: gen.PublicJwkKtyEC, Crv: gen.PublicJwkCrvP256, X: d.Key.X, Y: d.Key.Y}
	for _, k := range s.Tokens.JWKS(false) {
		claims.IdentityPublicKeys = append(claims.IdentityPublicKeys, gen.Jwk{Kty: gen.JwkKtyEC, Crv: gen.JwkCrvP256, X: k.Key.X, Y: k.Key.Y, Kid: k.Kid, Alg: gen.ES256, Use: gen.Sig})
	}
	op := s.Cfg.OpSigning
	claims.OpSigningPublicKey = gen.Jwk{Kty: gen.JwkKtyEC, Crv: gen.JwkCrvP256, X: op.X, Y: op.Y, Kid: "op-1", Alg: gen.ES256, Use: gen.Sig}
	jws, err := s.Tokens.Pack(claims)
	if err != nil {
		return gen.OfflinePack{}, apperr.Wrap(apperr.Internal, "pack.sign_failed", "", err)
	}
	return gen.OfflinePack{Claims: claims, IssuedAt: now, Jws: jws, OfflineValidUntil: until, PackV: pv.Latest}, nil
}

func findK1Devices(tx repository.Tx, tenant, outlet string) ([]device, error) {
	return find[device](tx, kDevice, tenant, outlet)
}

// GetDeviceOfflinePack returns the newest pack for a device. A device (or a pin session of it) may
// fetch its own pack; a revoked device gets device_revoked and no pack.
func (s *Service) GetDeviceOfflinePack(ctx context.Context, id string) (gen.OfflinePack, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.OfflinePack{}, errUnauth()
	}
	var out gen.OfflinePack
	s.retryUnverifiedSeries(ctx, pr.TenantID, id)
	err := s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		d, err := get[device](tx, kDevice, pr.TenantID, id)
		if err != nil || d == nil {
			return notFoundOr(err)
		}
		if pr.DeviceID != id {
			if err := auth.Require(ctx, "device.read", d.OutletID); err != nil {
				return errNotFound()
			}
		}
		if d.State != "active" {
			return apperr.New(apperr.Forbidden, "device_revoked", "the device is revoked")
		}
		d.LastSeen = s.now()
		if err := put(tx, kDevice, pr.TenantID, id, d, keys{k1: d.OutletID}); err != nil {
			return err
		}
		out, err = s.buildPack(ctx, tx, d)
		return err
	})
	return out, err
}

// CheckPackHistory answers the gateway: was this device issued pack_v, did it list the member,
// was the series code issued to it (judged against the pack held, ADR-0005 section 7).
func (s *Service) CheckPackHistory(ctx context.Context, in gen.PackHistoryCheck) (gen.PackHistoryVerdict, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.PackHistoryVerdict{}, errUnauth()
	}
	var out gen.PackHistoryVerdict
	err := s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		var hs []packHist
		if in.PackV != nil {
			h, err := get[packHist](tx, kPackHist, pr.TenantID, in.DeviceId+":"+itoa(*in.PackV))
			if err != nil || h == nil {
				return err
			}
			hs = []packHist{*h}
		} else {
			// No pack_v: any pack ever issued to the device (the quarantine case, A3.2 row 7).
			var err error
			if hs, err = find[packHist](tx, kPackHist, pr.TenantID, in.DeviceId); err != nil {
				return err
			}
		}
		for i := range hs {
			out.PackKnown = true
			if in.MemberId != nil && slices.Contains(hs[i].Members, *in.MemberId) {
				out.MemberInPack = true
			}
			if in.SeriesCode != nil && slices.Contains(hs[i].Series, *in.SeriesCode) {
				out.SeriesIssued = true
			}
		}
		return nil
	})
	return out, err
}
