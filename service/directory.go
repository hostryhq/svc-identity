package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/repository"
)

// The directory questions of the sync gateway (ADR-0005 A3.2 rows 1 to 4 and 6). Each is read-only and
// tenant-scoped: the tenant is the one the service token names, and another tenant's record is 404.

// DeviceKID is the key id of a device's key. A device has one key for life (ADR-0002 S7), so the id is
// derived from the device id: "dev-" + the last four characters + "-1".
func DeviceKID(deviceID string) string {
	t := deviceID
	if len(t) > 4 {
		t = t[len(t)-4:]
	}
	return "dev-" + t + "-1"
}

// PubX962 is the uncompressed X9.62 P-256 point (0x04 || X || Y), base64url: the sync wire form of a key.
func PubX962(k crypto.JWK) (string, error) {
	x, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil || len(x) != 32 {
		return "", errInvalid("key", "invalid")
	}
	y, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil || len(y) != 32 {
		return "", errInvalid("key", "invalid")
	}
	return crypto.B64(append(append([]byte{4}, x...), y...)), nil
}

// storePackGrants stores the permission sets of a pack once per digest and returns the digest.
func (s *Service) storePackGrants(tx repository.Tx, tenant string, members []gen.PackMember) (string, error) {
	g := packGrants{}
	for _, m := range members {
		perms := append([]string{}, m.Permissions...)
		slices.Sort(perms)
		g.Members = append(g.Members, memberPerms{MemberID: m.MemberId, Permissions: perms})
	}
	slices.SortFunc(g.Members, func(a, b memberPerms) int { return strings.Compare(a.MemberID, b.MemberID) })
	b, err := json.Marshal(g.Members)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	g.ID = crypto.B64(sum[:])
	if have, err := get[packGrants](tx, kPackGrant, tenant, g.ID); err != nil || have != nil {
		return g.ID, err
	}
	return g.ID, put(tx, kPackGrant, tenant, g.ID, g, keys{})
}

// GetDeviceCredential answers the identity-signed credential of a device in any state (row 1).
func (s *Service) GetDeviceCredential(ctx context.Context, id string) (gen.DeviceCredential, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.DeviceCredential{}, errUnauth()
	}
	var out gen.DeviceCredential
	err := s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		d, err := get[device](tx, kDevice, pr.TenantID, id)
		if err != nil || d == nil {
			return notFoundOr(err)
		}
		pub, err := PubX962(d.Key)
		if err != nil {
			return err
		}
		out = gen.DeviceCredential{DeviceId: d.ID, TenantId: d.TenantID, OutletId: d.OutletID, Kind: gen.DeviceKind(d.Kind), Kid: DeviceKID(d.ID), Pub: pub}
		if d.Recovers != "" {
			r := d.Recovers
			out.Recovers = &r
		}
		return nil
	})
	return out, err
}

// GetPackGrants answers what an issued pack version granted (row 2). A pack issued before the
// permission sets were kept has no answer and is reported as unknown, never as "granted nothing".
func (s *Service) GetPackGrants(ctx context.Context, deviceID string, packV int) (gen.PackGrants, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.PackGrants{}, errUnauth()
	}
	var out gen.PackGrants
	err := s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		h, err := get[packHist](tx, kPackHist, pr.TenantID, deviceID+":"+itoa(packV))
		if err != nil || h == nil || h.Grants == "" {
			return notFoundOr(err)
		}
		g, err := get[packGrants](tx, kPackGrant, pr.TenantID, h.Grants)
		if err != nil || g == nil {
			return notFoundOr(err)
		}
		out = gen.PackGrants{PackV: h.PackV, IssuedAt: h.At, OfflineValidUntil: h.Until, SeriesCodes: append([]string{}, h.Series...)}
		for _, m := range g.Members {
			out.Members = append(out.Members, struct {
				MemberId    gen.Id   `json:"member_id"`
				Permissions []string `json:"permissions"`
			}{MemberId: m.MemberID, Permissions: append([]string{}, m.Permissions...)})
		}
		if out.Members == nil {
			out.Members = []struct {
				MemberId    gen.Id   `json:"member_id"`
				Permissions []string `json:"permissions"`
			}{}
		}
		return nil
	})
	return out, err
}

// GetMemberGrants answers a member's status and effective permissions at an outlet now (row 3). A member
// who is not active holds nothing.
func (s *Service) GetMemberGrants(ctx context.Context, memberID, outlet string) (gen.MemberGrants, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.MemberGrants{}, errUnauth()
	}
	var out gen.MemberGrants
	err := s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		m, err := get[member](tx, kMember, pr.TenantID, memberID)
		if err != nil || m == nil {
			return notFoundOr(err)
		}
		out = gen.MemberGrants{MemberId: m.ID, Status: m.Status, OutletId: outlet, Permissions: []string{}}
		if m.Status != "active" {
			return nil
		}
		roles, _, err := s.loadRoles(tx, pr.TenantID)
		if err != nil {
			return err
		}
		out.Permissions = s.packPermissions(m, roles, outlet)
		return nil
	})
	return out, err
}

// GetDeviceRecovery answers the key-loss recovery record of the old device (row 4); never the code.
func (s *Service) GetDeviceRecovery(ctx context.Context, oldDeviceID string) (gen.DeviceRecovery, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.DeviceRecovery{}, errUnauth()
	}
	var out gen.DeviceRecovery
	err := s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		r, err := s.recoveryOf(tx, pr.TenantID, oldDeviceID)
		if err != nil || r == nil {
			return notFoundOr(err)
		}
		state := gen.Open
		if r.Closed {
			state = gen.Closed
		}
		out = gen.DeviceRecovery{Id: r.ID, OldDeviceId: r.OldDeviceID, NewDeviceId: r.NewDeviceID, ApproverId: r.ApproverID, RecoveredAt: r.RecoveredAt, State: state}
		return nil
	})
	return out, err
}

// recoveryOf returns the recovery record of an old device, or nil.
func (s *Service) recoveryOf(tx repository.Tx, tenant, oldDeviceID string) (*deviceRecovery, error) {
	rs, err := find[deviceRecovery](tx, kDevRecov, tenant, oldDeviceID)
	if err != nil || len(rs) == 0 {
		return nil, err
	}
	return &rs[0], nil
}

// GetSession answers the fixed facts of a strong session (row 6). Its end is read from the revocation
// feed's row for the session. Another tenant's session, and a pin session (which has no cloud row), are 404.
func (s *Service) GetSession(ctx context.Context, sid string) (gen.SessionFacts, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.SessionFacts{}, errUnauth()
	}
	var out gen.SessionFacts
	err := s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		sess, err := get[session](tx, kSession, repository.Global, sid)
		if err != nil || sess == nil || sess.TenantID != pr.TenantID {
			return notFoundOr(err)
		}
		out = gen.SessionFacts{SessionId: sess.ID, MemberId: sess.MemberID, IssuedAt: sess.CreatedAt}
		if sess.Device != "" {
			dev := sess.Device
			out.DeviceId = &dev
		}
		if sess.Revoked {
			rs, err := find[revocationDoc](tx, kRevocation, repository.Global, sess.ID)
			if err != nil {
				return err
			}
			var at time.Time
			for _, r := range rs {
				if r.Type == "session" && (at.IsZero() || r.RevokedAt.Before(at)) {
					at = r.RevokedAt
				}
			}
			if !at.IsZero() {
				out.EndedAt = &at
			}
		}
		return nil
	})
	return out, err
}
