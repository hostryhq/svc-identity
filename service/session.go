package service

import (
	"context"
	"crypto/sha256"
	"sort"
	"strings"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/repository"
)

type session struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	MemberID  string    `json:"member_id"`
	AccountID string    `json:"account_id"`
	Device    string    `json:"device"`
	Binding   string    `json:"binding"`
	AMR       string    `json:"amr"`
	AuthTime  time.Time `json:"auth_time"`
	Revoked   bool      `json:"revoked"`
	Shared    bool      `json:"shared"`
	CreatedAt time.Time `json:"created_at"`
}

type refreshDoc struct {
	ID        string    `json:"id"` // MAC of the token
	Session   string    `json:"session"`
	Lineage   string    `json:"lineage"`
	Used      bool      `json:"used"`
	IdleUntil time.Time `json:"idle_until"`
	AbsUntil  time.Time `json:"abs_until"`
}

type binding struct {
	ID        string     `json:"id"`
	AccountID string     `json:"account_id"`
	Device    string     `json:"device"`
	Key       crypto.JWK `json:"key"`
	Thumb     string     `json:"thumb"`
	CreatedAt time.Time  `json:"created_at"`
	Caution   time.Time  `json:"caution_until,omitempty"`
	State     string     `json:"state"` // active, rejected, revoked
}

// grantsFor builds the token's grants claim from the member's stored assignments: identical
// permission sets are grouped (ADR-0005 section 2). The owner role is the single wildcard.
func grantsFor(m *member, roles map[string]*role, ownerRoleID string) []auth.Grant {
	type key struct{ outlets string }
	byOutlets := map[string]map[string]bool{}
	for _, a := range m.Assignments {
		r := roles[a.RoleID]
		if r == nil {
			continue
		}
		ok := "*"
		if len(a.Outlets) > 0 {
			o := append([]string(nil), a.Outlets...)
			sort.Strings(o)
			ok = strings.Join(o, ",")
		}
		set := byOutlets[ok]
		if set == nil {
			set = map[string]bool{}
			byOutlets[ok] = set
		}
		for _, p := range r.Perms {
			set[p] = true
		}
	}
	var out []auth.Grant
	for _, ok := range sortedKeys(byOutlets) {
		perms := sortedKeys(byOutlets[ok])
		if byOutlets[ok][auth.Wildcard] {
			perms = []string{auth.Wildcard}
		}
		outlets := []string{"*"}
		if ok != "*" {
			outlets = strings.Split(ok, ",")
		}
		out = append(out, auth.Grant{Outlets: outlets, Perms: perms})
	}
	return out
}

func (s *Service) loadRoles(tx repository.Tx, tenant string) (map[string]*role, string, error) {
	rs, err := list[role](tx, kRole, tenant, "", 0)
	if err != nil {
		return nil, "", err
	}
	m := map[string]*role{}
	owner := ""
	for i := range rs {
		m[rs[i].ID] = &rs[i]
		if rs[i].BuiltIn {
			owner = rs[i].ID
		}
	}
	return m, owner, nil
}

// issueTokens creates a session, its refresh token and its access token for member m on a device.
func (s *Service) issueStrong(tx repository.Tx, m *member, acct string, deviceID string, bind *binding, amr string, shared bool) (gen.Session, error) {
	now := s.now()
	roles, ownerID, err := s.loadRoles(tx, m.TenantID)
	if err != nil {
		return gen.Session{}, err
	}
	sess := session{ID: string(s.NewID()), TenantID: m.TenantID, MemberID: m.ID, AccountID: acct, Device: deviceID, AMR: amr,
		AuthTime: now, Shared: shared, CreatedAt: now}
	if bind != nil {
		sess.Binding = bind.ID
	}
	if err := put(tx, kSession, repository.Global, sess.ID, sess, keys{k1: m.ID, k2: acct}); err != nil {
		return gen.Session{}, err
	}
	pair, err := s.tokenPair(tx, m, roles, ownerID, &sess, bind, "")
	if err != nil {
		return gen.Session{}, err
	}
	g := gen.Session{SessionId: sess.ID, MemberId: m.ID, Tokens: pair, Amr: gen.AuthMethod(amr), AuthTime: now}
	if bind != nil && now.Before(bind.Caution) {
		c := bind.Caution
		g.CautionUntil = &c
	}
	return g, nil
}

// tokenPair mints an access token and (for strong sessions) a rotating refresh token.
func (s *Service) tokenPair(tx repository.Tx, m *member, roles map[string]*role, ownerID string, sess *session, bind *binding, lineage string) (gen.TokenPair, error) {
	now := s.now()
	claims := auth.Claims{
		Subject: m.ID, Type: auth.TypeUser, TenantID: m.TenantID, DeviceID: sess.Device, SessionID: sess.ID,
		AMR: []string{sess.AMR}, AuthTime: sess.AuthTime.Unix(), Grants: grantsFor(m, roles, ownerID),
		IssuedAt: now.Unix(), ExpiresAt: now.Add(s.Cfg.AccessTTL).Unix(), JTI: string(s.NewID()),
	}
	if bind != nil && now.Before(bind.Caution) {
		claims.CautionUntil = bind.Caution.Unix()
	}
	tok, err := s.Tokens.Access(claims)
	if err != nil {
		return gen.TokenPair{}, apperr.Wrap(apperr.Internal, "token.sign_failed", "", err)
	}
	if lineage == "" {
		lineage = string(s.NewID())
	}
	idle, abs := s.Cfg.RefreshPersonal, s.Cfg.RefreshAbs
	if sess.Shared {
		idle, abs = 12*time.Hour, 12*time.Hour
	}
	rt := s.Tokens.Opaque()
	rd := refreshDoc{ID: s.refreshKey(rt), Session: sess.ID, Lineage: lineage, IdleUntil: now.Add(idle), AbsUntil: sess.CreatedAt.Add(abs)}
	if rd.IdleUntil.After(rd.AbsUntil) {
		rd.IdleUntil = rd.AbsUntil
	}
	if err := put(tx, kRefresh, repository.Global, rd.ID, rd, keys{k1: sess.ID}); err != nil {
		return gen.TokenPair{}, err
	}
	exp := rd.IdleUntil
	return gen.TokenPair{AccessToken: tok, TokenType: gen.TokenPairTokenTypeBearer, ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(),
		RefreshToken: &rt, RefreshExpiresAt: &exp}, nil
}

// RefreshHash is the value a refresh proof binds to: the SHA-256 of the refresh token, base64url.
// A client can compute it; the server-keyed hash used for storage cannot be.
func RefreshHash(rt string) string {
	sum := sha256.Sum256([]byte(rt))
	return crypto.B64(sum[:])
}

func (s *Service) refreshKey(rt string) string { return crypto.MAC(s.Cfg.MACKey, "refresh", rt) }

// RefreshSession rotates a refresh token (ADR-0005 section 2, IC-04, IST-12). Reuse of a rotated
// token revokes the whole session; the proof must be signed by the session's device key and a
// proof id is accepted once.
func (s *Service) RefreshSession(ctx context.Context, in gen.RefreshSession) (gen.TokenPair, error) {
	now := s.now()
	var out gen.TokenPair
	var refuse error
	tenant, err := s.tenantOfRefresh(ctx, in.RefreshToken)
	if err != nil || tenant == "" {
		return gen.TokenPair{}, notAuth(err)
	}
	err = s.Store.Tx(ctx, tenant, func(tx repository.Tx) error {
		rid := s.refreshKey(in.RefreshToken)
		rd, err := get[refreshDoc](tx, kRefresh, repository.Global, rid)
		if err != nil {
			return err
		}
		if rd == nil {
			refuse = errUnauth()
			return nil
		}
		sess, err := get[session](tx, kSession, repository.Global, rd.Session)
		if err != nil {
			return err
		}
		if sess == nil || sess.Device != in.DeviceId || sess.Revoked {
			refuse = errUnauth()
			return nil
		}
		dev, err := s.sessionKey(tx, sess)
		if err != nil {
			return err
		}
		if dev == nil {
			refuse = errUnauth()
			return nil
		}
		// Proof of the device key, over this token's hash, with a fresh jti and iat.
		cl, verr := s.Assertions.Verify(in.Proof, *dev, now)
		if verr != nil || (!cl.Trusted && (cl.Did != in.DeviceId || cl.Rth != RefreshHash(in.RefreshToken))) {
			refuse = errUnauth()
			return nil
		}
		if used, err := s.useJTI(tx, cl.Jti, now); err != nil || !used {
			refuse = errUnauth()
			return err
		}
		if rd.Used {
			// Reuse: the family is compromised. Revoke the session and tell the gateway.
			sess.Revoked = true
			if err := put(tx, kSession, repository.Global, sess.ID, sess, keys{k1: sess.MemberID, k2: sess.AccountID}); err != nil {
				return err
			}
			if err := s.emitSessionRevoked(tx, sess, "refresh_reuse"); err != nil {
				return err
			}
			refuse = errUnauth()
			return nil
		}
		if now.After(rd.IdleUntil) || now.After(rd.AbsUntil) {
			refuse = errUnauth()
			return nil
		}
		m, err := get[member](tx, kMember, sess.TenantID, sess.MemberID)
		if err != nil {
			return err
		}
		if m == nil || m.Status != "active" {
			refuse = errUnauth()
			return nil
		}
		rd.Used = true
		if err := put(tx, kRefresh, repository.Global, rd.ID, rd, keys{k1: sess.ID}); err != nil {
			return err
		}
		roles, ownerID, err := s.loadRoles(tx, sess.TenantID)
		if err != nil {
			return err
		}
		var bind *binding
		if sess.Binding != "" {
			bind, err = get[binding](tx, kBinding, repository.Global, sess.Binding)
			if err != nil {
				return err
			}
			if bind != nil && bind.State != "active" {
				refuse = errUnauth()
				return nil
			}
		}
		out, err = s.tokenPair(tx, m, roles, ownerID, sess, bind, rd.Lineage)
		return err
	})
	if err != nil {
		return gen.TokenPair{}, err
	}
	if refuse != nil {
		return gen.TokenPair{}, refuse
	}
	return out, nil
}

// tenantOfRefresh finds the tenant a refresh token belongs to, so the rotation can run in that
// tenant's transaction (tenant rows are invisible to a service-global transaction).
func (s *Service) tenantOfRefresh(ctx context.Context, rt string) (string, error) {
	tenant := ""
	err := s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		rd, err := get[refreshDoc](tx, kRefresh, repository.Global, s.refreshKey(rt))
		if err != nil || rd == nil {
			return err
		}
		sess, err := get[session](tx, kSession, repository.Global, rd.Session)
		if err != nil || sess == nil {
			return err
		}
		tenant = sess.TenantID
		return nil
	})
	return tenant, err
}

func notAuth(err error) error {
	if err != nil {
		return err
	}
	return errUnauth()
}

// useJTI records an assertion id; false means it was seen already (replay).
func (s *Service) useJTI(tx repository.Tx, jti string, now time.Time) (bool, error) {
	id := crypto.MAC(s.Cfg.MACKey, "jti", jti)
	if d, err := get[struct{ Until time.Time }](tx, kJTI, repository.Global, id); err != nil {
		return false, err
	} else if d != nil && now.Before(d.Until) {
		return false, nil
	}
	return true, put(tx, kJTI, repository.Global, id, struct{ Until time.Time }{now.Add(10 * time.Minute)}, keys{})
}

func (s *Service) emitSessionRevoked(tx repository.Tx, sess *session, reason string) error {
	return s.emit(tx, sess.TenantID, "", "identity.session.revoked", sess.ID, sess.MemberID,
		map[string]any{"session_id": sess.ID, "member_id": sess.MemberID, "reason": reason})
}

// EndSession ends a session (sign out) or a pin session id. Repeating is a no-op. A session of
// another member or tenant is a 404.
func (s *Service) EndSession(ctx context.Context, sid string) error {
	p, ok := principal(ctx)
	if !ok {
		return errUnauth()
	}
	return s.Store.Tx(ctx, p.TenantID, func(tx repository.Tx) error {
		if ps, err := get[pinSession](tx, kPinSess, p.TenantID, sid); err != nil {
			return err
		} else if ps != nil {
			if ps.Device != p.DeviceID && ps.Member != p.Subject {
				return errNotFound()
			}
			ps.Ended = true
			return put(tx, kPinSess, p.TenantID, sid, ps, keys{})
		}
		sess, err := get[session](tx, kSession, repository.Global, sid)
		if err != nil {
			return err
		}
		if sess == nil || sess.TenantID != p.TenantID || sess.MemberID != p.Subject {
			return errNotFound()
		}
		if sess.Revoked {
			return nil
		}
		sess.Revoked = true
		if err := put(tx, kSession, repository.Global, sid, sess, keys{k1: sess.MemberID, k2: sess.AccountID}); err != nil {
			return err
		}
		return s.emitSessionRevoked(tx, sess, "signed_out")
	})
}

// SwitchMember issues a token for another membership of the same account. Membership and member
// status are re-read; one tenant per token (IC-11).
func (s *Service) SwitchMember(ctx context.Context, in gen.SwitchMember) (gen.TokenPair, error) {
	p, ok := principal(ctx)
	if !ok {
		return gen.TokenPair{}, errUnauth()
	}
	var cur *session
	var target *membership
	err := s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		var err error
		cur, err = get[session](tx, kSession, repository.Global, p.SessionID)
		if err != nil || cur == nil || cur.Revoked || cur.AccountID == "" {
			cur = nil
			return err
		}
		ms, err := find[membership](tx, kMembership, repository.Global, cur.AccountID)
		if err != nil {
			return err
		}
		for i := range ms {
			if ms[i].MemberID == in.MemberId {
				target = &ms[i]
			}
		}
		return nil
	})
	if err != nil {
		return gen.TokenPair{}, err
	}
	if cur == nil || target == nil {
		return gen.TokenPair{}, errNotFound()
	}
	var out gen.TokenPair
	err = s.Store.Tx(ctx, target.TenantID, func(tx repository.Tx) error {
		m, err := get[member](tx, kMember, target.TenantID, target.MemberID)
		if err != nil {
			return err
		}
		if m == nil || m.Status != "active" {
			return errNotFound()
		}
		bind, err := get[binding](tx, kBinding, repository.Global, cur.Binding)
		if err != nil {
			return err
		}
		g, err := s.issueStrong(tx, m, cur.AccountID, cur.Device, bind, cur.AMR, cur.Shared)
		if err != nil {
			return err
		}
		out = g.Tokens
		return nil
	})
	return out, err
}

// JWKS returns the published public keys of a realm.
func (s *Service) JWKS(vendor bool) gen.Jwks {
	ks := []gen.Jwk{}
	for _, k := range s.Tokens.JWKS(vendor) {
		ks = append(ks, gen.Jwk{Kty: gen.JwkKtyEC, Crv: gen.JwkCrvP256, X: k.Key.X, Y: k.Key.Y, Kid: k.Kid, Alg: gen.ES256, Use: gen.Sig})
	}
	return gen.Jwks{Keys: ks}
}

// principal returns the verified caller placed by the guard (or the api layer for
// "authenticated" routes) as go-auth's Principal.
func principal(ctx context.Context) (auth.Principal, bool) {
	if p, ok := ctx.Value(callerKey{}).(auth.Principal); ok {
		return p, true
	}
	return auth.PrincipalFrom(ctx)
}

type callerKey struct{}

// WithCaller attaches a verified principal for routes the api layer authenticates itself
// ("authenticated" routes, which go-auth's Guard has no mode for).
func WithCaller(ctx context.Context, p auth.Principal) context.Context {
	return context.WithValue(ctx, callerKey{}, p)
}
