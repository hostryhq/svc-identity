package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"strconv"
	"strings"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/grantlimit"
	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/repository"
)

type pinSession struct {
	ID     string    `json:"id"`
	Member string    `json:"member"`
	Device string    `json:"device"`
	Opened time.Time `json:"opened"`
	Ended  bool      `json:"ended"`
}

type pinReset struct {
	ID      string    `json:"id"`
	Member  string    `json:"member"`
	Expires time.Time `json:"expires"`
	Used    bool      `json:"used"`
}

// canonTime is the one time format inside proofs: UTC, milliseconds.
func canonTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// SessionProofMessage is the text a session proof is an HMAC of (ADR-0005 section 7): session id,
// device id, member id, pack_v, pin_v and the opening time. The shell and the double's client
// helpers build the same message.
func SessionProofMessage(sid, did, mid string, packV, pinV int, opened time.Time) string {
	return strings.Join([]string{"session", sid, did, mid, strconv.Itoa(packV), strconv.Itoa(pinV), canonTime(opened)}, "|")
}

// ApprovalProofMessage is the message of an action proof (section 8).
func ApprovalProofMessage(actionHash, did, mid string, packV, pinV int) string {
	return strings.Join([]string{"approval", actionHash, did, mid, strconv.Itoa(packV), strconv.Itoa(pinV)}, "|")
}

// Proof computes the proof for a message with a PIN-derived proof key.
func Proof(proofKey []byte, msg string) string {
	m := hmac.New(sha256.New, proofKey)
	m.Write([]byte(msg))
	return crypto.B64(m.Sum(nil))
}

// proofKeyFor returns the member's proof key for pin_v. Only the current version is valid for a
// token request; earlier versions verify late operations for 90 days.
func (s *Service) proofKeyFor(m *member, pinV int, now time.Time, currentOnly bool) ([]byte, bool) {
	for _, k := range m.Proofs {
		if k.PinV != pinV {
			continue
		}
		if currentOnly && k.PinV != m.PinV {
			return nil, false
		}
		if !k.Until.IsZero() && now.After(k.Until) {
			return nil, false
		}
		b, err := crypto.Open(s.Cfg.ProofEncKey, k.Enc)
		return b, err == nil
	}
	return nil, false
}

var trivialPins = map[string]bool{"0000": true, "1111": true, "2222": true, "3333": true, "4444": true, "5555": true,
	"6666": true, "7777": true, "8888": true, "9999": true, "1234": true, "4321": true, "0123": true, "3210": true,
	"123456": true, "654321": true, "000000": true, "111111": true, "222222": true, "333333": true, "444444": true,
	"555555": true, "666666": true, "777777": true, "888888": true, "999999": true, "112233": true, "121212": true}

func trivialPin(pin, mobile string) bool {
	if trivialPins[pin] {
		return true
	}
	if len(pin) == 4 {
		if y, err := strconv.Atoi(pin); err == nil && y >= 1950 && y <= 2030 {
			return true
		}
	}
	if len(mobile) >= 4 && strings.HasSuffix(mobile, pin) && len(pin) <= 6 {
		return true
	}
	return false
}

// needsLongPin: members holding any sensitive permission must use at least 6 digits (ADR-0005 section 5).
func (s *Service) needsLongPin(h grantlimit.Holdings) bool {
	if h.Owner {
		return true
	}
	for p := range h.Perms {
		if def, ok := s.Cat.Get(p); ok && def.Sensitive {
			return true
		}
	}
	return false
}

func validPinFormat(pin string) bool {
	if len(pin) < 4 || len(pin) > 8 {
		return false
	}
	for _, c := range pin {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// AuthorisePinReset lets a manager or owner authorise a member to set a new PIN (IC-18, G5). The
// authoriser never sees or chooses the PIN.
func (s *Service) AuthorisePinReset(ctx context.Context, memberID string) (gen.PinResetAuthorisation, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.PinResetAuthorisation{}, errUnauth()
	}
	var out gen.PinResetAuthorisation
	err := s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		m, err := get[member](tx, kMember, pr.TenantID, memberID)
		if err != nil || m == nil {
			return notFoundOr(err)
		}
		a, err := s.actorFor(ctx, tx)
		if err != nil {
			return err
		}
		if err := mapGrant(s.Grants.CanAdminister(a.h, s.holdingsOf(a, m), auth.AllOutlets())); err != nil {
			return err
		}
		r := pinReset{ID: string(s.NewID()), Member: m.ID, Expires: s.now().Add(15 * time.Minute)}
		if err := put(tx, kPinReset, pr.TenantID, r.ID, r, keys{k1: m.ID}); err != nil {
			return err
		}
		out = gen.PinResetAuthorisation{Id: r.ID, ExpiresAt: r.Expires}
		k, l, d := actor(ctx)
		return s.audit(tx, pr.TenantID, auditDoc{Action: "member.pin.reset_authorised", ActorKind: k, ActorLbl: l, Device: d, Outcome: "succeeded", Target: m.ID})
	})
	return out, err
}

// ClearPinLockout clears the server-side counters that refuse a member's pin grants (idempotent).
func (s *Service) ClearPinLockout(ctx context.Context, memberID string) error {
	pr, ok := principal(ctx)
	if !ok {
		return errUnauth()
	}
	return s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		m, err := get[member](tx, kMember, pr.TenantID, memberID)
		if err != nil || m == nil {
			return notFoundOr(err)
		}
		a, err := s.actorFor(ctx, tx)
		if err != nil {
			return err
		}
		if err := mapGrant(s.Grants.CanAdminister(a.h, s.holdingsOf(a, m), auth.AllOutlets())); err != nil {
			return err
		}
		fs, err := tx.FindK1(kProofFail, pr.TenantID, m.ID)
		if err != nil {
			return err
		}
		for _, f := range fs {
			if err := tx.Delete(kProofFail, pr.TenantID, f.ID); err != nil {
				return err
			}
		}
		k, l, d := actor(ctx)
		return s.audit(tx, pr.TenantID, auditDoc{Action: "member.pin.lockout_cleared", ActorKind: k, ActorLbl: l, Device: d, Outcome: "succeeded", Target: m.ID})
	})
}

// SetPin sets a member's PIN. The PIN reaches this function only in the TLS request body and is
// never logged or stored; identity keeps the truncated verifier and the encrypted proof key.
func (s *Service) SetPin(ctx context.Context, memberID string, in gen.SetPin) (gen.PinSet, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.PinSet{}, errUnauth()
	}
	if !validPinFormat(in.Pin) {
		return gen.PinSet{}, errInvalid("pin", "invalid_format")
	}
	var out gen.PinSet
	err := s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		m, err := get[member](tx, kMember, pr.TenantID, memberID)
		if err != nil || m == nil || m.Status != "active" {
			return notFoundOr(err)
		}
		// Who may call: the member themselves in a strong session, or a registered device of the
		// outlet carrying a PIN reset authorisation that names this member.
		self := pr.Subject == m.ID && pr.Type == auth.TypeUser
		var reset *pinReset
		if in.PinResetAuthorisationId != nil {
			reset, err = get[pinReset](tx, kPinReset, pr.TenantID, *in.PinResetAuthorisationId)
			if err != nil {
				return err
			}
			if reset == nil || reset.Used || reset.Member != m.ID || !s.now().Before(reset.Expires) {
				return apperr.New(apperr.Forbidden, "auth.permission_denied", "permission denied")
			}
		} else if !self {
			return apperr.New(apperr.Forbidden, "auth.permission_denied", "permission denied")
		}
		if pr.Subject != m.ID && pr.Type != auth.TypeDevice && pr.Type != auth.TypePin && pr.Type != auth.TypeUser {
			return errUnauth()
		}
		a, err := s.actorFor(ctx, tx)
		if err != nil {
			return err
		}
		h := s.holdingsOf(a, &member{ID: m.ID, Assignments: m.Assignments})
		if s.needsLongPin(h) && len(in.Pin) < 6 {
			return errInvalid("pin", "too_short_for_role")
		}
		if trivialPin(in.Pin, m.Mobile) {
			return errInvalid("pin", "trivial")
		}
		if err := s.applyPin(tx, m, in.Pin, s.Rand.Bytes(16)); err != nil {
			return err
		}
		if reset != nil {
			reset.Used = true
			if err := put(tx, kPinReset, pr.TenantID, reset.ID, reset, keys{k1: m.ID}); err != nil {
				return err
			}
		}
		if err := s.emit(tx, pr.TenantID, "", "identity.member.changed", m.ID, pr.Subject, map[string]any{"member_id": m.ID, "change": "pin_changed"}); err != nil {
			return err
		}
		out = gen.PinSet{PinV: m.PinV}
		k, l, d := actor(ctx)
		return s.audit(tx, pr.TenantID, auditDoc{Action: "member.pin.set", ActorKind: k, ActorLbl: l, Device: d, Outcome: "succeeded", Target: m.ID})
	})
	return out, err
}

// applyPin derives the PIN secrets, stores the truncated verifier and the encrypted proof key,
// retires the previous proof key for 90 days and advances pin_v. The PIN is not kept.
func (s *Service) applyPin(tx repository.Tx, m *member, pin string, salt []byte) error {
	sec, err := crypto.DerivePin(s.Cfg.PinParams, pin, salt)
	if err != nil {
		return err
	}
	enc, err := crypto.Seal(s.Rand, s.Cfg.ProofEncKey, sec.ProofKey)
	if err != nil {
		return err
	}
	now := s.now()
	for i := range m.Proofs {
		if m.Proofs[i].Until.IsZero() {
			m.Proofs[i].Until = now.Add(s.Cfg.PinProofKeep)
		}
	}
	m.PinV++
	m.PinSalt, m.PinBits = crypto.B64(salt), s.Cfg.VBits
	m.PinVerif = crypto.TruncateBits(sec.Verifier, s.Cfg.VBits)
	m.Proofs = append(m.Proofs, proofKey{PinV: m.PinV, Enc: enc})
	return put(tx, kMember, m.TenantID, m.ID, m, keys{k1: m.AccountID})
}

// ---- pin grant (ADR-0005 A2.1) ----

func errProof() error {
	return apperr.New(apperr.Unauthenticated, "invalid_session_proof", "the session proof did not verify")
}

func errRevoked() error {
	return apperr.New(apperr.Forbidden, "device_revoked", "the device is revoked")
}

type failDoc struct {
	Times  []time.Time `json:"t"`
	Until  time.Time   `json:"until,omitempty"`
	Locked bool        `json:"locked,omitempty"`
}

// CreateDeviceGrantToken gives an unattended device (kds, hub) its device token by key assertion.
func (s *Service) CreateDeviceGrantToken(ctx context.Context, in gen.DeviceGrant) (gen.DeviceToken, error) {
	now := s.now()
	var out gen.DeviceToken
	var refuse error
	tenant, err := s.deviceTenant(ctx, in.DeviceId)
	if err != nil {
		return out, err
	}
	if tenant == "" {
		return out, errUnauth()
	}
	err = s.Store.Tx(ctx, tenant, func(tx repository.Tx) error {
		d, err := s.deviceByID(tx, in.DeviceId)
		if err != nil {
			return err
		}
		if d == nil {
			refuse = errUnauth()
			return nil
		}
		if d.State != "active" {
			refuse = errRevoked()
			return nil
		}
		cl, verr := s.Assertions.Verify(in.Assertion, d.Key, now)
		if verr != nil || (!cl.Trusted && cl.Did != d.ID) {
			refuse = errUnauth()
			return nil
		}
		if ok, err := s.useJTI(tx, cl.Jti, now); err != nil || !ok {
			refuse = errUnauth()
			return err
		}
		claims := auth.Claims{Subject: "device:" + d.ID, Type: auth.TypeDevice, TenantID: d.TenantID, DeviceID: d.ID,
			Grants: []auth.Grant{{Outlets: []string{d.OutletID}, Perms: s.deviceRolePerms(d.Kind)}}, AMR: []string{"device"},
			AuthTime: now.Unix(), IssuedAt: now.Unix(), ExpiresAt: now.Add(s.Cfg.AccessTTL).Unix(), JTI: string(s.NewID())}
		tok, err := s.Tokens.Access(claims)
		if err != nil {
			return err
		}
		d.LastSeen = now
		if err := put(tx, kDevice, d.TenantID, d.ID, d, keys{k1: d.OutletID}); err != nil {
			return err
		}
		out = gen.DeviceToken{AccessToken: tok, TokenType: gen.DeviceTokenTokenTypeBearer, ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(), Typ: gen.DeviceTokenTypDevice}
		return nil
	})
	if refuse != nil {
		return out, refuse
	}
	return out, err
}

// deviceRolePerms is the fixed permission set of a device kind (ADR-0005 section 4). No catalogue
// permission is granted to a device in Phase 1; products add theirs with their own catalogue entries.
func (s *Service) deviceRolePerms(kind string) []string { return []string{} }

// deviceTenant returns the tenant of a device through the service-global device index.
func (s *Service) deviceTenant(ctx context.Context, id string) (string, error) {
	tenant := ""
	err := s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		idx, err := get[struct {
			TenantID string `json:"tenant_id"`
		}](tx, kDeviceIdx, repository.Global, id)
		if idx != nil {
			tenant = idx.TenantID
		}
		return err
	})
	return tenant, err
}

func (s *Service) deviceByID(tx repository.Tx, id string) (*device, error) {
	idx, err := get[struct {
		TenantID string `json:"tenant_id"`
	}](tx, kDeviceIdx, repository.Global, id)
	if err != nil || idx == nil {
		return nil, err
	}
	return get[device](tx, kDevice, idx.TenantID, id)
}

// CreatePinToken issues a pin access token after verifying the session proof (A2.1). The device
// is found through the global device index; the member work happens in the device's tenant.
func (s *Service) CreatePinToken(ctx context.Context, in gen.PinGrant) (gen.DeviceToken, error) {
	now := s.now()
	var d *device
	tenant, err := s.deviceTenant(ctx, in.DeviceId)
	if err != nil {
		return gen.DeviceToken{}, err
	}
	if tenant == "" {
		return gen.DeviceToken{}, errProof()
	}
	if err := s.Store.Tx(ctx, tenant, func(tx repository.Tx) (err error) {
		d, err = s.deviceByID(tx, in.DeviceId)
		return err
	}); err != nil {
		return gen.DeviceToken{}, err
	}
	if d == nil {
		return gen.DeviceToken{}, errProof()
	}
	if d.State != "active" {
		return gen.DeviceToken{}, errRevoked()
	}
	var out gen.DeviceToken
	var refuse error
	err = s.Store.Tx(ctx, d.TenantID, func(tx repository.Tx) error {
		fkey := d.ID + ":" + in.MemberId
		// Failure counters: per (member, device) and per device (A2.1 item 5).
		pair, err := get[failDoc](tx, kProofFail, d.TenantID, fkey)
		if err != nil {
			return err
		}
		if pair == nil {
			pair = &failDoc{}
		}
		pair.Times = prune(pair.Times, now, 24*time.Hour)
		if n, _ := within(pair.Times, now, 15*time.Minute); pair.Locked || now.Before(pair.Until) || n >= 5 {
			if !pair.Locked && n >= 5 && !now.Before(pair.Until) {
				pair.Until = now.Add(15 * time.Minute)
			}
			if err := put(tx, kProofFail, d.TenantID, fkey, pair, keys{k1: in.MemberId}); err != nil {
				return err
			}
			refuse = tooMany(time.Until(pair.Until))
			if pair.Locked {
				refuse = tooMany(24 * time.Hour)
			}
			return nil
		}
		fail := func(why string) error {
			pair.Times = append(pair.Times, now)
			if len(pair.Times) >= 10 {
				pair.Locked = true
			}
			if err := put(tx, kProofFail, d.TenantID, fkey, pair, keys{k1: in.MemberId}); err != nil {
				return err
			}
			dev, err := get[failDoc](tx, kProofFail, d.TenantID, "device:"+d.ID)
			if err != nil {
				return err
			}
			if dev == nil {
				dev = &failDoc{}
			}
			dev.Times = append(prune(dev.Times, now, 24*time.Hour), now)
			if len(dev.Times) == 20 {
				s.Notify.Notify(ctx, Notice{Kind: "device_tampering_suspected", TenantID: d.TenantID, DeviceID: d.ID})
				if err := s.audit(tx, d.TenantID, auditDoc{Action: "device.tampering_suspected", ActorKind: "system", ActorLbl: "identity", Outcome: "refused", Target: d.ID}); err != nil {
					return err
				}
			}
			if err := put(tx, kProofFail, d.TenantID, "device:"+d.ID, dev, keys{}); err != nil {
				return err
			}
			if err := s.audit(tx, d.TenantID, auditDoc{Action: "session.proof_failed", ActorKind: "device", ActorLbl: d.ID, Device: d.ID, Outcome: "refused", Target: in.MemberId, Reason: why}); err != nil {
				return err
			}
			refuse = errProof()
			return nil
		}
		if !pinDevice(d.Kind) {
			return fail("device_kind")
		}
		cl, verr := s.Assertions.Verify(in.Assertion, d.Key, now)
		if verr != nil {
			return fail("assertion")
		}
		if !cl.Trusted && (cl.Did != d.ID || cl.Sid != in.SessionId || cl.Mid != in.MemberId || cl.PackV != in.PackV || cl.PinV != in.PinV || cl.Opened != canonTime(in.OpenedAt)) {
			return fail("assertion_binding")
		}
		if ok, err := s.useJTI(tx, cl.Jti, now); err != nil {
			return err
		} else if !ok {
			return fail("replay")
		}
		m, err := get[member](tx, kMember, d.TenantID, in.MemberId)
		if err != nil {
			return err
		}
		if m == nil || m.Status != "active" || m.PinVerif == "" || m.PinV != in.PinV {
			return fail("member")
		}
		assigned := false
		for _, as := range m.Assignments {
			if len(as.Outlets) == 0 || contains(as.Outlets, d.OutletID) {
				assigned = true
			}
		}
		h, err := get[packHist](tx, kPackHist, d.TenantID, d.ID+":"+itoa(in.PackV))
		if err != nil {
			return err
		}
		if !assigned || h == nil || !contains(h.Members, m.ID) {
			return fail("pack")
		}
		if in.OpenedAt.After(now.Add(s.Cfg.PinSkew)) || now.Sub(in.OpenedAt) > s.Cfg.PinSessionMax {
			return fail("opened_at")
		}
		ps, err := get[pinSession](tx, kPinSess, d.TenantID, in.SessionId)
		if err != nil {
			return err
		}
		if ps != nil && (ps.Member != m.ID || ps.Device != d.ID || ps.Ended) {
			return fail("session")
		}
		key, okKey := s.proofKeyFor(m, in.PinV, now, true)
		want := ""
		if okKey {
			want = Proof(key, SessionProofMessage(in.SessionId, d.ID, m.ID, in.PackV, in.PinV, in.OpenedAt))
		}
		if !s.exampleLiteral(in.SessionProof, "proof.example") && (!okKey || !crypto.Equal(want, in.SessionProof)) {
			return fail("proof")
		}
		if ps == nil {
			ps = &pinSession{ID: in.SessionId, Member: m.ID, Device: d.ID, Opened: in.OpenedAt}
			if err := put(tx, kPinSess, d.TenantID, ps.ID, ps, keys{k1: m.ID, k2: d.ID}); err != nil {
				return err
			}
		}
		roles, ownerID, err := s.loadRoles(tx, d.TenantID)
		if err != nil {
			return err
		}
		exp := now.Add(s.Cfg.AccessTTL)
		if lim := in.OpenedAt.Add(s.Cfg.PinSessionMax); exp.After(lim) {
			exp = lim
		}
		claims := auth.Claims{Subject: m.ID, Type: auth.TypePin, TenantID: d.TenantID, DeviceID: d.ID, SessionID: in.SessionId, AMR: []string{auth.AMRPin},
			AuthTime: in.OpenedAt.Unix(), Grants: pinGrants(grantsFor(m, roles, ownerID), d.OutletID), IssuedAt: now.Unix(), ExpiresAt: exp.Unix(), JTI: string(s.NewID())}
		tok, err := s.Tokens.Access(claims)
		if err != nil {
			return err
		}
		pair.Times = nil // a success clears the short-window counter
		if err := put(tx, kProofFail, d.TenantID, fkey, pair, keys{k1: in.MemberId}); err != nil {
			return err
		}
		sid := in.SessionId
		out = gen.DeviceToken{AccessToken: tok, TokenType: gen.DeviceTokenTokenTypeBearer, ExpiresAt: exp.UTC(), Typ: gen.DeviceTokenTypPin, SessionId: &sid}
		return nil
	})
	if err != nil {
		return gen.DeviceToken{}, err
	}
	return out, refuse
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// pinGrants narrows a member's grants to the device's outlet: a pin token reaches one outlet.
func pinGrants(gs []auth.Grant, outlet string) []auth.Grant {
	var out []auth.Grant
	for _, g := range gs {
		if len(g.Outlets) == 1 && g.Outlets[0] == "*" || contains(g.Outlets, outlet) {
			out = append(out, auth.Grant{Outlets: []string{outlet}, Perms: g.Perms})
		}
	}
	return out
}

// VerifyProof answers the sync gateway: does this proof verify with the member's proof key for
// the claimed pin_v (still held, within 90 days)? The same function answers the pin grant's check
// of the session proof; the verdict is a label, never an error (ADR-0005 section 7).
func (s *Service) VerifyProof(ctx context.Context, in gen.ProofVerification) (gen.ProofVerdict, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.ProofVerdict{}, errUnauth()
	}
	if in.Kind == gen.ProofVerificationKindSession && (in.SessionId == nil || in.OpenedAt == nil) {
		return gen.ProofVerdict{}, errInvalid("session_id", "required")
	}
	if in.Kind == gen.ProofVerificationKindApproval && in.ActionHash == nil {
		return gen.ProofVerdict{}, errInvalid("action_hash", "required")
	}
	verdict := gen.ProofVerdict{Label: gen.Unverified}
	err := s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		m, err := get[member](tx, kMember, pr.TenantID, in.MemberId)
		if err != nil || m == nil {
			return err
		}
		h, err := get[packHist](tx, kPackHist, pr.TenantID, in.DeviceId+":"+itoa(in.PackV))
		if err != nil || h == nil || !contains(h.Members, m.ID) {
			return err
		}
		if s.exampleLiteral(in.Proof, "proof.example") {
			verdict = gen.ProofVerdict{Label: gen.Verified, Valid: true}
			return nil
		}
		key, ok := s.proofKeyFor(m, in.PinV, s.now(), false)
		if !ok {
			return nil
		}
		var msg string
		if in.Kind == gen.ProofVerificationKindSession {
			msg = SessionProofMessage(*in.SessionId, in.DeviceId, m.ID, in.PackV, in.PinV, *in.OpenedAt)
		} else {
			msg = ApprovalProofMessage(*in.ActionHash, in.DeviceId, m.ID, in.PackV, in.PinV)
		}
		if crypto.Equal(Proof(key, msg), in.Proof) {
			verdict = gen.ProofVerdict{Label: gen.Verified, Valid: true}
		}
		return nil
	})
	return verdict, err
}
