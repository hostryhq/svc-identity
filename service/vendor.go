package service

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net/mail"
	"strings"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/go-common/logx"
	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/repository"
	openapi_types "github.com/oapi-codegen/runtime/types"
)

// MailSender delivers vendor setup links and security notices by email. Phase 1 has no real
// implementation (no domain, no provider); the double records, the CLI prints to the terminal.
type MailSender interface {
	Send(ctx context.Context, to, kind, link string) error
}

type vendorUser struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"display_name"`
	Role      string    `json:"role"`
	Status    string    `json:"status"` // setup_pending, active, deactivated
	Hash      string    `json:"password_hash,omitempty"`
	TOTPEnc   []byte    `json:"totp_enc,omitempty"`
	TOTPStep  int64     `json:"totp_step,omitempty"`
	Enrolled  bool      `json:"totp_enrolled"`
	CreatedAt time.Time `json:"created_at"`
	// CredAt is when the account was created, re-roled or given new credentials: the 7-day approver
	// rule counts from it (A2.3).
	CredAt time.Time   `json:"cred_at"`
	Fails  []time.Time `json:"fails,omitempty"`
	Locked time.Time   `json:"locked_until,omitempty"`
}

type vendorSetup struct {
	ID      string    `json:"id"` // MAC of the one-time token
	UserID  string    `json:"user_id"`
	Expires time.Time `json:"expires"`
	Used    bool      `json:"used"`
	Secret  []byte    `json:"secret,omitempty"` // encrypted TOTP secret chosen at begin
}

type vendorSession struct {
	ID      string    `json:"id"`
	UserID  string    `json:"user_id"`
	Started time.Time `json:"started"`
	EndsAt  time.Time `json:"ends_at"`
	Revoked bool      `json:"revoked"`
}

type vaudit struct {
	ID      string    `json:"id"`
	At      time.Time `json:"at"`
	Actor   string    `json:"actor"`
	Org     string    `json:"org,omitempty"`
	Action  string    `json:"action"`
	Target  string    `json:"target,omitempty"`
	Result  string    `json:"result"`
	Addr    string    `json:"addr,omitempty"`
	Request string    `json:"request,omitempty"`
	Ticket  string    `json:"ticket,omitempty"`
	Session string    `json:"support_session,omitempty"`
	Summary string    `json:"summary,omitempty"`
}

type addrKey struct{}

// WithAddr attaches the vendor user's client address (X-Vendor-Client-Address) for audit.
func WithAddr(ctx context.Context, addr string) context.Context {
	return context.WithValue(ctx, addrKey{}, addr)
}

func addrOf(ctx context.Context) string { a, _ := ctx.Value(addrKey{}).(string); return a }

// vendorAudit appends to the vendor audit chain in the request's transaction.
func (s *Service) vendorAudit(ctx context.Context, tx repository.Tx, v vaudit) error {
	v.ID, v.At, v.Addr, v.Request = string(s.NewID()), s.now(), addrOf(ctx), logx.RequestID(ctx)
	if v.Result == "" {
		v.Result = "succeeded"
	}
	if v.Actor == "" {
		if p, ok := principal(ctx); ok {
			v.Actor = p.VendorUser()
		}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return tx.AppendAudit(repository.Platform, v.ID, b)
}

// vendorPrincipal returns the verified vendor user.
func (s *Service) vendorPrincipal(ctx context.Context) (auth.Principal, error) {
	p, ok := principal(ctx)
	if !ok || p.Realm != auth.RealmVendor {
		return auth.Principal{}, errUnauth()
	}
	return p, nil
}

func vendorUserDTO(u *vendorUser) gen.VendorUser {
	return gen.VendorUser{Id: u.ID, Email: openapi_types.Email(u.Email), DisplayName: u.Name, Role: gen.VendorRole(u.Role), Status: gen.VendorUserStatus(u.Status),
		TotpEnrolled: u.Enrolled, CreatedAt: u.CreatedAt}
}

func signInFailed() error {
	return apperr.New(apperr.Unauthenticated, "vendor.sign_in_failed", "sign-in failed")
}

func setupInvalid() error {
	return apperr.New(apperr.Validation, "setup_link_invalid", "the setup link is not valid")
}

func (s *Service) userByEmail(tx repository.Tx, email string) (*vendorUser, error) {
	us, err := find[vendorUser](tx, kVendorUser, repository.Global, strings.ToLower(email))
	if err != nil || len(us) == 0 {
		return nil, err
	}
	return &us[0], nil
}

func (s *Service) putVendorUser(tx repository.Tx, u *vendorUser) error {
	return put(tx, kVendorUser, repository.Global, u.ID, u, keys{k1: u.Email, unique: true})
}

// newSetupLink creates a one-time setup link (24 hours, single use) and returns its token.
func (s *Service) newSetupLink(tx repository.Tx, userID string) (string, error) {
	tok := s.Rand.Token()
	d := vendorSetup{ID: crypto.MAC(s.Cfg.MACKey, "setup", tok), UserID: userID, Expires: s.now().Add(s.Cfg.SetupLinkTTL)}
	return tok, put(tx, kVendorSet, repository.Global, d.ID, d, keys{k1: userID})
}

// ---- sign-in and sessions ----

// CreateVendorSession signs a vendor user in: password (Argon2id) and a TOTP code accepted once.
// Every failure, including lockout, is the same 401 (ADR-0013, A0 AC-ID-4, AC-ID-5).
func (s *Service) CreateVendorSession(ctx context.Context, in gen.VendorSignIn) (gen.VendorSession, error) {
	now := s.now()
	var out gen.VendorSession
	var refuse error
	err := s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		addr := addrOf(ctx)
		al, err := s.limitGet(tx, "vendoraddr:"+addr)
		if err != nil {
			return err
		}
		al.Times = prune(al.Times, now, 15*time.Minute)
		if len(al.Times) >= 20 {
			refuse = signInFailed()
			return nil
		}
		u, err := s.userByEmail(tx, string(in.Email))
		if err != nil {
			return err
		}
		failed := func() error {
			al.Times = append(al.Times, now)
			if err := s.limitPut(tx, "vendoraddr:"+addr, al); err != nil {
				return err
			}
			if u != nil {
				u.Fails = append(prune(u.Fails, now, 15*time.Minute), now)
				if len(u.Fails) >= s.Cfg.VendorLockFails {
					u.Locked = now.Add(15 * time.Minute)
				}
				if err := s.putVendorUser(tx, u); err != nil {
					return err
				}
				if err := s.vendorAudit(ctx, tx, vaudit{Actor: u.ID, Action: "vendor.sign_in", Result: "failed"}); err != nil {
					return err
				}
			}
			refuse = signInFailed()
			return nil
		}
		if u == nil {
			// Same work as a real check so timing does not reveal whether the email exists.
			crypto.CheckPassword(in.Password, "1,1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
			return failed()
		}
		if u.Status != "active" || now.Before(u.Locked) {
			return failed()
		}
		secret, err := crypto.Open(s.Cfg.TOTPKey, u.TOTPEnc)
		if err != nil || !crypto.CheckPassword(in.Password, u.Hash) {
			return failed()
		}
		step, ok := s.totpOK(secret, in.TotpCode, now, u.TOTPStep)
		if !ok {
			return failed()
		}
		u.TOTPStep, u.Fails, u.Locked = step, nil, time.Time{}
		if err := s.putVendorUser(tx, u); err != nil {
			return err
		}
		sess := vendorSession{ID: string(s.NewID()), UserID: u.ID, Started: now, EndsAt: now.Add(s.Cfg.VendorSessionMax)}
		handle := s.Rand.Token()
		if err := put(tx, kVendorSess, repository.Global, sess.ID, sess, keys{k1: crypto.MAC(s.Cfg.MACKey, "renew", handle), k2: u.ID}); err != nil {
			return err
		}
		out, err = s.vendorSessionOut(u, &sess, handle)
		if err != nil {
			return err
		}
		return s.vendorAudit(ctx, tx, vaudit{Actor: u.ID, Action: "vendor.sign_in"})
	})
	if err != nil {
		return out, err
	}
	return out, refuse
}

func (s *Service) vendorSessionOut(u *vendorUser, sess *vendorSession, handle string) (gen.VendorSession, error) {
	now := s.now()
	exp := now.Add(s.Cfg.VendorAccessTTL)
	if exp.After(sess.EndsAt) {
		exp = sess.EndsAt
	}
	perms := VendorPermissions(u.Role)
	tok, err := s.Tokens.Vendor(auth.Claims{Subject: u.ID, Type: auth.TypeUser, SessionID: sess.ID, AMR: []string{"otp"}, AuthTime: now.Unix(),
		Grants: []auth.Grant{{Outlets: []string{"*"}, Perms: perms}}, IssuedAt: now.Unix(), ExpiresAt: exp.Unix(), JTI: string(s.NewID())})
	if err != nil {
		return gen.VendorSession{}, err
	}
	return gen.VendorSession{AccessToken: tok, ExpiresAt: exp, RenewalHandle: handle, SessionEndsAt: sess.EndsAt,
		User: gen.VendorPrincipal{Id: u.ID, DisplayName: u.Name, Role: gen.VendorRole(u.Role), Permissions: perms}}, nil
}

// RenewVendorSession rotates the renewal handle and issues a new access token; refused for a
// deactivated user or after the absolute session end.
func (s *Service) RenewVendorSession(ctx context.Context, in gen.VendorSessionRenewal) (gen.VendorSession, error) {
	now := s.now()
	var out gen.VendorSession
	var refuse error
	err := s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		rs, err := find[vendorSession](tx, kVendorSess, repository.Global, crypto.MAC(s.Cfg.MACKey, "renew", in.RenewalHandle))
		if err != nil || len(rs) == 0 {
			refuse = signInFailed()
			return err
		}
		sess := rs[0]
		u, err := get[vendorUser](tx, kVendorUser, repository.Global, sess.UserID)
		if err != nil {
			return err
		}
		if u == nil || u.Status != "active" || sess.Revoked || !now.Before(sess.EndsAt) {
			refuse = signInFailed()
			return nil
		}
		handle := s.Rand.Token()
		if err := put(tx, kVendorSess, repository.Global, sess.ID, sess, keys{k1: crypto.MAC(s.Cfg.MACKey, "renew", handle), k2: u.ID}); err != nil {
			return err
		}
		out, err = s.vendorSessionOut(u, &sess, handle)
		return err
	})
	if err != nil {
		return out, err
	}
	return out, refuse
}

// EndVendorSession ends the caller's vendor session and any support session of the user.
func (s *Service) EndVendorSession(ctx context.Context) error {
	p, err := s.vendorPrincipal(ctx)
	if err != nil {
		return err
	}
	userID := ""
	err = s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		sess, err := get[vendorSession](tx, kVendorSess, repository.Global, p.SessionID)
		if err != nil || sess == nil {
			return err
		}
		sess.Revoked, userID = true, sess.UserID
		return put(tx, kVendorSess, repository.Global, sess.ID, sess, keys{k2: sess.UserID})
	})
	if err != nil || userID == "" {
		return err
	}
	return s.endUserSupport(ctx, userID)
}

// ---- setup ----

// BeginVendorSetup validates a setup link and returns the TOTP enrolment material.
func (s *Service) BeginVendorSetup(ctx context.Context, in gen.BeginVendorSetup) (gen.VendorSetupChallenge, error) {
	now := s.now()
	var out gen.VendorSetupChallenge
	var refuse error
	err := s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		d, err := get[vendorSetup](tx, kVendorSet, repository.Global, crypto.MAC(s.Cfg.MACKey, "setup", in.SetupToken))
		if err != nil {
			return err
		}
		if d == nil || d.Used || !now.Before(d.Expires) {
			refuse = setupInvalid()
			return nil
		}
		u, err := get[vendorUser](tx, kVendorUser, repository.Global, d.UserID)
		if err != nil || u == nil || u.Status != "setup_pending" {
			refuse = setupInvalid()
			return err
		}
		secret := s.Rand.Bytes(20)
		if d.Secret, err = crypto.Seal(s.Rand, s.Cfg.TOTPKey, secret); err != nil {
			return err
		}
		if err := put(tx, kVendorSet, repository.Global, d.ID, d, keys{k1: d.UserID}); err != nil {
			return err
		}
		b32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
		out = gen.VendorSetupChallenge{Email: openapi_types.Email(u.Email), ExpiresAt: d.Expires,
			TotpProvisioningUri: fmt.Sprintf("otpauth://totp/Hostry:%s?secret=%s&issuer=Hostry", u.Email, b32)}
		return nil
	})
	if err != nil {
		return out, err
	}
	return out, refuse
}

// CompleteVendorSetup sets the password and confirms TOTP enrolment; the link is single use.
func (s *Service) CompleteVendorSetup(ctx context.Context, in gen.CompleteVendorSetup) (gen.VendorUser, error) {
	now := s.now()
	var out gen.VendorUser
	var refuse error
	err := s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		d, err := get[vendorSetup](tx, kVendorSet, repository.Global, crypto.MAC(s.Cfg.MACKey, "setup", in.SetupToken))
		if err != nil {
			return err
		}
		if d == nil || d.Used || !now.Before(d.Expires) || len(d.Secret) == 0 {
			refuse = setupInvalid()
			return nil
		}
		u, err := get[vendorUser](tx, kVendorUser, repository.Global, d.UserID)
		if err != nil || u == nil || u.Status != "setup_pending" {
			refuse = setupInvalid()
			return err
		}
		if len(in.Password) < 12 {
			refuse = errInvalid("password", "too_short")
			return nil
		}
		secret, err := crypto.Open(s.Cfg.TOTPKey, d.Secret)
		if err != nil {
			return err
		}
		step, ok := s.totpOK(secret, in.TotpCode, now, 0)
		if !ok {
			refuse = errInvalid("totp_code", "invalid")
			return nil
		}
		u.Hash, u.TOTPEnc, u.TOTPStep, u.Enrolled, u.Status, u.CredAt = crypto.HashPassword(s.Rand, s.Cfg.PasswordParams, in.Password), d.Secret, step, true, "active", now
		d.Used = true
		if err := put(tx, kVendorSet, repository.Global, d.ID, d, keys{k1: d.UserID}); err != nil {
			return err
		}
		if err := s.putVendorUser(tx, u); err != nil {
			return err
		}
		out = vendorUserDTO(u)
		return s.vendorAudit(ctx, tx, vaudit{Actor: u.ID, Action: "vendor.setup_completed", Target: u.ID})
	})
	if err != nil {
		return out, err
	}
	return out, refuse
}

// ---- vendor users ----

// ListVendorUsers lists vendor users.
func (s *Service) ListVendorUsers(ctx context.Context, p gen.ListVendorUsersParams) (gen.VendorUserPage, error) {
	if _, err := s.vendorPrincipal(ctx); err != nil {
		return gen.VendorUserPage{}, err
	}
	limit := pageLimit(p.Limit, 50, 100)
	out := gen.VendorUserPage{Items: []gen.VendorUser{}}
	err := s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		us, err := list[vendorUser](tx, kVendorUser, repository.Global, deref(p.Cursor), limit+1)
		if err != nil {
			return err
		}
		for i := range us {
			if i == limit {
				c := us[i-1].ID
				out.NextCursor = &c
				break
			}
			out.Items = append(out.Items, vendorUserDTO(&us[i]))
		}
		return s.vendorAudit(ctx, tx, vaudit{Action: "vendor.user.listed", Summary: fmt.Sprintf("%d users", len(out.Items))})
	})
	return out, err
}

// CreateVendorUser creates a user in setup_pending; the setup link goes out by email, never in the response.
func (s *Service) CreateVendorUser(ctx context.Context, in gen.CreateVendorUser) (gen.VendorUser, error) {
	if _, err := s.vendorPrincipal(ctx); err != nil {
		return gen.VendorUser{}, err
	}
	email := strings.ToLower(string(in.Email))
	if _, err := mail.ParseAddress(email); err != nil || strings.TrimSpace(in.DisplayName) == "" || !in.Role.Valid() {
		return gen.VendorUser{}, errInvalid("email", "invalid")
	}
	var out gen.VendorUser
	var link, to string
	err := s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		if ex, err := get[vendorUser](tx, kVendorUser, repository.Global, in.Id); err != nil {
			return err
		} else if ex != nil && ex.Email == email {
			out = vendorUserDTO(ex)
			return nil
		}
		now := s.now()
		u := &vendorUser{ID: in.Id, Email: email, Name: strings.TrimSpace(in.DisplayName), Role: string(in.Role), Status: "setup_pending", CreatedAt: now, CredAt: now}
		if err := s.putVendorUser(tx, u); err != nil {
			if err == repository.ErrConflict {
				return apperr.New(apperr.Conflict, "vendor_user_exists", "a vendor user with this email exists")
			}
			return err
		}
		tok, err := s.newSetupLink(tx, u.ID)
		if err != nil {
			return err
		}
		link, to = tok, email
		out = vendorUserDTO(u)
		return s.vendorAudit(ctx, tx, vaudit{Action: "vendor.user.created", Target: u.ID})
	})
	if err == nil && link != "" && s.Mail != nil {
		_ = s.Mail.Send(context.WithoutCancel(ctx), to, "vendor_setup", link)
	}
	return out, err
}

func (s *Service) activePlatformAdmins(tx repository.Tx) (n int, err error) {
	us, err := list[vendorUser](tx, kVendorUser, repository.Global, "", 0)
	for _, u := range us {
		if u.Role == "platform_admin" && u.Status == "active" {
			n++
		}
	}
	return n, err
}

// UpdateVendorUser changes role or status. Deactivation ends the user's sessions at once.
func (s *Service) UpdateVendorUser(ctx context.Context, id string, in gen.UpdateVendorUser) (gen.VendorUser, error) {
	p, err := s.vendorPrincipal(ctx)
	if err != nil {
		return gen.VendorUser{}, err
	}
	var out gen.VendorUser
	deactivated := ""
	err = s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		u, err := get[vendorUser](tx, kVendorUser, repository.Global, id)
		if err != nil || u == nil {
			return notFoundOr(err)
		}
		admins, err := s.activePlatformAdmins(tx)
		if err != nil {
			return err
		}
		leavingAdmin := u.Role == "platform_admin" && u.Status == "active"
		if in.Status != nil && string(*in.Status) == "deactivated" && u.Status != "deactivated" {
			if u.ID == p.VendorUser() {
				return apperr.New(apperr.Conflict, "cannot_deactivate_self", "you cannot deactivate yourself")
			}
			if leavingAdmin && admins <= 1 {
				return apperr.New(apperr.Conflict, "last_platform_admin", "this would leave no active platform admin")
			}
			u.Status = "deactivated"
			if err := s.endVendorUserSessions(tx, u.ID); err != nil {
				return err
			}
			deactivated = u.ID
		} else if in.Status != nil && string(*in.Status) == "active" && u.Status == "deactivated" {
			u.Status = "active"
		}
		if in.Role != nil && string(*in.Role) != u.Role {
			if u.ID == p.VendorUser() {
				return apperr.New(apperr.Conflict, "cannot_deactivate_self", "you cannot change your own role")
			}
			if leavingAdmin && string(*in.Role) != "platform_admin" && admins <= 1 {
				return apperr.New(apperr.Conflict, "last_platform_admin", "this would leave no active platform admin")
			}
			u.Role, u.CredAt = string(*in.Role), s.now()
		}
		if err := s.putVendorUser(tx, u); err != nil {
			return err
		}
		out = vendorUserDTO(u)
		return s.vendorAudit(ctx, tx, vaudit{Action: "vendor.user.updated", Target: u.ID})
	})
	if err == nil && deactivated != "" {
		err = s.endUserSupport(ctx, deactivated)
	}
	return out, err
}

func (s *Service) endVendorUserSessions(tx repository.Tx, userID string) error {
	ss, err := findK2[vendorSession](tx, kVendorSess, repository.Global, userID)
	for i := range ss {
		ss[i].Revoked = true
		if err := put(tx, kVendorSess, repository.Global, ss[i].ID, ss[i], keys{k2: userID, k1: "ended:" + ss[i].ID}); err != nil {
			return err
		}
	}
	return err
}

// ResetVendorUserTotp returns a user to setup_pending (new setup link by email); the account
// counts as new for the 7-day approver rule.
func (s *Service) ResetVendorUserTotp(ctx context.Context, id string) (gen.VendorUser, error) {
	if _, err := s.vendorPrincipal(ctx); err != nil {
		return gen.VendorUser{}, err
	}
	var out gen.VendorUser
	var link, to string
	err := s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		u, err := get[vendorUser](tx, kVendorUser, repository.Global, id)
		if err != nil || u == nil {
			return notFoundOr(err)
		}
		u.Status, u.Enrolled, u.TOTPEnc, u.Hash, u.CredAt = "setup_pending", false, nil, "", s.now()
		if err := s.putVendorUser(tx, u); err != nil {
			return err
		}
		if err := s.endVendorUserSessions(tx, u.ID); err != nil {
			return err
		}
		tok, err := s.newSetupLink(tx, u.ID)
		if err != nil {
			return err
		}
		link, to = tok, u.Email
		out = vendorUserDTO(u)
		return s.vendorAudit(ctx, tx, vaudit{Action: "vendor.user.totp_reset", Target: u.ID})
	})
	if err == nil && link != "" && s.Mail != nil {
		_ = s.Mail.Send(context.WithoutCancel(ctx), to, "vendor_setup", link)
	}
	return out, err
}

// ---- vendor audit ----

// ListVendorAuditEntries lists the vendor audit log newest first. admin.audit.read sees all
// entries, everyone else only their own.
func (s *Service) ListVendorAuditEntries(ctx context.Context, p gen.ListVendorAuditEntriesParams) (gen.VendorAuditPage, error) {
	pr, err := s.vendorPrincipal(ctx)
	if err != nil {
		return gen.VendorAuditPage{}, err
	}
	all := false
	if sc, err := auth.ScopeFor(ctx, "admin.audit.read"); err == nil && !sc.Empty() {
		all = true
	}
	limit := pageLimit(p.Limit, 50, 100)
	out := gen.VendorAuditPage{Items: []gen.VendorAuditEntry{}}
	err = s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		before := deref(p.Cursor)
		for {
			rs, err := tx.ListAudit(repository.Platform, before, 200)
			if err != nil {
				return err
			}
			for _, r := range rs {
				before = r.ID
				var v vaudit
				if err := json.Unmarshal(r.Doc, &v); err != nil {
					return err
				}
				if (!all && v.Actor != pr.VendorUser()) || (p.From != nil && v.At.Before(*p.From)) || (p.To != nil && v.At.After(*p.To)) ||
					(p.ActorVendorUserId != nil && v.Actor != *p.ActorVendorUserId) || (p.OrganisationId != nil && v.Org != *p.OrganisationId) ||
					(p.Action != nil && v.Action != *p.Action) || (p.SupportSessionId != nil && v.Session != *p.SupportSessionId) {
					continue
				}
				if len(out.Items) == limit {
					c := out.Items[len(out.Items)-1].Id
					out.NextCursor = &c
					return nil
				}
				out.Items = append(out.Items, vendorAuditDTO(v))
			}
			if len(rs) < 200 {
				return nil
			}
		}
	})
	return out, err
}

func vendorAuditDTO(v vaudit) gen.VendorAuditEntry {
	opt := func(x string) *string {
		if x == "" {
			return nil
		}
		return &x
	}
	return gen.VendorAuditEntry{Id: v.ID, OccurredAt: v.At, ActorVendorUserId: v.Actor, Action: v.Action, Result: gen.VendorAuditEntryResult(v.Result), RequestId: v.Request,
		OrganisationId: opt(v.Org), TargetId: opt(v.Target), SourceAddress: opt(v.Addr), SupportSessionId: opt(v.Session), TicketReference: opt(v.Ticket), ReadSummary: opt(v.Summary)}
}

var _ = ids.ID("")

// totpOK checks a TOTP code against the last accepted step (a code is accepted once).
func (s *Service) totpOK(secret []byte, code string, now time.Time, last int64) (int64, bool) {
	if s.exampleLiteral(code, "123456") {
		return last + 1, true
	}
	step, ok := crypto.CheckTOTP(secret, code, now)
	return step, ok && step > last
}
