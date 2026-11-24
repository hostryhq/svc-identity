package service

import (
	"context"
	"strings"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/repository"
)

type supportSession struct {
	ID      string    `json:"id"`
	UserID  string    `json:"user_id"`
	Org     string    `json:"org"`
	Mode    string    `json:"mode"`
	Reason  string    `json:"reason"`
	Ticket  string    `json:"ticket"`
	Started time.Time `json:"started"`
	EndsAt  time.Time `json:"ends_at"`
	Ended   time.Time `json:"ended,omitempty"`
}

func (ss *supportSession) status(now time.Time) string {
	switch {
	case !ss.Ended.IsZero():
		return "ended"
	case !now.Before(ss.EndsAt):
		return "expired"
	}
	return "active"
}

func supportDTO(ss *supportSession, now time.Time) gen.SupportSession {
	g := gen.SupportSession{Id: ss.ID, OrganisationId: ss.Org, VendorUserId: ss.UserID, Mode: gen.SupportSessionModeView, StartedAt: ss.Started, EndsAt: ss.EndsAt,
		Status: gen.SupportSessionStatus(ss.status(now)), TicketReference: ss.Ticket}
	if !ss.Ended.IsZero() {
		t := ss.Ended
		g.EndedAt = &t
	}
	return g
}

func (s *Service) supportToken(ss *supportSession) (gen.SupportToken, error) {
	now := s.now()
	exp := now.Add(s.Cfg.SupportToken)
	if exp.After(ss.EndsAt) {
		exp = ss.EndsAt
	}
	var perms []string
	for _, e := range catalogueEntries {
		if e.Realm == "tenant" && e.SupportViewable && !e.StrongOnly && !e.OwnerGrant && !e.Sensitive {
			perms = append(perms, e.Key)
		}
	}
	tok, err := s.Tokens.Access(auth.Claims{Subject: "support:" + ss.UserID, Type: auth.TypeSupport, TenantID: ss.Org, SessionID: ss.ID, Mode: auth.ModeView, Ticket: ss.Ticket,
		Grants: []auth.Grant{{Outlets: []string{"*"}, Perms: perms}}, IssuedAt: now.Unix(), ExpiresAt: exp.Unix(), JTI: string(s.NewID())})
	return gen.SupportToken{AccessToken: tok, ExpiresAt: exp}, err
}

// StartSupportSession starts a view-mode support session for one organisation (ADR-0005 section
// 10, A2.5). Act mode is refused in Phase 1; one active session per vendor user.
func (s *Service) StartSupportSession(ctx context.Context, in gen.StartSupportSession) (gen.SupportSessionStarted, error) {
	pr, err := s.vendorPrincipal(ctx)
	if err != nil {
		return gen.SupportSessionStarted{}, err
	}
	if in.Mode != nil && *in.Mode == gen.StartSupportSessionModeAct {
		return gen.SupportSessionStarted{}, apperr.New(apperr.Validation, "mode_not_supported", "act mode is not available yet").WithFields(apperr.FieldError{Field: "mode", Code: "mode_not_supported"})
	}
	dur := s.Cfg.SupportDefault
	if in.DurationMinutes != nil {
		dur = time.Duration(*in.DurationMinutes) * time.Minute
	}
	if dur <= 0 || dur > s.Cfg.SupportMax {
		return gen.SupportSessionStarted{}, errInvalid("duration_minutes", "out_of_range")
	}
	if strings.TrimSpace(in.TicketReference) == "" {
		return gen.SupportSessionStarted{}, errInvalid("ticket_reference", "required")
	}
	if len(strings.TrimSpace(in.Reason)) < 10 {
		return gen.SupportSessionStarted{}, errInvalid("reason", "too_short")
	}
	ctx, err = s.vendorOrg(ctx, "admin.support.session.start", in.OrganisationId)
	if err != nil {
		return gen.SupportSessionStarted{}, err
	}
	var out gen.SupportSessionStarted
	err = s.Store.Tx(ctx, in.OrganisationId, func(tx repository.Tx) error {
		now := s.now()
		u, err := get[vendorUser](tx, kVendorUser, repository.Global, pr.VendorUser())
		if err != nil {
			return err
		}
		if u == nil || u.Status != "active" {
			return errUnauth()
		}
		mine, err := find[supportSession](tx, kSupport, repository.Global, u.ID)
		if err != nil {
			return err
		}
		for i := range mine {
			if mine[i].status(now) == "active" {
				return apperr.New(apperr.Conflict, "support_session_active", "this vendor user already has an active support session")
			}
		}
		ss := supportSession{ID: string(s.NewID()), UserID: u.ID, Org: in.OrganisationId, Mode: "view", Reason: strings.TrimSpace(in.Reason),
			Ticket: strings.TrimSpace(in.TicketReference), Started: now, EndsAt: now.Add(dur)}
		if err := put(tx, kSupport, repository.Global, ss.ID, ss, keys{k1: u.ID, k2: ss.Org}); err != nil {
			return err
		}
		tok, err := s.supportToken(&ss)
		if err != nil {
			return err
		}
		out = gen.SupportSessionStarted{Session: supportDTO(&ss, now), Token: tok}
		auth.SetAuditTarget(ctx, ss.ID)
		if err := s.audit(tx, ss.Org, auditDoc{Action: "support.session.started", ActorKind: "vendor", ActorLbl: "Hostry support", Outcome: "succeeded", Target: ss.ID,
			Session: ss.ID, Ticket: ss.Ticket, Reason: ss.Reason, Show: true}); err != nil {
			return err
		}
		return s.vendorAudit(ctx, tx, vaudit{Org: ss.Org, Action: "support.session.started", Target: ss.ID, Session: ss.ID, Ticket: ss.Ticket})
	})
	return out, err
}

func (s *Service) ownSupport(tx repository.Tx, pr auth.Principal, id string) (*supportSession, error) {
	ss, err := get[supportSession](tx, kSupport, repository.Global, id)
	if err != nil || ss == nil || ss.UserID != pr.VendorUser() {
		return nil, notFoundOr(err)
	}
	return ss, nil
}

// GetSupportSession returns the caller's own support session.
func (s *Service) GetSupportSession(ctx context.Context, id string) (gen.SupportSession, error) {
	pr, err := s.vendorPrincipal(ctx)
	if err != nil {
		return gen.SupportSession{}, err
	}
	var out gen.SupportSession
	err = s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		ss, err := s.ownSupport(tx, pr, id)
		if err != nil {
			return err
		}
		out = supportDTO(ss, s.now())
		return s.vendorAudit(ctx, tx, vaudit{Org: ss.Org, Action: "support.session.read", Target: ss.ID, Session: ss.ID})
	})
	return out, err
}

// RenewSupportToken issues a new token with the same session end; refused after the end.
func (s *Service) RenewSupportToken(ctx context.Context, id string) (gen.SupportToken, error) {
	pr, err := s.vendorPrincipal(ctx)
	if err != nil {
		return gen.SupportToken{}, err
	}
	var out gen.SupportToken
	err = s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		ss, err := s.ownSupport(tx, pr, id)
		if err != nil {
			return err
		}
		if ss.status(s.now()) != "active" {
			return apperr.New(apperr.Conflict, "support_session_ended", "the support session has ended")
		}
		out, err = s.supportToken(ss)
		if err != nil {
			return err
		}
		return s.vendorAudit(ctx, tx, vaudit{Org: ss.Org, Action: "support.token.renewed", Target: ss.ID, Session: ss.ID})
	})
	return out, err
}

// EndSupportSession ends a support session (idempotent) and writes the end entry to the tenant's log.
func (s *Service) EndSupportSession(ctx context.Context, id string) (gen.SupportSession, error) {
	pr, err := s.vendorPrincipal(ctx)
	if err != nil {
		return gen.SupportSession{}, err
	}
	var out gen.SupportSession
	var org string
	err = s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		ss, err := s.ownSupport(tx, pr, id)
		if err != nil {
			return err
		}
		org = ss.Org
		if ss.Ended.IsZero() && s.now().Before(ss.EndsAt) {
			ss.Ended = s.now()
			if err := put(tx, kSupport, repository.Global, ss.ID, ss, keys{k1: ss.UserID, k2: ss.Org}); err != nil {
				return err
			}
		}
		out = supportDTO(ss, s.now())
		return s.vendorAudit(ctx, tx, vaudit{Org: ss.Org, Action: "support.session.ended", Target: ss.ID, Session: ss.ID})
	})
	if err != nil {
		return out, err
	}
	return out, s.tenantSupportEnded(ctx, org, id, "support.session.ended")
}

// tenantSupportEnded writes the end entry to the organisation's own audit log.
func (s *Service) tenantSupportEnded(ctx context.Context, org, sid, action string) error {
	return s.Store.Tx(ctx, org, func(tx repository.Tx) error {
		return s.audit(tx, org, auditDoc{Action: action, ActorKind: "vendor", ActorLbl: "Hostry support", Outcome: "succeeded", Target: sid, Session: sid, Show: true})
	})
}

// endUserSupport ends every active support session of a vendor user (sign-out, deactivation).
func (s *Service) endUserSupport(ctx context.Context, userID string) error {
	var ended []supportSession
	err := s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		ss, err := find[supportSession](tx, kSupport, repository.Global, userID)
		if err != nil {
			return err
		}
		for i := range ss {
			if ss[i].status(s.now()) != "active" {
				continue
			}
			ss[i].Ended = s.now()
			if err := put(tx, kSupport, repository.Global, ss[i].ID, ss[i], keys{k1: userID, k2: ss[i].Org}); err != nil {
				return err
			}
			ended = append(ended, ss[i])
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, e := range ended {
		if err := s.tenantSupportEnded(ctx, e.Org, e.ID, "support.session.ended"); err != nil {
			return err
		}
	}
	return nil
}
