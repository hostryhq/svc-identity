package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/repository"
)

type approvalReq struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	AccountID string    `json:"account_id"`
	Member    string    `json:"member"`
	Session   string    `json:"session"`
	Operation string    `json:"operation"`
	BodyHash  string    `json:"body_hash"`
	State     string    `json:"state"` // pending, approved, rejected, lapsed, used
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Token     string    `json:"token,omitempty"` // shown once to the requester
	Approver  string    `json:"approver,omitempty"`
}

func (r *approvalReq) effective(now time.Time) string {
	if r.State == "pending" && !now.Before(r.ExpiresAt) {
		return "lapsed"
	}
	return r.State
}

func (s *Service) callerSession(tx repository.Tx, p auth.Principal) (*session, *binding, error) {
	sess, err := get[session](tx, kSession, repository.Global, p.SessionID)
	if err != nil || sess == nil || sess.Revoked || sess.MemberID != p.Subject {
		return nil, nil, err
	}
	var b *binding
	if sess.Binding != "" {
		b, err = get[binding](tx, kBinding, repository.Global, sess.Binding)
	}
	return sess, b, err
}

func (s *Service) underCaution(b *binding) bool { return b != nil && s.now().Before(b.Caution) }

// CreateApprovalRequest files a refused operation for approval from another binding (A2.2 item 6).
// The approver's app shows the stored operation and body, never requester-supplied text.
func (s *Service) CreateApprovalRequest(ctx context.Context, operationID string, requestBody []byte) (gen.ApprovalRequest, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.ApprovalRequest{}, errUnauth()
	}
	if s.Approvable != nil && !s.Approvable(operationID) {
		return gen.ApprovalRequest{}, errInvalid("operation_id", "not_approvable")
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(requestBody, &obj) != nil || obj == nil {
		return gen.ApprovalRequest{}, errInvalid("request_body", "invalid")
	}
	var out gen.ApprovalRequest
	err := s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		sess, _, err := s.callerSession(tx, pr)
		if err != nil {
			return err
		}
		if sess == nil {
			return errUnauth()
		}
		now := s.now()
		r := approvalReq{ID: string(s.NewID()), TenantID: pr.TenantID, AccountID: sess.AccountID, Member: pr.Subject, Session: sess.ID,
			Operation: operationID, BodyHash: BodyHashField(requestBody), State: "pending", CreatedAt: now, ExpiresAt: now.Add(s.Cfg.ApprovalReqTTL)}
		if err := put(tx, kApprReq, repository.Global, r.ID, r, keys{k1: r.TenantID, k2: r.AccountID}); err != nil {
			return err
		}
		out = approvalDTO(&r, now, true)
		return nil
	})
	return out, err
}

// BodyHashField is the approval's body_hash as the contract states it: "sha256:" and the lower-case hex
// SHA-256 over the exact body bytes as sent. The bh claim of the approval token carries the same digest
// in go-auth's encoding (auth.BodyHash, base64url), which is what auth.VerifyBodyHash and the
// approval checker compare against the repeated request.
func BodyHashField(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// claimBodyHash converts a stored body_hash field to the bh claim value.
func claimBodyHash(field string) string {
	raw, err := hex.DecodeString(strings.TrimPrefix(field, "sha256:"))
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func approvalDTO(r *approvalReq, now time.Time, showToken bool) gen.ApprovalRequest {
	g := gen.ApprovalRequest{Id: r.ID, OperationId: r.Operation, BodyHash: r.BodyHash, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, State: gen.ApprovalRequestState(r.effective(now))}
	if showToken && r.Token != "" {
		t := r.Token
		g.ApprovalToken = &t
	}
	return g
}

// ListApprovalRequests lists the caller's own requests and, from a binding not under caution,
// pending requests of the same account or (for owners) of the organisation.
func (s *Service) ListApprovalRequests(ctx context.Context, p gen.ListApprovalRequestsParams) (gen.ApprovalRequestPage, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.ApprovalRequestPage{}, errUnauth()
	}
	out := gen.ApprovalRequestPage{Items: []gen.ApprovalRequest{}}
	err := s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		sess, b, err := s.callerSession(tx, pr)
		if err != nil || sess == nil {
			return err
		}
		a, err := s.actorFor(ctx, tx)
		if err != nil {
			return err
		}
		rs, err := find[approvalReq](tx, kApprReq, repository.Global, pr.TenantID)
		if err != nil {
			return err
		}
		now := s.now()
		for i := range rs {
			r := &rs[i]
			mine := r.Member == pr.Subject
			eligible := !s.underCaution(b) && r.effective(now) == "pending" && (r.AccountID == sess.AccountID || a.h.Owner)
			if mine || eligible {
				out.Items = append(out.Items, approvalDTO(r, now, mine))
			}
		}
		return nil
	})
	return out, err
}

// GetApprovalRequest returns a request. The approval token appears once, to the requester.
func (s *Service) GetApprovalRequest(ctx context.Context, id string) (gen.ApprovalRequest, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.ApprovalRequest{}, errUnauth()
	}
	var out gen.ApprovalRequest
	err := s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		r, err := get[approvalReq](tx, kApprReq, repository.Global, id)
		if err != nil || r == nil || r.TenantID != pr.TenantID {
			return notFoundOr(err)
		}
		sess, b, err := s.callerSession(tx, pr)
		if err != nil || sess == nil {
			return notFoundOr(err)
		}
		a, err := s.actorFor(ctx, tx)
		if err != nil {
			return err
		}
		mine := r.Member == pr.Subject
		if !mine && (s.underCaution(b) || !(r.AccountID == sess.AccountID || a.h.Owner)) {
			return errNotFound()
		}
		out = approvalDTO(r, s.now(), mine)
		if mine && r.Token != "" {
			r.Token = ""
			return put(tx, kApprReq, repository.Global, r.ID, r, keys{k1: r.TenantID, k2: r.AccountID})
		}
		return nil
	})
	return out, err
}

// DecideApprovalRequest approves or rejects a request. A binding under caution can approve nothing
// and reject nothing (A2.2 item 7). Approval mints the single-use approval token.
func (s *Service) DecideApprovalRequest(ctx context.Context, id string, in gen.DecideApproval) (gen.ApprovalRequest, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.ApprovalRequest{}, errUnauth()
	}
	var out gen.ApprovalRequest
	err := s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		r, err := get[approvalReq](tx, kApprReq, repository.Global, id)
		if err != nil || r == nil || r.TenantID != pr.TenantID {
			return notFoundOr(err)
		}
		sess, b, err := s.callerSession(tx, pr)
		if err != nil || sess == nil {
			return notFoundOr(err)
		}
		a, err := s.actorFor(ctx, tx)
		if err != nil {
			return err
		}
		if pr.Type != auth.TypeUser || s.underCaution(b) {
			return apperr.New(apperr.Forbidden, "auth.permission_denied", "permission denied")
		}
		sameAccount := r.AccountID == sess.AccountID
		if !sameAccount && !a.h.Owner {
			return errNotFound()
		}
		now := s.now()
		if r.effective(now) != "pending" {
			return apperr.New(apperr.Conflict, "approval_not_pending", "the request is no longer pending")
		}
		if in.Decision == gen.Reject {
			r.State = "rejected"
		} else {
			r.State, r.Approver = "approved", pr.Subject
			claims := auth.Claims{Subject: r.Member, Type: auth.TypeApproval, TenantID: r.TenantID, SessionID: r.Session, Operation: r.Operation,
				BodyHash: claimBodyHash(r.BodyHash), IssuedAt: now.Unix(), ExpiresAt: now.Add(s.Cfg.ApprovalTokTTL).Unix(), JTI: string(s.NewID())}
			tok, err := s.Tokens.Access(claims)
			if err != nil {
				return err
			}
			r.Token = tok
		}
		if err := put(tx, kApprReq, repository.Global, r.ID, r, keys{k1: r.TenantID, k2: r.AccountID}); err != nil {
			return err
		}
		out = approvalDTO(r, now, false)
		return s.audit(tx, pr.TenantID, auditDoc{Action: "approval." + string(in.Decision), ActorKind: "member", ActorLbl: pr.Subject, Outcome: "succeeded", Target: r.Operation, Device: pr.DeviceID})
	})
	return out, err
}

func bindingDTO(b *binding) gen.Binding {
	g := gen.Binding{Id: b.ID, DeviceId: b.Device, CreatedAt: b.CreatedAt, State: gen.BindingState(b.State)}
	if !b.Caution.IsZero() {
		c := b.Caution
		g.CautionUntil = &c
	}
	return g
}

// ListBindings lists the bindings of the signed-in account with their caution state.
func (s *Service) ListBindings(ctx context.Context, p gen.ListBindingsParams) (gen.BindingPage, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.BindingPage{}, errUnauth()
	}
	out := gen.BindingPage{Items: []gen.Binding{}}
	err := s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		sess, err := get[session](tx, kSession, repository.Global, pr.SessionID)
		if err != nil || sess == nil {
			return err
		}
		bs, err := find[binding](tx, kBinding, repository.Global, sess.AccountID)
		if err != nil {
			return err
		}
		for i := range bs {
			out.Items = append(out.Items, bindingDTO(&bs[i]))
		}
		return nil
	})
	return out, err
}

// RejectBinding revokes a new binding and its sessions at once ("not me"). Allowed only from a
// binding that is not under caution.
func (s *Service) RejectBinding(ctx context.Context, id string) (gen.Binding, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.Binding{}, errUnauth()
	}
	var out gen.Binding
	err := s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		sess, cur, err := s.callerSession(tx, pr)
		if err != nil || sess == nil {
			return notFoundOr(err)
		}
		b, err := get[binding](tx, kBinding, repository.Global, id)
		if err != nil || b == nil || b.AccountID != sess.AccountID {
			return notFoundOr(err)
		}
		if s.underCaution(cur) || b.ID == cur.ID {
			return apperr.New(apperr.Forbidden, "auth.permission_denied", "permission denied")
		}
		b.State = "rejected"
		if err := put(tx, kBinding, repository.Global, b.ID, b, keys{k1: b.AccountID, k2: b.Device}); err != nil {
			return err
		}
		ss, err := find[session](tx, kSession, repository.Global, pr.Subject)
		if err != nil {
			return err
		}
		all, err := findK2[session](tx, kSession, repository.Global, sess.AccountID)
		if err != nil {
			return err
		}
		_ = ss
		for i := range all {
			if all[i].Binding != b.ID || all[i].Revoked {
				continue
			}
			all[i].Revoked = true
			if err := put(tx, kSession, repository.Global, all[i].ID, all[i], keys{k1: all[i].MemberID, k2: all[i].AccountID}); err != nil {
				return err
			}
			if err := s.addRevocation(tx, all[i].TenantID, "session", all[i].ID); err != nil {
				return err
			}
			if err := s.emitSessionRevoked(tx, &all[i], "binding_rejected"); err != nil {
				return err
			}
		}
		out = bindingDTO(b)
		return s.audit(tx, pr.TenantID, auditDoc{Action: "binding.rejected", ActorKind: "member", ActorLbl: pr.Subject, Outcome: "succeeded", Target: b.Device, Device: pr.DeviceID})
	})
	return out, err
}

// ListAuditEntries returns the tenant's audit log newest first, vendor and support access included.
func (s *Service) ListAuditEntries(ctx context.Context, p gen.ListAuditEntriesParams) (gen.TenantAuditPage, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.TenantAuditPage{}, errUnauth()
	}
	limit := pageLimit(p.Limit, 50, 200)
	out := gen.TenantAuditPage{Items: []gen.TenantAuditEntry{}}
	err := s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		before := deref(p.Cursor)
		for {
			rs, err := tx.ListAudit(pr.TenantID, before, 200)
			if err != nil {
				return err
			}
			for _, r := range rs {
				before = r.ID
				var d auditDoc
				if err := json.Unmarshal(r.Doc, &d); err != nil {
					return err
				}
				if (p.From != nil && d.At.Before(*p.From)) || (p.To != nil && d.At.After(*p.To)) || (p.Action != nil && d.Action != *p.Action) ||
					(p.ActorKind != nil && d.ActorKind != string(*p.ActorKind)) {
					continue
				}
				if len(out.Items) == limit {
					c := out.Items[len(out.Items)-1].Id
					out.NextCursor = &c
					return nil
				}
				out.Items = append(out.Items, auditDTO(d))
			}
			if len(rs) < 200 {
				return nil
			}
		}
	})
	return out, err
}

func auditDTO(d auditDoc) gen.TenantAuditEntry {
	g := gen.TenantAuditEntry{Id: d.ID, Action: d.Action, ActorKind: gen.TenantAuditEntryActorKind(d.ActorKind), ActorLabel: d.ActorLbl, OccurredAt: d.At,
		Outcome: gen.TenantAuditEntryOutcome(d.Outcome), ShowToOwner: d.Show}
	opt := func(v string) *string {
		if v == "" {
			return nil
		}
		return &v
	}
	g.ReadSummary, g.TargetId, g.SupportSessionId = opt(d.Summary), opt(d.Target), opt(d.Session)
	g.Reason, g.TicketReference = opt(d.Reason), opt(d.Ticket)
	return g
}
