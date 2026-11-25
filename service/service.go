// Package service holds the identity business rules: no HTTP, no SQL. It depends on the
// repository interfaces and on small ports (clock, ids, randomness, SMS, token signing) that the
// real service, the test double and unit tests wire differently.
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/grantlimit"
	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/go-common/clock"
	"github.com/hostryhq/go-common/events"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/repository"
)

// Document kinds. Global kinds are registered with the repository (ADR-0003 A1.6).
const (
	kAccount    = "account"       // global: person, keyed by mobile
	kMembership = "membership"    // global index: account -> (tenant, member)
	kChallenge  = "otp_challenge" // global
	kLimit      = "limit"         // global: counters for OTP sends, failures, PIN-proof failures
	kInvitation = "invitation"    // global: pending owner invitations, found by number
	kSession    = "session"       // global: sid -> tenant, member, device
	kRefresh    = "refresh"       // global: refresh token hash
	kDeviceIdx  = "device_index"  // global: device id -> tenant (+ key thumbprint)
	kNonce      = "nonce"         // global: registration nonces
	kActivation = "activation"    // global: activation codes, found by code
	kJTI        = "jti"           // global: single-use assertion ids
	kBinding    = "binding"       // global: account-device bindings
	kApprReq    = "approval_request"
	kRevocation = "revocation" // global: ordered feed for the sync gateway
	kVendorUser = "vendor_user"
	kVendorSess = "vendor_session"
	kVendorSet  = "vendor_setup"
	kVendorAppr = "vendor_approval"
	kSupport    = "support_session"
	kRecovery   = "owner_recovery"
	kOwnerCount = "owner_count" // global: owners per organisation, for the last-owner rule

	kMember       = "member"          // tenant
	kRole         = "role"            // tenant
	kDevice       = "device"          // tenant
	kPackHist     = "pack_hist"       // tenant: pack versions issued per device
	kPinSess      = "pin_sess"        // tenant: pin sessions (sid ownership)
	kPinReset     = "pin_reset"       // tenant: PIN reset authorisations
	kSeqCtr       = "seq"             // tenant: per-aggregate event sequence
	kPackVer      = "pack_ver"        // tenant: latest pack_v per device
	kProofFail    = "proof_fail"      // tenant: pin-grant failure counters
	kPackGrant    = "pack_grants"     // tenant: permission sets of issued packs, once per digest (ADR-0005 A3.2)
	kDevRecov     = "device_recovery" // tenant: key-loss recovery records, K1 = the old device id
	kEntitlements = "entitlements"    // tenant: last entitlement snapshot read from tenancy, id = tenant (ADR-0014 T10)
)

func init() {
	repository.RegisterGlobal(kAccount, kMembership, kChallenge, kLimit, kInvitation, kSession, kRefresh, kDeviceIdx,
		kNonce, kActivation, kJTI, kBinding, kApprReq, kRevocation, kVendorUser, kVendorSess, kVendorSet, kVendorAppr,
		kSupport, kRecovery, kOwnerCount)
}

// SMSSender sends a text message. The only production implementation will be a DLT-registered
// provider (not available yet); the double and test senders refuse to start outside dev/test/ci.
type SMSSender interface {
	Send(ctx context.Context, mobileE164, text string) error
	// Real reports whether this sender talks to a real provider (IC-09).
	Real() bool
}

// Notifier tells people about security-relevant changes (new device, owner removed, recovery).
// Phase 1 delivers through the audit log, events and this interface; email and push senders
// plug in later.
type Notifier interface {
	Notify(ctx context.Context, n Notice)
}

// Notice is one notification. It carries ids and a fixed code, never free text or numbers.
type Notice struct {
	Kind      string // e.g. new_device, owner_removed, recovery_started, device_registered
	TenantID  string
	AccountID string
	MemberID  string
	DeviceID  string
	Detail    string
}

// TokenIssuer signs tokens. Implementations: the ES256 signer (real), a literal-token issuer for
// the contract double (serves the spec's examples) and test fakes.
type TokenIssuer interface {
	Access(c auth.Claims) (string, error)   // tenant realm: user, pin, device, drain, support, approval
	Vendor(c auth.Claims) (string, error)   // vendor realm
	Opaque() string                         // refresh token, 256-bit
	Pack(claims any) (string, error)        // offline pack and wipe order JWS
	Credential(claims any) (string, error)  // LAN credential JWS, typ hostry-cred+jws, signed with the current identity key (ADR-0002 A3.4)
	VendorGrant(claims any) (string, error) // vendor approval grant for another service (typ vendor_approval)
	JWKS(vendor bool) []KeyInfo             // published public keys: current and pre-published next
}

// KeyInfo is a published key with its id.
type KeyInfo struct {
	Kid string
	Key crypto.JWK
}

func itoa(n int) string { return strconv.Itoa(n) }

func sprintf(f string, a ...any) string { return fmt.Sprintf(f, a...) }

// Config is the service configuration. Defaults match ADR-0005 A2 "Defaults".
type Config struct {
	Environment string // dev, test, ci or a real environment name

	AccessTTL       time.Duration // 15 min
	RefreshPersonal time.Duration // 30 days idle
	RefreshAbs      time.Duration // 90 days
	OTPTTL          time.Duration // 5 min
	OTPCooldown     time.Duration // 30 s
	OTPSends15      int           // 3 per 15 min
	OTPSendsDay     int           // 6 per day
	OTPDeviceDay    int           // sends per device per day
	OTPIPDay        int           // sends per client address per day
	OTPDailyBudget  int           // global daily SMS budget; the breaker trips above it
	OTPFailCap      int           // failed verifications per number per 24 h
	OTPAttempts     int           // 5 per challenge
	ActivationTTL   time.Duration // 10 min
	ActivationFails int           // failed redemptions per client address per hour
	ActivationDay   int           // activations per outlet per day
	NonceTTL        time.Duration
	CautionWindow   time.Duration // 24 h
	ApprovalReqTTL  time.Duration // 10 min
	ApprovalTokTTL  time.Duration // 5 min
	PinSessionMax   time.Duration // 16 h
	PinSkew         time.Duration // 60 s
	PinProofKeep    time.Duration // 90 days
	VBits           int           // 12
	OfflineDays     int           // 7
	IdleLockMinutes int
	DrainTTL        time.Duration // 5 min
	WipeDelay       time.Duration // 15 min
	PackKeyNotice   time.Duration

	// Vendor realm.
	VendorAccessTTL      time.Duration // 15 min
	VendorSessionMax     time.Duration // absolute session length
	SupportDefault       time.Duration // 30 min
	SupportMax           time.Duration // 60 min
	SupportToken         time.Duration // 15 min
	InvitationTTL        time.Duration // 14 days
	SetupLinkTTL         time.Duration // 24 h
	MinApproverAge       time.Duration // 7 days
	RecoveryDelay        time.Duration // 24 h
	SignInCodeTTL        time.Duration // 10 min
	SignInApprovalTTL    time.Duration // 30 min
	LongApprovalTTL      time.Duration // 24 h
	RevokeQuotaOrg       int           // 2
	RevokeQuotaUser      int           // 10
	VendorLockFails      int           // 5 failures in 15 min
	SignInCodeEnabled    bool          // vendor_assist.signin_code.enabled
	RecoveryEnabled      bool          // vendor_assist.recovery.enabled
	PinParams            crypto.PinParams
	PasswordParams       crypto.PinParams
	MACKey               []byte // keyed hashes of OTPs, mobiles, refresh tokens
	ProofEncKey          []byte // 32 bytes: encrypts PIN proof keys at rest
	TOTPKey              []byte // 32 bytes: encrypts vendor TOTP secrets at rest
	IssuerName           string
	AllowedCountryPrefix string // "+91"
	// OpSigning is the sync gateway's op-signing public key, carried in every pack (ADR-0002 S17).
	OpSigning crypto.JWK
	// ExampleLiterals makes the service accept the literal placeholder credentials of the API
	// specification examples (assertion.example, proof.example, sig.example, TOTP 123456). It is
	// set by the contract run and tests only; the main package never sets it.
	ExampleLiterals bool
	// ExtraPermissions are permission keys accepted in roles in addition to the generated catalogue.
	// Products add theirs with their own catalogue entries; the test double adds the restaurant ones
	// the specification examples use.
	ExtraPermissions []string
	// SeriesDocTypes are the document types a billing device is issued series for (default tax_invoice).
	SeriesDocTypes []string
}

// DefaultConfig returns the ADR defaults with keys left empty (callers must set them).
func DefaultConfig() Config {
	return Config{
		Environment: "dev",
		AccessTTL:   15 * time.Minute, RefreshPersonal: 30 * 24 * time.Hour, RefreshAbs: 90 * 24 * time.Hour,
		OTPTTL: 5 * time.Minute, OTPCooldown: 30 * time.Second, OTPSends15: 3, OTPSendsDay: 6, OTPDeviceDay: 20, OTPIPDay: 40,
		OTPDailyBudget: 10000, OTPFailCap: 10, OTPAttempts: 5,
		ActivationTTL: 10 * time.Minute, ActivationFails: 10, ActivationDay: 20, NonceTTL: 5 * time.Minute,
		CautionWindow: 24 * time.Hour, ApprovalReqTTL: 10 * time.Minute, ApprovalTokTTL: 5 * time.Minute,
		PinSessionMax: 16 * time.Hour, PinSkew: 60 * time.Second, PinProofKeep: 90 * 24 * time.Hour, VBits: 12,
		OfflineDays: 7, IdleLockMinutes: 5, DrainTTL: 5 * time.Minute, WipeDelay: 15 * time.Minute,
		VendorAccessTTL: 15 * time.Minute, VendorSessionMax: 12 * time.Hour, SupportDefault: 30 * time.Minute,
		SupportMax: 60 * time.Minute, SupportToken: 15 * time.Minute, InvitationTTL: 14 * 24 * time.Hour,
		SetupLinkTTL: 24 * time.Hour, MinApproverAge: 7 * 24 * time.Hour, RecoveryDelay: 24 * time.Hour,
		SignInCodeTTL: 10 * time.Minute, SignInApprovalTTL: 30 * time.Minute, LongApprovalTTL: 24 * time.Hour,
		RevokeQuotaOrg: 2, RevokeQuotaUser: 10, VendorLockFails: 5,
		PinParams: crypto.DefaultPinParams, PasswordParams: crypto.DefaultPinParams,
		IssuerName: "identity", AllowedCountryPrefix: "+91",
	}
}

// Service is the identity service.
type Service struct {
	Cfg    Config
	Store  repository.Store
	Clock  clock.Clock
	NewID  func() ids.ID
	Rand   crypto.Random
	SMS    SMSSender
	Notify Notifier
	Mail   MailSender
	Tokens TokenIssuer
	// Tenancy issues document-series codes for billing devices; nil in development issues none.
	Tenancy Tenancy
	Cat     *auth.Catalogue
	Grants  grantlimit.Evaluator
	// Assertions verifies device-key assertions; production uses the ES256 verifier of this package.
	Assertions AssertionVerifier
	// SMSAsync sends the OTP text after the response is written, so a known number does not answer
	// slower than an unknown one (IC-03, IST-07). The double sends synchronously so tests are deterministic.
	SMSAsync bool
	// Approvable reports whether an operation id may be filed for caution approval (A2.2). The api
	// layer supplies it from the generated route table.
	Approvable func(operationID, method, path string) (subject string, ok bool)
}

// AssertionVerifier verifies a device assertion JWS against the device's public key and returns
// its claims. Tests that must serve the spec's literal examples replace it.
type AssertionVerifier interface {
	Verify(assertion string, key crypto.JWK, now time.Time) (AssertionClaims, error)
}

// StartupCheck refuses a configuration that must not run: a non-real SMS sender outside dev,
// test and ci (IC-09), missing keys, a catalogue that fails its lints.
func (s *Service) StartupCheck() error {
	env := s.Cfg.Environment
	if s.SMS != nil && !s.SMS.Real() && env != "dev" && env != "test" && env != "ci" {
		return fmt.Errorf("service: refusing to start: the test SMS sender is only allowed in dev, test and ci (environment %q)", env)
	}
	if len(s.Cfg.MACKey) < 32 || len(s.Cfg.ProofEncKey) != 32 || len(s.Cfg.TOTPKey) != 32 {
		return fmt.Errorf("service: MAC key must be >= 32 bytes and the proof and TOTP encryption keys exactly 32 bytes")
	}
	return nil
}

func (s *Service) now() time.Time { return s.Clock.Now().UTC() }

// ---- document helpers ----

func get[T any](tx repository.Tx, kind, scope, id string) (*T, error) {
	r, ok, err := tx.Get(kind, scope, id)
	if err != nil || !ok {
		return nil, err
	}
	var v T
	if err := json.Unmarshal(r.Doc, &v); err != nil {
		return nil, fmt.Errorf("service: decode %s: %w", kind, err)
	}
	return &v, nil
}

type keys struct {
	k1, k2 string
	unique bool
}

func put(tx repository.Tx, kind, scope, id string, v any, k keys) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return tx.Put(repository.Record{Kind: kind, Scope: scope, ID: id, K1: k.k1, K2: k.k2, Unique: k.unique, Doc: b})
}

// create is put that refuses an existing id (repository.ErrConflict) instead of overwriting it.
func create(tx repository.Tx, kind, scope, id string, v any, k keys) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return tx.Create(repository.Record{Kind: kind, Scope: scope, ID: id, K1: k.k1, K2: k.k2, Unique: k.unique, Doc: b})
}

func decode[T any](rs []repository.Record) ([]T, error) {
	out := make([]T, 0, len(rs))
	for _, r := range rs {
		var v T
		if err := json.Unmarshal(r.Doc, &v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func find[T any](tx repository.Tx, kind, scope, k1 string) ([]T, error) {
	rs, err := tx.FindK1(kind, scope, k1)
	if err != nil {
		return nil, err
	}
	return decode[T](rs)
}

func findK2[T any](tx repository.Tx, kind, scope, k2 string) ([]T, error) {
	rs, err := tx.FindK2(kind, scope, k2)
	if err != nil {
		return nil, err
	}
	return decode[T](rs)
}

func list[T any](tx repository.Tx, kind, scope, after string, limit int) ([]T, error) {
	rs, err := tx.List(kind, scope, after, limit)
	if err != nil {
		return nil, err
	}
	return decode[T](rs)
}

// ---- errors (codes follow api-specs) ----

func errNotFound() error {
	return apperr.New(apperr.NotFound, "resource.not_found", "resource not found")
}

func errInvalid(field, code string) error {
	return apperr.New(apperr.Validation, "validation.failed", "the request is invalid").WithFields(apperr.FieldError{Field: field, Code: code})
}

func errGrant() error {
	return apperr.New(apperr.Forbidden, "grant_not_permitted", "this change is not permitted by the grant limits")
}

func errUnauth() error {
	return apperr.New(apperr.Unauthenticated, "auth.invalid_token", "invalid or missing credentials")
}

// mapGrant turns a grantlimit refusal (403 grant_not_permitted) into the API error.
func mapGrant(err error) error {
	if err == nil {
		return nil
	}
	return errGrant()
}

// ---- events and audit ----

// emit writes a domain event for the aggregate key to the outbox in the current transaction.
func (s *Service) emit(tx repository.Tx, tenant, outlet, typ, key, actor string, data map[string]any) error {
	seq, err := s.nextSeq(tx, tenant, key)
	if err != nil {
		return err
	}
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return tx.Emit(events.Envelope{
		ID: s.NewID(), Type: typ, V: 1, Source: "identity", TenantID: ids.ID(tenant), OutletID: ids.ID(outlet),
		Key: key, KeySeq: seq, OccurredAt: s.now(), Actor: actor, Data: b,
	})
}

func (s *Service) nextSeq(tx repository.Tx, tenant, key string) (int64, error) {
	type ctr struct {
		N int64 `json:"n"`
	}
	c, err := get[ctr](tx, kSeqCtr, tenant, key)
	if err != nil {
		return 0, err
	}
	if c == nil {
		c = &ctr{}
	}
	c.N++
	return c.N, put(tx, kSeqCtr, tenant, key, c, keys{})
}

// auditDoc is one tenant audit entry (gen.TenantAuditEntry plus internal fields).
type auditDoc struct {
	ID        string    `json:"id"`
	At        time.Time `json:"at"`
	Action    string    `json:"action"`
	ActorKind string    `json:"actor_kind"`
	ActorLbl  string    `json:"actor_label"`
	Outcome   string    `json:"outcome"`
	Target    string    `json:"target,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	Ticket    string    `json:"ticket,omitempty"`
	Session   string    `json:"support_session,omitempty"`
	Summary   string    `json:"read_summary,omitempty"`
	Show      bool      `json:"show_to_owner,omitempty"`
	Device    string    `json:"device,omitempty"`
	Before    string    `json:"before,omitempty"`
	After     string    `json:"after,omitempty"`
}

// audit appends to the tenant's chained audit log. Fixed-vocabulary fields only: no secrets, no
// numbers, no free text beyond the vendor-supplied reason (IC-26, IC-28).
func (s *Service) audit(tx repository.Tx, tenant string, d auditDoc) error {
	d.ID = string(s.NewID())
	d.At = s.now()
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	return tx.AppendAudit(tenant, d.ID, b)
}

// actor describes the verified caller for audit entries.
func actor(ctx context.Context) (kind, label, device string) {
	p, ok := auth.PrincipalFrom(ctx)
	if !ok {
		return "system", "system", ""
	}
	switch {
	case p.Type == auth.TypeSupport:
		return "vendor", "Hostry support", p.DeviceID
	case p.Realm == auth.RealmVendor:
		return "vendor", "Hostry support", ""
	case p.Type == auth.TypeDevice:
		return "device", p.Subject, p.DeviceID
	default:
		return "member", p.Subject, p.DeviceID
	}
}

// maskMobile shows the country code and the last three digits only, as MobileMasked requires.
func maskMobile(m string) string {
	if len(m) != 13 {
		return "+91*******000"
	}
	return "+91" + strings.Repeat("*", 7) + m[10:]
}

func (s *Service) mobileKey(m string) string { return crypto.MAC(s.Cfg.MACKey, "mobile", m) }
