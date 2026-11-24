package service

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/repository"
)

// OTPTemplate is the only SMS text (IC-05, IST-10): the code, the warning, no link.
const OTPTemplate = "Your Hostry code is %s. Hostry staff will never ask for this code."

var mobileRE = regexp.MustCompile(`^\+91[6-9][0-9]{9}$`)

// RetryAfterError is a 429 that tells the client when to try again (Retry-After header).
type RetryAfterError struct {
	Err   *apperr.Error
	After time.Duration
}

// Error implements error.
func (e *RetryAfterError) Error() string { return e.Err.Error() }

// Unwrap exposes the problem error so it is rendered as a normal problem response.
func (e *RetryAfterError) Unwrap() error { return e.Err }

func tooMany(after time.Duration) error {
	if after < time.Second {
		after = time.Second
	}
	return &RetryAfterError{Err: apperr.New(apperr.RateLimited, "rate_limited", "too many requests; try again later"), After: after}
}

type limitDoc struct {
	Times []time.Time `json:"t,omitempty"`
	Until time.Time   `json:"until,omitempty"`
	N     int         `json:"n,omitempty"`
}

func (s *Service) limitGet(tx repository.Tx, id string) (*limitDoc, error) {
	d, err := get[limitDoc](tx, kLimit, repository.Global, id)
	if err != nil {
		return nil, err
	}
	if d == nil {
		d = &limitDoc{}
	}
	return d, nil
}

func (s *Service) limitPut(tx repository.Tx, id string, d *limitDoc) error {
	return put(tx, kLimit, repository.Global, id, d, keys{})
}

// within returns how many of times are inside window before now, and the oldest of them.
func within(times []time.Time, now time.Time, window time.Duration) (n int, oldest time.Time) {
	for _, t := range times {
		if now.Sub(t) < window {
			if n == 0 || t.Before(oldest) {
				oldest = t
			}
			n++
		}
	}
	return n, oldest
}

func prune(times []time.Time, now time.Time, window time.Duration) []time.Time {
	var out []time.Time
	for _, t := range times {
		if now.Sub(t) < window {
			out = append(out, t)
		}
	}
	return out
}

// CreateOtpChallenge starts an OTP sign-in (ADR-0005 section 3, IC-02..IC-04). The answer is the
// same for known and unknown numbers: counters advance identically and a code is sent only to a
// number with an account or a pending invitation.
func (s *Service) CreateOtpChallenge(ctx context.Context, in gen.CreateOtpChallenge, clientAddr string) (gen.OtpChallenge, error) {
	if !mobileRE.MatchString(in.MobileE164) {
		return gen.OtpChallenge{}, errInvalid("mobile_e164", "not_indian_mobile")
	}
	pub, err := crypto.FromJWK(crypto.JWK{Kty: string(in.DevicePublicKey.Kty), Crv: string(in.DevicePublicKey.Crv), X: in.DevicePublicKey.X, Y: in.DevicePublicKey.Y})
	if err != nil || in.DeviceId == "" {
		return gen.OtpChallenge{}, errInvalid("device_public_key", "invalid")
	}
	_ = pub
	now := s.now()
	mkey := s.mobileKey(in.MobileE164)
	var out gen.OtpChallenge
	var refuse error
	var send func()
	err = s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		type check struct {
			id         string
			cooldown   bool
			per15, day int
		}
		checks := []check{
			{"send:num:" + mkey, true, s.Cfg.OTPSends15, s.Cfg.OTPSendsDay},
			{"send:dev:" + in.DeviceId, false, 0, s.Cfg.OTPDeviceDay},
			{"send:ip:" + clientAddr, false, 0, s.Cfg.OTPIPDay},
			{"send:budget:" + now.Format("2006-01-02"), false, 0, s.Cfg.OTPDailyBudget},
		}
		docs := make([]*limitDoc, len(checks))
		var wait time.Duration
		for i, c := range checks {
			d, err := s.limitGet(tx, c.id)
			if err != nil {
				return err
			}
			d.Times = prune(d.Times, now, 24*time.Hour)
			docs[i] = d
			bump := func(after time.Duration) {
				if after > wait {
					wait = after
				}
			}
			if c.cooldown && len(d.Times) > 0 {
				if last := d.Times[len(d.Times)-1]; now.Sub(last) < s.Cfg.OTPCooldown {
					bump(s.Cfg.OTPCooldown - now.Sub(last))
				}
			}
			if c.per15 > 0 {
				if n, oldest := within(d.Times, now, 15*time.Minute); n >= c.per15 {
					bump(15*time.Minute - now.Sub(oldest))
				}
			}
			if c.day > 0 && len(d.Times) >= c.day {
				bump(24*time.Hour - now.Sub(d.Times[0]))
			}
		}
		if wait > 0 {
			for i, c := range checks {
				if err := s.limitPut(tx, c.id, docs[i]); err != nil { // pruned state only
					return err
				}
			}
			refuse = tooMany(wait)
			return nil
		}
		for i, c := range checks {
			docs[i].Times = append(docs[i].Times, now)
			if err := s.limitPut(tx, c.id, docs[i]); err != nil {
				return err
			}
		}
		acct, err := s.accountByMobile(tx, in.MobileE164)
		if err != nil {
			return err
		}
		invs, err := s.pendingInvitations(tx, mkey, now)
		if err != nil {
			return err
		}
		known := acct != nil || len(invs) > 0
		code := s.Rand.Digits(6)
		id := string(s.NewID())
		ch := challenge{
			ID: id, MobileKey: mkey, Device: in.DeviceId, Key: crypto.JWK{Kty: "EC", Crv: "P-256", X: in.DevicePublicKey.X, Y: in.DevicePublicKey.Y},
			CodeMAC: crypto.MAC(s.Cfg.MACKey, "otp", id, code), ExpiresAt: now.Add(s.Cfg.OTPTTL), Known: known,
		}
		if err := put(tx, kChallenge, repository.Global, id, ch, keys{}); err != nil {
			return err
		}
		out = gen.OtpChallenge{Id: id, ExpiresAt: ch.ExpiresAt, ResendAfter: now.Add(s.Cfg.OTPCooldown)}
		if known && s.SMS != nil {
			sms, mobile, c := s.SMS, in.MobileE164, code
			send = func() { _ = sms.Send(context.WithoutCancel(ctx), mobile, smsText(c)) }
		}
		return nil
	})
	if err != nil {
		return gen.OtpChallenge{}, err
	}
	if refuse != nil {
		return gen.OtpChallenge{}, refuse
	}
	if send != nil {
		send() // after commit: an SMS is never sent for a challenge that was not stored
	}
	return out, nil
}

func smsText(code string) string { return sprintf(OTPTemplate, code) }

type challenge struct {
	ID        string     `json:"id"`
	MobileKey string     `json:"mobile_key"`
	Device    string     `json:"device"`
	Key       crypto.JWK `json:"key"`
	CodeMAC   string     `json:"code_mac"`
	ExpiresAt time.Time  `json:"expires_at"`
	Attempts  int        `json:"attempts"`
	Used      bool       `json:"used"`
	Known     bool       `json:"known"`
}

func (s *Service) accountByMobile(tx repository.Tx, mobile string) (*account, error) {
	as, err := find[account](tx, kAccount, repository.Global, s.mobileKey(mobile))
	if err != nil || len(as) == 0 {
		return nil, err
	}
	return &as[0], nil
}

var errOTP = errors.New("otp refused")

// failOTP records a failed verification against the number across challenges (IC-02, IST-04).
func (s *Service) failOTP(tx repository.Tx, mkey string, now time.Time) error {
	id := "fail:num:" + mkey
	d, err := s.limitGet(tx, id)
	if err != nil {
		return err
	}
	d.Times = append(prune(d.Times, now, 24*time.Hour), now)
	if len(d.Times) >= s.Cfg.OTPFailCap {
		d.Until = now.Add(24 * time.Hour)
	}
	return s.limitPut(tx, id, d)
}

func (s *Service) otpBlocked(tx repository.Tx, mkey string, now time.Time) (bool, error) {
	d, err := s.limitGet(tx, "fail:num:"+mkey)
	if err != nil {
		return false, err
	}
	return now.Before(d.Until), nil
}
