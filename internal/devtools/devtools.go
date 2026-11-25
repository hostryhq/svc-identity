// Package devtools holds the development-only aids that let an end-to-end suite drive the real
// identity binary without reaching into its database or its secrets (e2e-tests#1, E1 to E3):
//
//   - a capture of the texts the test SMS sender and the mail sender would have sent (E1 sign-in
//     codes, E3 vendor setup links);
//   - a clock whose offset can be moved (E2, the 7-day approver rule);
//   - an HTTP handler under /dev/ that exposes both.
//
// Nothing here is part of the API contract. Every entry point is refused outside HOSTRY_ENV dev, test or
// ci with HOSTRY_IDENTITY_ALLOW_TEST_SMS=1 (the guard of the test SMS sender): Guard is checked when the
// configuration loads and again when the handler is built.
package devtools

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Guard is the dev-only condition shared with the test SMS sender: a development environment and the
// explicit allow flag.
func Guard(environment string, allowTestSMS bool) error {
	switch environment {
	case "dev", "test", "ci":
	default:
		return errors.New("development aids are refused outside HOSTRY_ENV dev, test and ci")
	}
	if !allowTestSMS {
		return errors.New("development aids need HOSTRY_IDENTITY_ALLOW_TEST_SMS=1")
	}
	return nil
}

// maxKept bounds each capture list; the oldest entries are dropped.
const maxKept = 1000

type entry struct{ to, kind, text string }

// Capture records what would have been sent. It implements service.SMSSender and service.MailSender.
// Nothing is logged and nothing leaves the process; entries live in memory only.
type Capture struct {
	mu   sync.Mutex
	sms  []entry
	mail []entry
}

// Send implements service.SMSSender: the text is kept for the recipient number.
func (c *Capture) Send(_ context.Context, mobileE164, text string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sms = keep(c.sms, entry{to: mobileE164, text: text})
	return nil
}

// Real implements service.SMSSender: a capture is never a real sender.
func (c *Capture) Real() bool { return false }

// mailSend records a mail (to, kind, link token); it is the body of the adapter that Mail returns.
func (c *Capture) mailSend(to, kind, link string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mail = keep(c.mail, entry{to: strings.ToLower(to), kind: kind, text: link})
}

func keep(l []entry, e entry) []entry {
	if len(l) >= maxKept {
		l = l[1:]
	}
	return append(l, e)
}

// Mail returns the capture as a service.MailSender.
func (c *Capture) Mail() MailSender { return mailAdapter{c} }

// MailSender mirrors service.MailSender (this package must not import service).
type MailSender interface {
	Send(ctx context.Context, to, kind, link string) error
}

type mailAdapter struct{ c *Capture }

func (m mailAdapter) Send(_ context.Context, to, kind, link string) error {
	m.c.mailSend(to, kind, link)
	return nil
}

var codeRE = regexp.MustCompile(`code is ([0-9A-Za-z]+)\.`)

// LastCode returns the sign-in code of the most recent text to a number.
func (c *Capture) LastCode(mobileE164 string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := len(c.sms) - 1; i >= 0; i-- {
		if c.sms[i].to == mobileE164 {
			if m := codeRE.FindStringSubmatch(c.sms[i].text); m != nil {
				return m[1], true
			}
		}
	}
	return "", false
}

// LastMail returns the kind and link token of the most recent mail to an address.
func (c *Capture) LastMail(to string) (kind, link string, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	to = strings.ToLower(to)
	for i := len(c.mail) - 1; i >= 0; i-- {
		if c.mail[i].to == to {
			return c.mail[i].kind, c.mail[i].text, true
		}
	}
	return "", "", false
}

// Clock is the wall clock moved by an offset. It satisfies clock.Clock. It moves forward in real time
// from whatever instant it was set to, so a suite can set "8 days from now" once and let time run.
type Clock struct {
	mu     sync.Mutex
	offset time.Duration
}

// Now implements clock.Clock.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().UTC().Add(c.offset)
}

// Advance moves the clock forward (or back, for a negative d).
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.offset += d
	c.mu.Unlock()
}

// Set makes Now equal t at this moment.
func (c *Clock) Set(t time.Time) {
	c.mu.Lock()
	c.offset = time.Until(t)
	c.mu.Unlock()
}

// Reset returns to the wall clock.
func (c *Clock) Reset() {
	c.mu.Lock()
	c.offset = 0
	c.mu.Unlock()
}

// Handler serves the development routes. Either part may be nil: its routes then answer 404.
//
//	GET    /dev/otp/{mobile}   {"mobile", "code"} the last sign-in code sent to the number
//	GET    /dev/mail/{email}   {"to", "kind", "link"} the last setup link sent to the address
//	GET    /dev/clock          {"now"}
//	POST   /dev/clock          {"now": RFC 3339} or {"advance": "168h"}
//	DELETE /dev/clock          back to the wall clock
//
// It refuses to be built outside the dev guard.
func Handler(environment string, allowTestSMS bool, cap *Capture, clk *Clock) (http.Handler, error) {
	if err := Guard(environment, allowTestSMS); err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	if cap != nil {
		mux.HandleFunc("GET /dev/otp/{mobile}", func(w http.ResponseWriter, r *http.Request) {
			m := r.PathValue("mobile")
			if code, ok := cap.LastCode(m); ok {
				writeJSON(w, http.StatusOK, map[string]string{"mobile": m, "code": code})
				return
			}
			http.NotFound(w, r)
		})
		mux.HandleFunc("GET /dev/mail/{email}", func(w http.ResponseWriter, r *http.Request) {
			to := r.PathValue("email")
			if kind, link, ok := cap.LastMail(to); ok {
				writeJSON(w, http.StatusOK, map[string]string{"to": to, "kind": kind, "link": link})
				return
			}
			http.NotFound(w, r)
		})
	}
	if clk != nil {
		now := func(w http.ResponseWriter) {
			writeJSON(w, http.StatusOK, map[string]string{"now": clk.Now().Format(time.RFC3339Nano)})
		}
		mux.HandleFunc("GET /dev/clock", func(w http.ResponseWriter, _ *http.Request) { now(w) })
		mux.HandleFunc("DELETE /dev/clock", func(w http.ResponseWriter, _ *http.Request) { clk.Reset(); now(w) })
		mux.HandleFunc("POST /dev/clock", func(w http.ResponseWriter, r *http.Request) {
			var in struct {
				Now     *time.Time `json:"now"`
				Advance string     `json:"advance"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&in); err != nil || (in.Now == nil) == (in.Advance == "") {
				http.Error(w, `send exactly one of {"now": RFC 3339} or {"advance": "168h"}`, http.StatusBadRequest)
				return
			}
			if in.Now != nil {
				clk.Set(*in.Now)
			} else {
				d, err := time.ParseDuration(in.Advance)
				if err != nil {
					http.Error(w, "advance is not a duration", http.StatusBadRequest)
					return
				}
				clk.Advance(d)
			}
			now(w)
		})
	}
	return mux, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
