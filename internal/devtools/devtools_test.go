package devtools_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hostryhq/svc-identity/internal/devtools"
	"github.com/hostryhq/svc-identity/service"
)

func get(t *testing.T, h http.Handler, method, path, body string) (int, map[string]string) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var m map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return rec.Code, m
}

func TestHandlerIsNotBuiltOutsideDevelopment(t *testing.T) {
	for _, c := range []struct {
		env   string
		allow bool
	}{{"production", true}, {"staging", true}, {"", true}, {"dev", false}, {"ci", false}} {
		if h, err := devtools.Handler(c.env, c.allow, &devtools.Capture{}, &devtools.Clock{}); err == nil || h != nil {
			t.Errorf("env %q allow %v: handler built", c.env, c.allow)
		}
	}
}

// E1: the sign-in code is read from the capture, by number; E3: the setup link by address.
func TestCaptureReturnsTheLastCodeAndLinkAndNothingElse(t *testing.T) {
	cap := &devtools.Capture{}
	var _ service.SMSSender = cap
	var _ service.MailSender = cap.Mail()
	h, err := devtools.Handler("dev", true, cap, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := get(t, h, "GET", "/dev/otp/+919876543210", ""); c != 404 {
		t.Fatalf("no text yet: %d", c)
	}
	_ = cap.Send(context.Background(), "+919876543210", "Your Hostry code is 111111. Hostry staff will never ask for this code.")
	_ = cap.Send(context.Background(), "+919876543210", "Your Hostry code is 222222. Hostry staff will never ask for this code.")
	_ = cap.Send(context.Background(), "+919876543211", "Your Hostry code is 333333. Hostry staff will never ask for this code.")
	if c, m := get(t, h, "GET", "/dev/otp/+919876543210", ""); c != 200 || m["code"] != "222222" {
		t.Fatalf("last code for the number: %d %v", c, m)
	}
	_ = cap.Mail().Send(context.Background(), "Root@Hostry.test", "vendor_setup", "link-token-1")
	if c, m := get(t, h, "GET", "/dev/mail/root@hostry.test", ""); c != 200 || m["link"] != "link-token-1" || m["kind"] != "vendor_setup" {
		t.Fatalf("setup link: %d %v", c, m)
	}
	if c, _ := get(t, h, "GET", "/dev/clock", ""); c != 404 {
		t.Fatalf("the clock routes exist only when the clock aid is on: %d", c)
	}
}

// E2: the clock moves by an offset and keeps running; it can be set, advanced and reset.
func TestClockEndpointMovesAndResets(t *testing.T) {
	clk := &devtools.Clock{}
	h, err := devtools.Handler("test", true, nil, clk)
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now()
	if c, _ := get(t, h, "POST", "/dev/clock", `{"advance":"168h"}`); c != 200 {
		t.Fatalf("advance: %d", c)
	}
	if d := clk.Now().Sub(before); d < 168*time.Hour || d > 168*time.Hour+time.Minute {
		t.Fatalf("advanced by %v", d)
	}
	target := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	if c, _ := get(t, h, "POST", "/dev/clock", `{"now":"2030-01-02T03:04:05Z"}`); c != 200 {
		t.Fatalf("set: %d", c)
	}
	if d := clk.Now().Sub(target); d < 0 || d > time.Minute {
		t.Fatalf("set to %v, now %v", target, clk.Now())
	}
	for _, bad := range []string{`{}`, `{"now":"2030-01-02T03:04:05Z","advance":"1h"}`, `{"advance":"soon"}`, `nope`} {
		if c, _ := get(t, h, "POST", "/dev/clock", bad); c != 400 {
			t.Errorf("body %s: %d", bad, c)
		}
	}
	if c, _ := get(t, h, "DELETE", "/dev/clock", ""); c != 200 {
		t.Fatalf("reset: %d", c)
	}
	if d := time.Since(clk.Now()); d < -time.Minute || d > time.Minute {
		t.Fatalf("not back on the wall clock: %v", d)
	}
}
