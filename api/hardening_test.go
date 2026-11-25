package api_test

import (
	"testing"
	"time"

	"github.com/hostryhq/svc-identity/double"
	"github.com/hostryhq/svc-identity/internal/gen"
)

// SR-H2 / CR-H1: a known device id presented with a new key is a new binding under caution (A2.2),
// never the old binding with its expired caution.
func TestKnownDeviceIdWithNewKeyIsNewBindingUnderCaution(t *testing.T) {
	e := newEnv(t)
	first, dev := e.ownerSession()
	if first.CautionUntil != nil {
		t.Fatal("the first binding is not under caution")
	}
	e.d.Clock.Advance(48 * time.Hour)
	attacker := double.NewDevice(dev.ID) // the victim's device id, the attacker's own key
	s := e.signIn(ownerMobile, attacker)
	if s.CautionUntil == nil {
		t.Fatal("same device id with a different key must be under caution")
	}
	e.expect(403, "approval_required", "POST", "/v1/members", s.Tokens.AccessToken, gen.CreateMember{Id: newID(), DisplayName: "Eve"})
	e.d.Clock.Advance(2 * time.Minute)
	// The genuine device is unaffected.
	again := e.signIn(ownerMobile, dev)
	if again.CautionUntil != nil {
		t.Fatal("the genuine binding stays out of caution")
	}
}
