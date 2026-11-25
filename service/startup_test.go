package service_test

import (
	"context"
	"strings"
	"testing"

	"github.com/hostryhq/svc-identity/service"
)

type fakeSMS struct{ real bool }

func (f fakeSMS) Send(context.Context, string, string) error { return nil }
func (f fakeSMS) Real() bool                                 { return f.real }

func keyed(env string, sms fakeSMS) *service.Service {
	cfg := service.DefaultConfig()
	cfg.Environment = env
	cfg.MACKey = make([]byte, 32)
	cfg.ProofEncKey = make([]byte, 32)
	cfg.TOTPKey = make([]byte, 32)
	return &service.Service{Cfg: cfg, SMS: sms}
}

// IST-35: the service refuses to start with a non-real SMS sender outside dev, test and ci.
func TestRefusesToStartWithTestSMSSenderOutsideDevTestCI(t *testing.T) {
	for env, wantErr := range map[string]bool{"dev": false, "test": false, "ci": false, "staging": true, "production": true, "": true} {
		err := keyed(env, fakeSMS{real: false}).StartupCheck()
		if (err != nil) != wantErr {
			t.Errorf("environment %q with the test sender: err=%v, want error=%v", env, err, wantErr)
		}
	}
	if err := keyed("production", fakeSMS{real: true}).StartupCheck(); err != nil {
		t.Errorf("a real sender must start in production: %v", err)
	}
}

func TestRefusesToStartWithoutKeys(t *testing.T) {
	s := keyed("dev", fakeSMS{})
	s.Cfg.ProofEncKey = []byte("short")
	if err := s.StartupCheck(); err == nil || !strings.Contains(err.Error(), "keys") && !strings.Contains(err.Error(), "MAC") {
		t.Fatalf("short proof key accepted: %v", err)
	}
}

// IST-16 (catalogue side): the generated catalogue passes go-auth's lints, and every x-permission of
// the contract is a catalogue entry or one of the two route-level modes.
func TestCatalogueLints(t *testing.T) {
	cat, err := service.NewCatalogue()
	if err != nil {
		t.Fatal(err)
	}
	if len(cat.All()) < 30 {
		t.Fatalf("catalogue has %d entries", len(cat.All()))
	}
	for _, p := range cat.All() {
		if p.StrongOnly && !p.OwnerGrant {
			t.Errorf("%s is strong_only but not owner_grant", p.Name)
		}
		if p.SupportActable {
			t.Errorf("%s is support_actable but no permission carries it in Phase 1", p.Name)
		}
	}
}
