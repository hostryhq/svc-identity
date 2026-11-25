package service

import (
	"testing"

	"github.com/hostryhq/svc-identity/internal/gen"
)

func TestIssuerEnvFollowsEnvironment(t *testing.T) {
	for env, want := range map[string]gen.IssuerEnv{"dev": gen.Dev, "test": gen.Test, "ci": gen.Ci, "production": gen.Live, "staging": gen.Live} {
		if got := (&Service{Cfg: Config{Environment: env}}).issuerEnv(); got != want {
			t.Errorf("%s: got %s, want %s", env, got, want)
		}
	}
}
