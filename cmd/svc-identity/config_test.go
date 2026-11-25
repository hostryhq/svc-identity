package main

import (
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

// IST-35 (config side): the test SMS sender is refused outside dev, test and ci and without the flag.
func TestConfigRefusesTestSMSWithoutExplicitDevFlagOrOutsideDev(t *testing.T) {
	base := map[string]string{"HOSTRY_ENV": "dev", "HOSTRY_IDENTITY_DSN": "postgres://x"}
	if _, err := loadConfig(env(base)); err == nil || !strings.Contains(err.Error(), "ALLOW_TEST_SMS") {
		t.Fatalf("the test sender must need the explicit flag even in dev: %v", err)
	}
	ok := map[string]string{"HOSTRY_ENV": "dev", "HOSTRY_IDENTITY_DSN": "postgres://x", "HOSTRY_IDENTITY_ALLOW_TEST_SMS": "1"}
	if _, err := loadConfig(env(ok)); err != nil {
		t.Fatalf("dev with the flag must load: %v", err)
	}
	prod := map[string]string{"HOSTRY_ENV": "production", "HOSTRY_IDENTITY_DSN": "postgres://x", "HOSTRY_IDENTITY_ALLOW_TEST_SMS": "1"}
	if _, err := loadConfig(env(prod)); err == nil {
		t.Fatal("the test sender must be refused in production even with the flag")
	}
	real := map[string]string{"HOSTRY_ENV": "dev", "HOSTRY_IDENTITY_DSN": "postgres://x", "HOSTRY_IDENTITY_SMS": "real"}
	if _, err := loadConfig(env(real)); err == nil || !strings.Contains(err.Error(), "DLT") {
		t.Fatalf("the real sender does not exist yet: %v", err)
	}
}

func TestConfigReportsAllProblemsAtOnce(t *testing.T) {
	_, err := loadConfig(env(map[string]string{}))
	if err == nil || !strings.Contains(err.Error(), "HOSTRY_ENV") || !strings.Contains(err.Error(), "HOSTRY_IDENTITY_DSN") {
		t.Fatalf("want all missing settings reported: %v", err)
	}
}

func TestProductionRequiresKeyFilesAndRegistry(t *testing.T) {
	_, err := loadConfig(env(map[string]string{"HOSTRY_ENV": "production", "HOSTRY_IDENTITY_DSN": "x", "HOSTRY_IDENTITY_SMS": "none"}))
	if err == nil || !strings.Contains(err.Error(), "TENANT_KEY_FILE") || !strings.Contains(err.Error(), "SERVICE_KEYS_DIR") {
		t.Fatalf("production must require key files and the service key registry: %v", err)
	}
}
