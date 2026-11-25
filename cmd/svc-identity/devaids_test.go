package main

import (
	"strings"
	"testing"
)

// E1 to E3: the capture and the clock are dev-only, with the guard of the test SMS sender. Outside dev,
// test and ci, or without HOSTRY_IDENTITY_ALLOW_TEST_SMS=1, the configuration does not load.
func TestDevAidsAreRefusedOutsideDevelopment(t *testing.T) {
	for _, flag := range []string{"HOSTRY_IDENTITY_DEV_CAPTURE", "HOSTRY_IDENTITY_DEV_CLOCK"} {
		for name, m := range map[string]map[string]string{
			"production":           {"HOSTRY_ENV": "production", "HOSTRY_IDENTITY_ALLOW_TEST_SMS": "1"},
			"staging":              {"HOSTRY_ENV": "staging", "HOSTRY_IDENTITY_ALLOW_TEST_SMS": "1"},
			"dev without allow":    {"HOSTRY_ENV": "dev"},
			"dev with real sms":    {"HOSTRY_ENV": "dev", "HOSTRY_IDENTITY_ALLOW_TEST_SMS": "1", "HOSTRY_IDENTITY_SMS": "real"},
			"ci without allow":     {"HOSTRY_ENV": "ci"},
			"empty environment":    {"HOSTRY_IDENTITY_ALLOW_TEST_SMS": "1"},
			"test but not enabled": {"HOSTRY_ENV": "test", "HOSTRY_IDENTITY_ALLOW_TEST_SMS": "0"},
		} {
			m["HOSTRY_IDENTITY_DSN"], m[flag] = "postgres://x", "1"
			if _, err := loadConfig(env(m)); err == nil || !strings.Contains(err.Error(), "DEV_CAPTURE") {
				t.Errorf("%s with %s set must be refused for the dev aid: %v", name, flag, err)
			}
		}
		ok := map[string]string{"HOSTRY_ENV": "ci", "HOSTRY_IDENTITY_DSN": "postgres://x", "HOSTRY_IDENTITY_ALLOW_TEST_SMS": "1", flag: "1"}
		c, err := loadConfig(env(ok))
		if err != nil {
			t.Fatalf("%s in ci with the allow flag must load: %v", flag, err)
		}
		a := c.devAids()
		if (flag == "HOSTRY_IDENTITY_DEV_CAPTURE") != (a.capture != nil) || (flag == "HOSTRY_IDENTITY_DEV_CLOCK") != (a.clock != nil) {
			t.Errorf("%s switched on the wrong aid: %+v", flag, a)
		}
	}
	// Off by default: no flag, no aid, and the handler is the service's own.
	c, err := loadConfig(env(map[string]string{"HOSTRY_ENV": "dev", "HOSTRY_IDENTITY_DSN": "postgres://x", "HOSTRY_IDENTITY_ALLOW_TEST_SMS": "1"}))
	if err != nil {
		t.Fatal(err)
	}
	if a := c.devAids(); a.capture != nil || a.clock != nil {
		t.Fatalf("aids on by default: %+v", a)
	}
}
