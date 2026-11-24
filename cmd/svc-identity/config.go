package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/bus"
	"github.com/hostryhq/go-common/clock"
	"github.com/hostryhq/go-common/outbox"
	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/internal/token"
	"github.com/hostryhq/svc-identity/service"
)

// config is read from the environment only and validated at start-up; all problems are reported
// together. Secrets are referenced by file path (FILE variables), never passed by value.
type config struct {
	Environment string // HOSTRY_ENV: dev, test, ci or a named environment
	DSN         string // HOSTRY_IDENTITY_DSN (a secret: reference the secret store in deployment)
	DBRole      string // HOSTRY_IDENTITY_DB_ROLE: SET ROLE in dev when connecting as a superuser
	Listen      string // HOSTRY_IDENTITY_LISTEN
	Migrate     bool   // HOSTRY_IDENTITY_AUTO_MIGRATE=1 (dev only)

	TenantKeyFile, VendorKeyFile, PackKeyFile string // PEM PKCS#8 P-256 private keys
	MACKeyFile, ProofKeyFile, TOTPKeyFile     string // base64 files holding 32 random bytes
	ServiceKeysDir                            string // directory of <service>.pub.pem public keys
	OpSigningPub                              string // PEM public key of the sync gateway's op-signing key

	SMS           string // HOSTRY_IDENTITY_SMS: "test" (dev only) ; "real" is not available (no DLT registration yet)
	AllowTestSMS  bool   // HOSTRY_IDENTITY_ALLOW_TEST_SMS=1: the explicit dev flag
	AllowConsole  bool   // HOSTRY_IDENTITY_ALLOW_CONSOLE_MAIL=1
	SignInCode    bool   // vendor_assist.signin_code.enabled
	Recovery      bool   // vendor_assist.recovery.enabled
	NATSURL       string // HOSTRY_NATS_URL (optional)
	NATSSeedFile  string // HOSTRY_NATS_SEED_FILE
	ephemeralKeys bool
	problems      []string
}

func loadConfig(get func(string) string) (*config, error) {
	c := &config{
		Environment: get("HOSTRY_ENV"), DSN: get("HOSTRY_IDENTITY_DSN"), DBRole: get("HOSTRY_IDENTITY_DB_ROLE"), Listen: orDefault(get("HOSTRY_IDENTITY_LISTEN"), ":8080"),
		Migrate: get("HOSTRY_IDENTITY_AUTO_MIGRATE") == "1", TenantKeyFile: get("HOSTRY_IDENTITY_TENANT_KEY_FILE"), VendorKeyFile: get("HOSTRY_IDENTITY_VENDOR_KEY_FILE"),
		PackKeyFile: get("HOSTRY_IDENTITY_PACK_KEY_FILE"), MACKeyFile: get("HOSTRY_IDENTITY_MAC_KEY_FILE"), ProofKeyFile: get("HOSTRY_IDENTITY_PROOF_KEY_FILE"),
		TOTPKeyFile: get("HOSTRY_IDENTITY_TOTP_KEY_FILE"), ServiceKeysDir: get("HOSTRY_SERVICE_KEYS_DIR"), OpSigningPub: get("HOSTRY_OP_SIGNING_PUB_FILE"),
		SMS: orDefault(get("HOSTRY_IDENTITY_SMS"), "test"), AllowTestSMS: get("HOSTRY_IDENTITY_ALLOW_TEST_SMS") == "1", AllowConsole: get("HOSTRY_IDENTITY_ALLOW_CONSOLE_MAIL") == "1",
		SignInCode: get("HOSTRY_IDENTITY_VENDOR_SIGNIN_CODE") == "1", Recovery: get("HOSTRY_IDENTITY_VENDOR_RECOVERY") == "1",
		NATSURL: get("HOSTRY_NATS_URL"), NATSSeedFile: get("HOSTRY_NATS_SEED_FILE"),
	}
	bad := func(s string) { c.problems = append(c.problems, s) }
	if c.Environment == "" {
		bad("HOSTRY_ENV is required")
	}
	if c.DSN == "" {
		bad("HOSTRY_IDENTITY_DSN is required")
	}
	dev := c.Environment == "dev" || c.Environment == "test" || c.Environment == "ci"
	if !dev {
		for k, v := range map[string]string{"TENANT_KEY_FILE": c.TenantKeyFile, "VENDOR_KEY_FILE": c.VendorKeyFile, "PACK_KEY_FILE": c.PackKeyFile,
			"MAC_KEY_FILE": c.MACKeyFile, "PROOF_KEY_FILE": c.ProofKeyFile, "TOTP_KEY_FILE": c.TOTPKeyFile} {
			if v == "" {
				bad("HOSTRY_IDENTITY_" + k + " is required outside dev, test and ci")
			}
		}
		if c.ServiceKeysDir == "" {
			bad("HOSTRY_SERVICE_KEYS_DIR is required outside dev, test and ci")
		}
	}
	if c.SMS == "real" {
		bad("HOSTRY_IDENTITY_SMS=real is not available: no DLT-registered SMS provider exists yet")
	}
	if c.SMS == "test" && (!dev || !c.AllowTestSMS) {
		bad("the test SMS sender needs HOSTRY_ENV in dev, test or ci and HOSTRY_IDENTITY_ALLOW_TEST_SMS=1")
	}
	if c.Migrate && !dev {
		bad("HOSTRY_IDENTITY_AUTO_MIGRATE is for dev only; run `svc-identity migrate`")
	}
	if len(c.problems) > 0 {
		return nil, errors.New("configuration: " + strings.Join(c.problems, "; "))
	}
	return c, nil
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func readKey32(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(k) != 32 {
		return nil, fmt.Errorf("%s must hold 32 bytes, base64 encoded", path)
	}
	return k, nil
}

func (c *config) serviceConfig() (service.Config, error) {
	sc := service.DefaultConfig()
	sc.Environment, sc.SignInCodeEnabled, sc.RecoveryEnabled = c.Environment, c.SignInCode, c.Recovery
	load := func(path string, dst *[]byte) error {
		if path == "" { // dev, test and ci only (checked in loadConfig): ephemeral keys
			*dst = crypto.System.Bytes(32)
			c.ephemeralKeys = true
			return nil
		}
		k, err := readKey32(path)
		*dst = k
		return err
	}
	for _, x := range []struct {
		p string
		d *[]byte
	}{{c.MACKeyFile, &sc.MACKey}, {c.ProofKeyFile, &sc.ProofEncKey}, {c.TOTPKeyFile, &sc.TOTPKey}} {
		if err := load(x.p, x.d); err != nil {
			return sc, err
		}
	}
	if c.OpSigningPub != "" {
		pub, err := readPublic(c.OpSigningPub)
		if err != nil {
			return sc, err
		}
		sc.OpSigning = crypto.ToJWK(pub)
	} else if c.Environment == "dev" || c.Environment == "test" || c.Environment == "ci" {
		sc.OpSigning = crypto.ToJWK(&mustEphemeral().PublicKey)
	} else {
		return sc, errors.New("HOSTRY_OP_SIGNING_PUB_FILE is required outside dev, test and ci")
	}
	return sc, nil
}

func (c *config) signer() (*token.Signer, error) {
	if c.TenantKeyFile == "" {
		return token.NewEphemeral(crypto.System)
	}
	t, err := token.LoadKey("k-"+c.Environment+"-tenant", c.TenantKeyFile)
	if err != nil {
		return nil, err
	}
	v, err := token.LoadKey("v-"+c.Environment+"-vendor", c.VendorKeyFile)
	if err != nil {
		return nil, err
	}
	p, err := token.LoadKey("p-"+c.Environment+"-pack", c.PackKeyFile)
	if err != nil {
		return nil, err
	}
	return &token.Signer{TenantKey: t, VendorKey: v, Packer: p, Random: crypto.System}, nil
}

func readPublic(path string) (*ecdsa.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an EC public key", path)
	}
	return ec, nil
}

// serviceRegistry loads the service key registry deployed with the stack (ADR-0005 section 9): one
// <service>.pub.pem per service; the key id is the service name.
func (c *config) serviceRegistry() (*auth.ServiceVerifier, error) {
	keys := map[string]*ecdsa.PublicKey{}
	if c.ServiceKeysDir != "" {
		files, err := filepath.Glob(filepath.Join(c.ServiceKeysDir, "*.pub.pem"))
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			k, err := readPublic(f)
			if err != nil {
				return nil, err
			}
			keys[strings.TrimSuffix(filepath.Base(f), ".pub.pem")] = k
		}
	}
	return &auth.ServiceVerifier{Registry: auth.NewStaticKeySet(auth.KeyDoc{Keys: keys}), Self: "identity", Clock: clock.System}, nil
}

func (c *config) smsSender(log *slog.Logger) (service.SMSSender, error) {
	// Only the test sender exists (DLT registration is not available, AM12). loadConfig already
	// refused it outside dev, test and ci or without the explicit flag; StartupCheck refuses again.
	log.Warn("SMS: the test sender is active; no message leaves this process")
	return testSMS{}, nil
}

// testSMS records nothing and sends nothing; the OTP is never logged either, so a dev run uses the
// double or reads codes through its own test sender. It exists so the service can start in dev.
type testSMS struct{}

func (testSMS) Send(context.Context, string, string) error { return nil }
func (testSMS) Real() bool                                 { return false }

func (c *config) busSink() (outbox.Sink, func(), error) {
	nc, err := bus.Connect(c.NATSURL, "identity", c.NATSSeedFile)
	if err != nil {
		return nil, nil, err
	}
	pub, err := bus.NewPublisher(nc)
	if err != nil {
		nc.Close()
		return nil, nil, err
	}
	return pub, nc.Close, nil
}

func mustEphemeral() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}
