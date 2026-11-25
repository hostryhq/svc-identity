package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // TOTP (RFC 6238) is defined over HMAC-SHA1
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	"golang.org/x/crypto/argon2"
)

// MAC is HMAC-SHA256(key, parts joined by 0x00), hex encoded. It is used for keyed hashes of OTPs,
// mobile-number lookup keys and refresh-token hashes: a bare hash of a 6-digit code is reversible.
func MAC(key []byte, parts ...string) string {
	m := hmac.New(sha256.New, key)
	for i, p := range parts {
		if i > 0 {
			m.Write([]byte{0})
		}
		m.Write([]byte(p))
	}
	return hex.EncodeToString(m.Sum(nil))
}

// Equal compares two strings in constant time.
func Equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

// Random is the source of secrets. Production uses crypto/rand; tests inject a seeded reader.
type Random struct{ R io.Reader }

// System is the crypto/rand source.
var System = Random{R: rand.Reader}

// Bytes returns n random bytes.
func (r Random) Bytes(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(r.R, b); err != nil {
		panic("crypto: random source failed: " + err.Error())
	}
	return b
}

// Token returns a 256-bit opaque token, base64url.
func (r Random) Token() string { return B64(r.Bytes(32)) }

// Digits returns n decimal digits, uniformly.
func (r Random) Digits(n int) string { return r.Alphabet(n, "0123456789") }

// Alphabet returns n characters uniformly from alphabet.
func (r Random) Alphabet(n int, alphabet string) string {
	out := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := range out {
		v, err := rand.Int(r.R, max)
		if err != nil {
			panic("crypto: random source failed: " + err.Error())
		}
		out[i] = alphabet[v.Int64()]
	}
	return string(out)
}

// CodeAlphabet is the 32-symbol alphabet of activation and vendor codes: Crockford base32 without I, L, O, U
// (the pattern of the activation code in the contract is ^[0-9A-HJKMNP-TV-Z]{8}$).
const CodeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// PinParams are the Argon2id parameters of the PIN derivation (ADR-0005 section 5).
type PinParams struct {
	Time    uint32
	MemoryK uint32 // KiB
}

// DefaultPinParams are 19 MiB and 2 iterations.
var DefaultPinParams = PinParams{Time: 2, MemoryK: 19 * 1024}

// PinSecrets are the two independent values derived from a PIN (ADR-0005 section 5).
type PinSecrets struct {
	Verifier []byte // goes (truncated) into packs
	ProofKey []byte // never leaves identity
}

// DerivePin computes S = Argon2id(pin, salt) and derives the verifier and the proof key with HKDF.
func DerivePin(p PinParams, pin string, salt []byte) (PinSecrets, error) {
	s := argon2.IDKey([]byte(pin), salt, p.Time, p.MemoryK, 1, 32)
	v, err := hkdf.Key(sha256.New, s, nil, "hostry/pin/verifier/v1", 32)
	if err != nil {
		return PinSecrets{}, err
	}
	k, err := hkdf.Key(sha256.New, s, nil, "hostry/pin/proof/v1", 32)
	if err != nil {
		return PinSecrets{}, err
	}
	return PinSecrets{Verifier: v, ProofKey: k}, nil
}

// TruncateBits returns the first bits bits of b as a hex string (rest of the last byte zeroed).
func TruncateBits(b []byte, bits int) string {
	n := (bits + 7) / 8
	out := append([]byte(nil), b[:n]...)
	if r := bits % 8; r != 0 {
		out[n-1] &= byte(0xff << (8 - r))
	}
	return hex.EncodeToString(out)
}

// HashPassword is Argon2id for vendor passwords: "m=..,t=..$salt$hash".
func HashPassword(r Random, p PinParams, pw string) string {
	salt := r.Bytes(16)
	h := argon2.IDKey([]byte(pw), salt, p.Time, p.MemoryK, 1, 32)
	return fmt.Sprintf("%d,%d$%s$%s", p.MemoryK, p.Time, B64(salt), B64(h))
}

// CheckPassword verifies a password against HashPassword output in constant time.
func CheckPassword(pw, stored string) bool {
	var m, t uint32
	parts := splitN(stored, '$')
	if len(parts) != 3 {
		return false
	}
	if _, err := fmt.Sscanf(parts[0], "%d,%d", &m, &t); err != nil {
		return false
	}
	salt, err1 := UnB64(parts[1])
	want, err2 := UnB64(parts[2])
	if err1 != nil || err2 != nil {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, 1, 32)
	return subtle.ConstantTimeCompare(got, want) == 1
}

func splitN(s string, sep byte) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// Seal encrypts plaintext with AES-256-GCM under key (32 bytes); the nonce is prepended.
func Seal(r Random, key, plaintext []byte) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	nonce := r.Bytes(g.NonceSize())
	return g.Seal(nonce, nonce, plaintext, nil), nil
}

// Open decrypts Seal output.
func Open(key, sealed []byte) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < g.NonceSize() {
		return nil, errors.New("crypto: short ciphertext")
	}
	return g.Open(nil, sealed[:g.NonceSize()], sealed[g.NonceSize():], nil)
}

func gcm(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// TOTP computes the RFC 6238 six-digit code for secret at time t (30 s step).
func TOTP(secret []byte, t time.Time) string {
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], uint64(t.Unix()/30))
	m := hmac.New(sha1.New, secret) //nolint:gosec
	m.Write(ctr[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff) % 1_000_000
	return fmt.Sprintf("%06d", code)
}

// TOTPStep is the 30-second step number of t, used to refuse a second use of the same code.
func TOTPStep(t time.Time) int64 { return t.Unix() / 30 }

// CheckTOTP accepts the current step and one step either side. It returns the matched step.
func CheckTOTP(secret []byte, code string, now time.Time) (int64, bool) {
	for d := int64(-1); d <= 1; d++ {
		t := now.Add(time.Duration(d) * 30 * time.Second)
		if Equal(TOTP(secret, t), code) {
			return TOTPStep(t), true
		}
	}
	return 0, false
}
