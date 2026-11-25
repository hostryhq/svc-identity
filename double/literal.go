package double

import (
	"strconv"
	"sync/atomic"
	"time"

	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/service"
)

// literalAssertions accepts the spec's literal example assertions and proofs, and verifies any
// other assertion for real. Used only in the contract run (Options.LiteralTokens).
type literalAssertions struct {
	inner service.AssertionVerifier
}

var literalSeq atomic.Int64

func (l literalAssertions) Verify(a string, key crypto.JWK, now time.Time) (service.AssertionClaims, error) {
	if a == "assertion.example" || a == "proof.example" {
		return service.AssertionClaims{Trusted: true, Jti: "literal-" + strconv.FormatInt(literalSeq.Add(1), 10)}, nil
	}
	return l.inner.Verify(a, key, now)
}
