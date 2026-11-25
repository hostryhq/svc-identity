package double

import (
	"net/http"
	"net/http/httptest"

	tdouble "github.com/hostryhq/svc-tenancy/double"

	"github.com/hostryhq/svc-identity/internal/tenancyclient"
)

// Tenancy is svc-tenancy's own test double, wired in process as identity's tenancy dependency: the
// same generated client and service-token handling the real service uses, over a transport that calls
// the double's handler directly (no port). Put it in a state with its SeedWorld (for example
// "registration-verified": organisation, outlet and a verified tax registration) before a billing
// device registers. It is on only when Options.WithTenancy is set.
type Tenancy = tdouble.Env

// handlerTransport serves requests from an http.Handler in process.
type handlerTransport struct{ h http.Handler }

func (t handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	t.h.ServeHTTP(rec, r)
	return rec.Result(), nil
}

// newTenancy builds the tenancy double and the identity client over it.
func newTenancy() (*Tenancy, *tenancyclient.Client, error) {
	env, err := tdouble.NewEnv()
	if err != nil {
		return nil, nil, err
	}
	signer := env.Registry.Signer("identity")
	cl, err := tenancyclient.New("http://tenancy.double", signer, &http.Client{Transport: handlerTransport{env.Double}})
	return env, cl, err
}
