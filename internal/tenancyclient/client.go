// Package tenancyclient is identity's client of the tenancy service. It wraps the generated client of
// the internal routes of the tenancy contract (internal/gen/tenancy) and adds what ADR-0013 V2 and the
// go-service standard require of every outbound call: a short-lived service token naming the tenant
// acted for (go-auth ServiceSigner), a timeout, and one bounded retry with jitter on a transport
// failure or a 502, 503 or 504, always with the same Idempotency-Key so a retry never repeats an effect.
package tenancyclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/svc-identity/internal/gen/tenancy"
	"github.com/hostryhq/svc-identity/service"
)

// Audience is the service name tokens are minted for.
const Audience = "tenancy"

// Client implements service.Tenancy over HTTP.
type Client struct {
	c      *tenancy.ClientWithResponses
	signer *auth.ServiceSigner
	// Timeout bounds one attempt (default 5s).
	Timeout time.Duration
}

var _ service.Tenancy = (*Client)(nil)

// New builds a client for the tenancy service at baseURL. hc may be nil (http.DefaultClient); tests
// pass a client whose transport serves a handler in process.
func New(baseURL string, signer *auth.ServiceSigner, hc *http.Client) (*Client, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	c, err := tenancy.NewClientWithResponses(strings.TrimRight(baseURL, "/"), tenancy.WithHTTPClient(hc))
	if err != nil {
		return nil, err
	}
	return &Client{c: c, signer: signer, Timeout: 5 * time.Second}, nil
}

// IssueSeries implements service.Tenancy.
func (c *Client) IssueSeries(ctx context.Context, tenant, outlet, device string, docTypes []string, state string) ([]service.SeriesCode, error) {
	body := tenancy.IssueSeries{OutletId: outlet, DeviceId: device, State: tenancy.IssueSeriesState(state)}
	for _, d := range docTypes {
		body.DocTypes = append(body.DocTypes, tenancy.DocType(d))
	}
	key := idempotencyKey(body)
	var resp *tenancy.IssueDocumentSeriesResponse
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		resp, err = c.once(ctx, tenant, key, body)
		if err == nil && resp.StatusCode() != http.StatusBadGateway && resp.StatusCode() != http.StatusServiceUnavailable && resp.StatusCode() != http.StatusGatewayTimeout {
			break
		}
		if attempt == 0 {
			select {
			case <-time.After(time.Duration(50+rand.IntN(100)) * time.Millisecond):
			case <-ctx.Done():
				return nil, unavailable()
			}
		}
	}
	if err != nil || resp == nil {
		return nil, unavailable()
	}
	switch resp.StatusCode() {
	case http.StatusCreated:
		if resp.JSON201 == nil {
			return nil, unavailable()
		}
		out := make([]service.SeriesCode, 0, len(resp.JSON201.Items))
		for _, s := range resp.JSON201.Items {
			out = append(out, service.SeriesCode{Code: s.Code, DocType: string(s.DocType), RegistrationID: s.TaxRegistrationId, State: string(s.Status)})
		}
		return out, nil
	case http.StatusNotFound:
		return nil, service.ErrOutletUnknown
	case http.StatusConflict:
		if problemCode(resp.Body) == "registration_unverified" {
			return nil, service.ErrRegistrationUnverified
		}
		return nil, unavailable()
	case http.StatusTooManyRequests:
		return nil, apperr.New(apperr.RateLimited, "series_cap_reached", "too many series were issued today; try again later")
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, apperr.New(apperr.Internal, "tenancy.not_authorised", "")
	}
	return nil, unavailable()
}

func (c *Client) once(ctx context.Context, tenant, key string, body tenancy.IssueSeries) (*tenancy.IssueDocumentSeriesResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	tok, err := c.signer.Sign(Audience, tenant)
	if err != nil {
		return nil, err
	}
	return c.c.IssueDocumentSeriesWithResponse(ctx, &tenancy.IssueDocumentSeriesParams{IdempotencyKey: key}, body,
		func(_ context.Context, r *http.Request) error {
			r.Header.Set(auth.ServiceTokenHeader, tok)
			return nil
		})
}

func unavailable() error {
	return apperr.New(apperr.Unavailable, "tenancy.unavailable", "the tenancy service could not be reached; try again")
}

// idempotencyKey is stable for one request body, so a retry (or a repeated registration of the same
// device) is a replay at tenancy, and a different body never reuses a key.
func idempotencyKey(b tenancy.IssueSeries) string {
	j, _ := json.Marshal(b)
	sum := sha256.Sum256(j)
	return "identity-series-" + hex.EncodeToString(sum[:16])
}

func problemCode(body []byte) string {
	var p struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(body, &p)
	return p.Code
}
