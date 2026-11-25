package service

import (
	"context"
	"errors"

	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/repository"
)

// Tenancy is what identity needs from the tenancy service (ADR-0003 section 1a, D3): the document-series
// registry is tenancy's; identity asks it for codes when a billing device registers and carries them in
// the signed offline pack. The implementation is a generated client over the internal routes of the
// tenancy contract (internal/tenancyclient); tests run it against svc-tenancy's double.
type Tenancy interface {
	// IssueSeries issues (or, on a repeat for the same device and outlet, returns) the series codes of a
	// device under the outlet's registration. It returns ErrOutletUnknown for an outlet that does not
	// exist in the tenant, ErrRegistrationUnverified when the outlet's tax registration is not verified,
	// and an apperr (rate limited or unavailable) otherwise.
	IssueSeries(ctx context.Context, tenant, outlet, device string, docTypes []string, state string) ([]SeriesCode, error)
	// ManualBooks lists the active paper bill books of an outlet (listOutletManualBookSeries), entry-only.
	ManualBooks(ctx context.Context, tenant, outlet string) ([]ManualBook, error)
}

// ManualBook is a registered paper bill book of an outlet.
type ManualBook struct{ Code, RegistrationID string }

// manualBooks are the books carried in a billing device's pack. A failed lookup leaves them out of this pack
// (the next fetch carries them); it never fails the pack.
func (s *Service) manualBooks(ctx context.Context, d *device) []gen.PackManualBook {
	if s.Tenancy == nil || billingFor(d.Kind) == "none" {
		return nil
	}
	bs, err := s.Tenancy.ManualBooks(ctx, d.TenantID, d.OutletID)
	if err != nil {
		return nil
	}
	out := make([]gen.PackManualBook, 0, len(bs))
	for _, b := range bs {
		out = append(out, gen.PackManualBook{Code: b.Code, TaxRegistrationId: b.RegistrationID})
	}
	return out
}

// SeriesCode is one issued series of a device.
type SeriesCode struct {
	ID             string // tenancy's series id
	Code           string
	DocType        string
	RegistrationID string
	State          string // active or dormant
}

// Errors of the Tenancy port.
var (
	ErrOutletUnknown          = errors.New("service: outlet unknown to tenancy")
	ErrRegistrationUnverified = errors.New("service: the outlet's tax registration is not verified")
)

// DefaultSeriesDocTypes are the document types a billing device is issued a series for.
// A billing device gets an invoice series and a credit_note series as a pair (tenancy 422 series.credit_note_required otherwise).
var DefaultSeriesDocTypes = []string{"tax_invoice", "credit_note"}

func (s *Service) seriesDocTypes() []string {
	if len(s.Cfg.SeriesDocTypes) > 0 {
		return s.Cfg.SeriesDocTypes
	}
	return DefaultSeriesDocTypes
}

// issueSeriesFor asks tenancy for the series of a billing device (pos: active, waiter: dormant). It
// runs outside any database transaction. For a kind with no billing it does nothing. With no tenancy
// client configured (dev only; the main package refuses that elsewhere) it issues nothing.
//
// A tax registration that is not verified is not an error for the device: it registers without billing
// (billing_capability none) and is issued its series on the pack fetch after the registration is verified.
// An outlet tenancy does not know is refused.
func (s *Service) issueSeriesFor(ctx context.Context, tenant, outlet, deviceID, kind string) (series []devSeries, unverified bool, err error) {
	if s.Tenancy == nil || billingFor(kind) == "none" {
		return nil, false, nil
	}
	state := billingFor(kind)
	codes, err := s.Tenancy.IssueSeries(ctx, tenant, outlet, deviceID, s.seriesDocTypes(), state)
	switch {
	case errors.Is(err, ErrRegistrationUnverified):
		return nil, true, nil
	case errors.Is(err, ErrOutletUnknown):
		return nil, false, errInvalid("outlet_id", "not_found")
	case err != nil:
		return nil, false, err
	}
	for _, c := range codes {
		series = append(series, devSeries{SeriesID: c.ID, Code: c.Code, DocType: c.DocType, RegistrationID: c.RegistrationID, State: c.State})
	}
	return series, false, nil
}

// devSeries is a series code of a device as stored with it, so a pack is built without a network call.
type devSeries struct {
	SeriesID       string `json:"series_id,omitempty"` // tenancy's id, for the drain statement's series set (ADR-0005 A3.3)
	Code           string `json:"code"`
	DocType        string `json:"doc_type"`
	RegistrationID string `json:"tax_registration_id"`
	State          string `json:"state"`
}

func packSeries(d *device) []gen.PackSeries {
	out := []gen.PackSeries{}
	for _, c := range d.Series {
		out = append(out, gen.PackSeries{Code: c.Code, DocType: gen.PackSeriesDocType(c.DocType), State: gen.PackSeriesState(c.State), TaxRegistrationId: c.RegistrationID})
	}
	return out
}

func seriesCodes(d *device) []string {
	out := make([]string, 0, len(d.Series))
	for _, c := range d.Series {
		out = append(out, c.Code)
	}
	return out
}

// retryUnverifiedSeries gives a device that registered while its outlet's registration was unverified
// its series once tenancy can issue them. Called before a pack is built; a failure leaves the device as
// it was (the pack is then built without series, as before).
func (s *Service) retryUnverifiedSeries(ctx context.Context, tenant, deviceID string) {
	if s.Tenancy == nil {
		return
	}
	var d *device
	if err := s.Store.Tx(ctx, tenant, func(tx repository.Tx) error {
		var err error
		d, err = get[device](tx, kDevice, tenant, deviceID)
		return err
	}); err != nil || d == nil || !d.RegUnverified || d.State != "active" {
		return
	}
	series, unverified, err := s.issueSeriesFor(ctx, tenant, d.OutletID, d.ID, d.Kind)
	if err != nil || unverified {
		return
	}
	_ = s.Store.Tx(ctx, tenant, func(tx repository.Tx) error {
		d, err := get[device](tx, kDevice, tenant, deviceID)
		if err != nil || d == nil || !d.RegUnverified {
			return err
		}
		d.Series, d.RegUnverified, d.Billing = series, false, billingFor(d.Kind)
		return put(tx, kDevice, tenant, deviceID, d, keys{k1: d.OutletID})
	})
}
