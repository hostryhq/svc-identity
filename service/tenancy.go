package service

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/hostryhq/go-common/apperr"

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
	// OutletBrand reads the brand of an outlet (getStreamOwner; ADR-0014 A3.4 item 1). It returns
	// ErrOutletUnknown for an outlet that does not exist in the tenant and an Unavailable apperr
	// (code tenancy.unavailable) when tenancy cannot answer.
	OutletBrand(ctx context.Context, tenant, outlet string) (string, error)
	// Entitlements reads the organisation's entitlement snapshot (getEntitlements; ADR-0014 T10). An Unavailable apperr
	// (code tenancy.unavailable) when tenancy cannot answer.
	Entitlements(ctx context.Context, tenant string) (gen.EntitlementSnapshot, error)
}

// ManualBook is a registered paper bill book of an outlet.
type ManualBook struct{ Code, RegistrationID string }

// manualBooks are the books carried in a billing device's pack. A failed lookup keeps the last good answer
// (lastGood, stored with the pack version) so an outage neither drops the books nor changes the pack digest;
// it never fails the pack. The result is never nil, so "none" digests the same however it arose.
func (s *Service) manualBooks(ctx context.Context, d *device, lastGood []gen.PackManualBook) []gen.PackManualBook {
	if s.Tenancy == nil || billingFor(d.Kind) == "none" {
		return []gen.PackManualBook{}
	}
	bs, err := s.Tenancy.ManualBooks(ctx, d.TenantID, d.OutletID)
	if err != nil {
		if lastGood == nil {
			return []gen.PackManualBook{}
		}
		return lastGood
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

// brandFor reads the outlet's brand from tenancy for a device being registered (ADR-0014 A3.4 item 1). It
// is the same step as the series call and fails the registration when tenancy cannot answer: no credential
// is issued without a brand. With no tenancy client (dev only) the brand stays empty and the credential
// route answers 503 until it is filled.
func (s *Service) brandFor(ctx context.Context, tenant, outlet string) (string, error) {
	if s.Tenancy == nil {
		return "", nil
	}
	b, err := s.Tenancy.OutletBrand(ctx, tenant, outlet)
	switch {
	case errors.Is(err, ErrOutletUnknown):
		return "", errInvalid("outlet_id", "not_found")
	case err != nil:
		return "", err
	}
	return b, nil
}

// errBrandUnknown is the answer for a device row that has no brand yet (created before ADR-0014 A3.4): the
// start-up backfill fills it; until then no credential or pack leaves.
func errBrandUnknown() error {
	return apperr.New(apperr.Unavailable, "tenancy.unavailable", "the device's brand is not known yet; try again")
}

// BackfillDeviceBrands fills the brand of device rows created before ADR-0014 A3.4, once per start-up
// (ADR-0014 A3.4 item 2). It asks tenancy for each distinct outlet once, outside any transaction, and
// returns how many rows still have no brand (tenancy unreachable or the outlet gone). It is safe to run
// again and to run concurrently with registrations: a row is written only if it is still empty.
func (s *Service) BackfillDeviceBrands(ctx context.Context) (remaining int, err error) {
	if s.Tenancy == nil {
		return 0, nil
	}
	type ref struct{ tenant, outlet string }
	type entry struct{ tenant, id string }
	var idx []entry
	after := ""
	for {
		var recs []repository.Record
		if err := s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
			var err error
			recs, err = tx.List(kDeviceIdx, repository.Global, after, 200)
			return err
		}); err != nil {
			return 0, err
		}
		for _, r := range recs {
			var t struct {
				TenantID string `json:"tenant_id"`
			}
			if json.Unmarshal(r.Doc, &t) == nil && t.TenantID != "" {
				idx = append(idx, entry{t.TenantID, r.ID})
			}
			after = r.ID
		}
		if len(recs) < 200 {
			break
		}
	}
	brands := map[ref]string{}
	for _, x := range idx {
		var d *device
		if err := s.Store.Tx(ctx, x.tenant, func(tx repository.Tx) error {
			var err error
			d, err = get[device](tx, kDevice, x.tenant, x.id)
			return err
		}); err != nil {
			return remaining, err
		}
		if d == nil || d.BrandID != "" {
			continue
		}
		k := ref{x.tenant, d.OutletID}
		b, ok := brands[k]
		if !ok {
			var err error
			if b, err = s.Tenancy.OutletBrand(ctx, x.tenant, d.OutletID); err != nil {
				remaining++
				continue
			}
			brands[k] = b
		}
		if err := s.Store.Tx(ctx, x.tenant, func(tx repository.Tx) error {
			d, err := get[device](tx, kDevice, x.tenant, x.id)
			if err != nil || d == nil || d.BrandID != "" {
				return err
			}
			d.BrandID = b
			return put(tx, kDevice, x.tenant, x.id, d, keys{k1: d.OutletID})
		}); err != nil {
			return remaining, err
		}
	}
	return remaining, nil
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
