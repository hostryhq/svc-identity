package service

import (
	"context"
	"time"

	"github.com/hostryhq/go-common/events"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/repository"
)

// entitlementRec is the last entitlement snapshot identity read from tenancy for an organisation, kept so a
// pack can still carry one while tenancy cannot answer (ADR-0014 T10). It is a copy: tenancy owns the answer.
type entitlementRec struct {
	Snap gen.EntitlementSnapshot `json:"snap"`
	At   time.Time               `json:"at"`
}

// packEntitlements returns the snapshot a pack for the tenant carries: the live answer of tenancy when it
// can give one (stored for next time), otherwise the last stored one, otherwise none. An absent snapshot
// never blocks a pack: trading is not gated by entitlements (ADR-0014 T10). A live answer older than the
// stored one (a late reply) is not stored and not carried.
func (s *Service) packEntitlements(ctx context.Context, tx repository.Tx, tenant string) (*gen.EntitlementSnapshot, error) {
	rec, err := get[entitlementRec](tx, kEntitlements, tenant, tenant)
	if err != nil {
		return nil, err
	}
	if s.Tenancy == nil {
		return recSnap(rec), nil
	}
	live, err := s.Tenancy.Entitlements(ctx, tenant)
	if err != nil {
		return recSnap(rec), nil
	}
	if rec != nil && live.EntitlementsV < rec.Snap.EntitlementsV {
		return recSnap(rec), nil
	}
	if err := put(tx, kEntitlements, tenant, tenant, entitlementRec{Snap: live, At: s.now()}, keys{}); err != nil {
		return nil, err
	}
	return &live, nil
}

func recSnap(r *entitlementRec) *gen.EntitlementSnapshot {
	if r == nil {
		return nil
	}
	c := r.Snap
	return &c
}

// ConsumeTenancyEntitlementChange applies tenancy.subscription.changed and tenancy.organisation.status_changed:
// it reads the organisation's new snapshot from tenancy and stores it, so the next pack a device fetches
// carries it (and takes a new pack_v). Other event types are ignored. A repeat is harmless: it reads and stores
// the same answer. A tenancy failure is returned so the inbox retries the event.
func (s *Service) ConsumeTenancyEntitlementChange(ctx context.Context, e events.Envelope) error {
	switch e.Type {
	case "tenancy.subscription.changed", "tenancy.organisation.status_changed":
	default:
		return nil
	}
	if s.Tenancy == nil || e.TenantID == "" {
		return nil
	}
	live, err := s.Tenancy.Entitlements(ctx, string(e.TenantID))
	if err != nil {
		return err
	}
	return s.Store.Tx(ctx, string(e.TenantID), func(tx repository.Tx) error {
		rec, err := get[entitlementRec](tx, kEntitlements, string(e.TenantID), string(e.TenantID))
		if err != nil {
			return err
		}
		if rec != nil && live.EntitlementsV < rec.Snap.EntitlementsV {
			return nil
		}
		return put(tx, kEntitlements, string(e.TenantID), string(e.TenantID), entitlementRec{Snap: live, At: s.now()}, keys{})
	})
}

// ConsumeTenancy is the inbox handler for tenancy events: vendor access marks and entitlement changes.
func (s *Service) ConsumeTenancy(ctx context.Context, e events.Envelope) error {
	if err := s.ConsumeVendorAccess(ctx, e); err != nil {
		return err
	}
	return s.ConsumeTenancyEntitlementChange(ctx, e)
}
