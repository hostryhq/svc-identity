package service

import (
	"context"
	"encoding/json"

	"github.com/hostryhq/go-common/events"
	"github.com/hostryhq/svc-identity/repository"
)

// ConsumeVendorAccess applies tenancy.vendor_access.recorded and billing.vendor_access.recorded (ADR-0005 A3.4):
// the executing service wrote the event in the transaction that executed a vendor approval, and identity sets that
// approval executed on the first success. A refused or failed outcome changes nothing, an entry without an
// approval id (any other vendor action) is not identity's, and a repeat or a late second grant is a no-op, so the
// handler is idempotent. Other event types are ignored.
func (s *Service) ConsumeVendorAccess(ctx context.Context, e events.Envelope) error {
	var d struct {
		ApprovalID string `json:"approval_id"`
		Outcome    string `json:"outcome"` // tenancy: succeeded, refused, failed
		Result     string `json:"result"`  // billing: success, refused
		GrantJTI   string `json:"grant_jti"`
	}
	switch e.Type {
	case "tenancy.vendor_access.recorded", "billing.vendor_access.recorded":
	default:
		return nil
	}
	if err := json.Unmarshal(e.Data, &d); err != nil {
		return err
	}
	if d.ApprovalID == "" || !(d.Outcome == "succeeded" || d.Result == "success") {
		return nil
	}
	return s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		a, err := get[vendorApproval](tx, kVendorAppr, repository.Global, d.ApprovalID)
		if err != nil || a == nil || a.State != "approved" || !grantKind(a.Kind) {
			return err
		}
		a.Used, a.State = true, "completed"
		if d.GrantJTI != "" {
			a.GrantJTI = d.GrantJTI // the grant that executed
		}
		return put(tx, kVendorAppr, repository.Global, a.ID, a, keys{k1: a.Org, k2: a.Requester})
	})
}
