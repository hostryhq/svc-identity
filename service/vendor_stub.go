package service

import (
	"context"

	"github.com/hostryhq/svc-identity/repository"
)

// TouchAudited runs an empty transaction in the given scope. For a request on a vendor user's
// authority the store records the vendor access row (a replayed request is still an access).
func (s *Service) TouchAudited(ctx context.Context, scope string) error {
	return s.Store.Tx(ctx, scope, func(repository.Tx) error { return nil })
}

// VendorOrgContext puts the organisation a vendor route names into the context, after checking the
// permission (go-auth VendorTenant). The api layer uses it to record a replayed request.
func (s *Service) VendorOrgContext(ctx context.Context, perm, org string) (context.Context, error) {
	return s.vendorOrg(ctx, perm, org)
}
