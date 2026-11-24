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
