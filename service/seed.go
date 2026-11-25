package service

import (
	"context"

	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/svc-identity/repository"
)

// Seeder writes initial state for the test double, integration tests and development seed
// scripts. It is not reachable from any route and checks nothing a route would check.
type Seeder struct{ s *Service }

// Seed returns a Seeder.
func (s *Service) Seed() *Seeder { return &Seeder{s: s} }

// OwnerInvitation creates a pending owner invitation (what the vendor operation does after its
// checks) and returns the invitation id and the id the owner member will have.
func (sd *Seeder) OwnerInvitation(ctx context.Context, tenant, mobile, name string) (inv, member string, err error) {
	s := sd.s
	err = s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		i, err := s.newOwnerInvitation(tx, tenant, mobile, name)
		if err != nil {
			return err
		}
		inv, member = i.ID, i.MemberID
		return nil
	})
	return
}

// Role stores a role.
func (sd *Seeder) Role(ctx context.Context, tenant, id, name string, perms []string) error {
	s := sd.s
	return s.Store.Tx(ctx, tenant, func(tx repository.Tx) error {
		now := s.now()
		return put(tx, kRole, tenant, id, role{ID: id, Name: name, Perms: perms, CreatedAt: now, UpdatedAt: now}, keys{})
	})
}

// SeedMember describes a member to seed.
type SeedMember struct {
	ID, Name, Status, Mobile string
	Assignments              []SeedAssignment
}

// SeedAssignment is a role assignment to seed.
type SeedAssignment struct {
	ID, RoleID string
	Outlets    []string
}

// Member stores a member (without an account).
func (sd *Seeder) Member(ctx context.Context, tenant string, m SeedMember) error {
	s := sd.s
	return s.Store.Tx(ctx, tenant, func(tx repository.Tx) error {
		doc := member{ID: m.ID, TenantID: tenant, DisplayName: m.Name, Status: m.Status, Mobile: m.Mobile, Assignments: []assignment{}, CreatedAt: s.now()}
		if doc.Status == "" {
			doc.Status = "active"
		}
		for _, a := range m.Assignments {
			doc.Assignments = append(doc.Assignments, assignment{ID: a.ID, RoleID: a.RoleID, Outlets: a.Outlets})
		}
		return put(tx, kMember, tenant, doc.ID, doc, keys{})
	})
}

// PinFor sets a member's PIN directly and returns the salt and the proof key the client side would
// derive (for tests that act as the shell).
func (sd *Seeder) PinFor(ctx context.Context, tenant, memberID, pin string) (salt []byte, err error) {
	s := sd.s
	err = s.Store.Tx(ctx, tenant, func(tx repository.Tx) error {
		m, err := get[member](tx, kMember, tenant, memberID)
		if err != nil || m == nil {
			return notFoundOr(err)
		}
		salt = s.Rand.Bytes(16)
		return s.applyPin(tx, m, pin, salt)
	})
	return
}

// Account links a member to an account for a number (so the number can sign in).
func (sd *Seeder) Account(ctx context.Context, tenant, memberID, mobile string) (string, error) {
	s := sd.s
	var id string
	err := s.Store.Tx(ctx, tenant, func(tx repository.Tx) error {
		m, err := get[member](tx, kMember, tenant, memberID)
		if err != nil || m == nil {
			return notFoundOr(err)
		}
		a, err := s.accountByMobile(tx, mobile)
		if err != nil {
			return err
		}
		if a == nil {
			a = &account{ID: string(s.NewID()), Mobile: mobile, CreatedAt: s.now()}
			if err := put(tx, kAccount, repository.Global, a.ID, a, keys{k1: s.mobileKey(mobile), unique: true}); err != nil {
				return err
			}
		}
		id, m.AccountID = a.ID, a.ID
		if err := put(tx, kMember, tenant, m.ID, m, keys{k1: a.ID}); err != nil {
			return err
		}
		return put(tx, kMembership, repository.Global, m.ID, membership{MemberID: m.ID, TenantID: tenant, AccountID: a.ID}, keys{k1: a.ID})
	})
	return id, err
}

var _ = apperr.Internal
