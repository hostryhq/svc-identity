package service

import (
	"context"
	"errors"
	"net/mail"
	"strings"

	"github.com/hostryhq/svc-identity/repository"
)

// ErrPlatformAdminExists is returned by VendorBootstrap when an active platform_admin exists.
var ErrPlatformAdminExists = errors.New("service: an active platform_admin already exists")

// VendorBootstrap creates the first platform_admin in the setup-pending state and returns the
// one-time setup token (the caller prints the link to the terminal only, never to a log). It is
// the implementation of `svc-identity vendor bootstrap`: there is no HTTP route, no default
// account and no credential in a migration (ADR-0005 A2.3). It refuses when an active
// platform_admin exists. operator is the operating-system user and host, recorded in the
// hash-chained vendor audit log.
func (s *Service) VendorBootstrap(ctx context.Context, email, operator string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if _, err := mail.ParseAddress(email); err != nil {
		return "", errors.New("service: invalid email address")
	}
	var token string
	err := s.Store.Tx(ctx, repository.Platform, func(tx repository.Tx) error {
		n, err := s.activePlatformAdmins(tx)
		if err != nil {
			return err
		}
		if n > 0 {
			return ErrPlatformAdminExists
		}
		u, err := s.userByEmail(tx, email)
		if err != nil {
			return err
		}
		now := s.now()
		if u == nil {
			u = &vendorUser{ID: string(s.NewID()), Email: email, Name: "Platform admin", CreatedAt: now}
		}
		u.Role, u.Status, u.Enrolled, u.TOTPEnc, u.Hash, u.CredAt = "platform_admin", "setup_pending", false, nil, "", now
		if err := s.putVendorUser(tx, u); err != nil {
			return err
		}
		if token, err = s.newSetupLink(tx, u.ID); err != nil {
			return err
		}
		return s.vendorAudit(ctx, tx, vaudit{Actor: "cli:" + operator, Action: "vendor.bootstrap", Target: u.ID})
	})
	return token, err
}

// VendorRecover returns an existing platform_admin to setup-pending, ends its sessions and returns
// a setup token. It cannot create users or change roles (`svc-identity vendor recover`). A
// recovered account is subject to the 7-day approval rule because CredAt restarts.
func (s *Service) VendorRecover(ctx context.Context, email, operator string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	var token string
	err := s.Store.Tx(ctx, repository.Platform, func(tx repository.Tx) error {
		u, err := s.userByEmail(tx, email)
		if err != nil {
			return err
		}
		if u == nil || u.Role != "platform_admin" {
			return errors.New("service: no platform_admin with that email")
		}
		u.Status, u.Enrolled, u.TOTPEnc, u.Hash, u.CredAt = "setup_pending", false, nil, "", s.now()
		if err := s.putVendorUser(tx, u); err != nil {
			return err
		}
		if err := s.endVendorUserSessions(tx, u.ID); err != nil {
			return err
		}
		if token, err = s.newSetupLink(tx, u.ID); err != nil {
			return err
		}
		return s.vendorAudit(ctx, tx, vaudit{Actor: "cli:" + operator, Action: "vendor.recover", Target: u.ID})
	})
	return token, err
}
