package service

import (
	"context"
	auth "github.com/hostryhq/go-auth"
	"time"

	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/repository"
)

// The seeding methods below build the state the shared contract suite's examples refer to. Like
// the rest of Seeder they are reachable from no route.

// ExampleLiterals reports whether the service accepts the literal placeholder credentials of the
// API specification's examples ("assertion.example", "proof.example", "sig.example", TOTP 123456).
// It is set only by the contract run of the double and the integration tests, never by main.
func (s *Service) exampleLiteral(got, want string) bool { return s.Cfg.ExampleLiterals && got == want }

// SeedDevice describes a device to seed.
type SeedDevice struct {
	ID, Outlet, Kind, Name, KeyProt, State, AccountID string
	Store                                             string // protected (default) or unprotected
	Key                                               crypto.JWK
	LastSeen, DrainedAt                               time.Time
	DrainedThrough                                    map[string]int
}

// Device stores a device and its global index entry.
func (sd *Seeder) Device(ctx context.Context, tenant string, d SeedDevice) error {
	s := sd.s
	return s.Store.Tx(ctx, tenant, func(tx repository.Tx) error {
		if d.State == "" {
			d.State = "active"
		}
		if d.Store == "" {
			d.Store = "protected"
		}
		doc := device{Store: d.Store, ID: d.ID, TenantID: tenant, OutletID: d.Outlet, Kind: d.Kind, Name: d.Name, State: d.State, KeyProt: d.KeyProt, Billing: billingFor(d.Kind),
			Key: d.Key, Thumb: crypto.Thumbprint(d.Key), AccountID: d.AccountID, CreatedAt: s.now(), LastSeen: d.LastSeen, DrainedAt: d.DrainedAt}
		for st, seq := range d.DrainedThrough {
			doc.DrainedThr = append(doc.DrainedThr, stream{Stream: st, Seq: seq})
		}
		if b, err := s.brandFor(ctx, tenant, d.Outlet); err == nil {
			doc.BrandID = b
		} else if d.State == "active" {
			return err
		}
		if d.State == "active" && s.Tenancy != nil {
			series, unverified, err := s.issueSeriesFor(ctx, tenant, d.Outlet, d.ID, d.Kind)
			if err != nil {
				return err
			}
			doc.Series = series
			if unverified {
				doc.RegUnverified, doc.Billing = true, "none"
			}
		}
		k1 := doc.Thumb
		if d.State != "active" {
			k1 = "revoked:" + d.ID
		}
		if err := put(tx, kDeviceIdx, repository.Global, d.ID, struct {
			TenantID string `json:"tenant_id"`
		}{tenant}, keys{k1: k1, unique: true}); err != nil {
			return err
		}
		return put(tx, kDevice, tenant, d.ID, doc, keys{k1: d.Outlet})
	})
}

// BuiltInOwnerRole stores the built-in Owner role with a fixed id.
func (sd *Seeder) BuiltInOwnerRole(ctx context.Context, tenant, id string) error {
	s := sd.s
	return s.Store.Tx(ctx, tenant, func(tx repository.Tx) error {
		now := s.now()
		return put(tx, kRole, tenant, id, role{ID: id, Name: "Owner", BuiltIn: true, Perms: []string{"*"}, CreatedAt: now, UpdatedAt: now}, keys{})
	})
}

// Owner creates the built-in owner role, an owner member and its account.
func (sd *Seeder) Owner(ctx context.Context, tenant, memberID, name, mobile string) (accountID string, err error) {
	s := sd.s
	err = s.Store.Tx(ctx, tenant, func(tx repository.Tx) error {
		_, ownerID, err := s.loadRoles(tx, tenant)
		if err != nil {
			return err
		}
		now := s.now()
		if ownerID == "" {
			ownerID = string(s.NewID())
			if err := put(tx, kRole, tenant, ownerID, role{ID: ownerID, Name: "Owner", BuiltIn: true, Perms: []string{"*"}, CreatedAt: now, UpdatedAt: now}, keys{}); err != nil {
				return err
			}
		}
		m := member{ID: memberID, TenantID: tenant, DisplayName: name, Status: "active", Assignments: []assignment{{ID: string(s.NewID()), RoleID: ownerID}}, CreatedAt: now}
		if err := put(tx, kMember, tenant, m.ID, m, keys{}); err != nil {
			return err
		}
		return s.adjustOwners(tx, tenant, +1)
	})
	if err != nil {
		return "", err
	}
	return sd.Account(ctx, tenant, memberID, mobile)
}

// Session stores a strong session.
func (sd *Seeder) Session(ctx context.Context, tenant, sid, memberID, accountID, deviceID, bindingID string) error {
	s := sd.s
	return s.Store.Tx(ctx, tenant, func(tx repository.Tx) error {
		now := s.now()
		return put(tx, kSession, repository.Global, sid, session{ID: sid, TenantID: tenant, MemberID: memberID, AccountID: accountID, Device: deviceID, Binding: bindingID,
			AMR: "otp", AuthTime: now, CreatedAt: now}, keys{k1: memberID, k2: accountID})
	})
}

// Binding stores an account-device binding; caution is the end of its caution window (zero: none).
func (sd *Seeder) Binding(ctx context.Context, id, accountID, deviceID string, key crypto.JWK, caution time.Time) error {
	s := sd.s
	return s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		return put(tx, kBinding, repository.Global, id, binding{ID: id, AccountID: accountID, Device: deviceID, Key: key, Thumb: crypto.Thumbprint(key), CreatedAt: s.now(), Caution: caution, State: "active"},
			keys{k1: accountID, k2: deviceID})
	})
}

// Refresh stores a refresh token for a session.
func (sd *Seeder) Refresh(ctx context.Context, tenant, sid, tok string) error {
	s := sd.s
	return s.Store.Tx(ctx, tenant, func(tx repository.Tx) error {
		now := s.now()
		rd := refreshDoc{ID: s.refreshKey(tok), Session: sid, Lineage: sid, IdleUntil: now.Add(30 * 24 * time.Hour), AbsUntil: now.Add(90 * 24 * time.Hour)}
		return put(tx, kRefresh, repository.Global, rd.ID, rd, keys{k1: sid})
	})
}

// Challenge stores an OTP challenge whose code is known to the caller.
func (sd *Seeder) Challenge(ctx context.Context, id, mobile, deviceID string, key crypto.JWK, code string) error {
	s := sd.s
	return s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		return put(tx, kChallenge, repository.Global, id, challenge{ID: id, MobileKey: s.mobileKey(mobile), Device: deviceID, Key: key,
			CodeMAC: crypto.MAC(s.Cfg.MACKey, "otp", id, code), ExpiresAt: s.now().Add(5 * time.Minute), Known: true}, keys{})
	})
}

// Nonce stores a registration nonce.
func (sd *Seeder) Nonce(ctx context.Context, nonce string) error {
	s := sd.s
	return s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		return put(tx, kNonce, repository.Global, crypto.MAC(s.Cfg.MACKey, "nonce", nonce), nonceDoc{Expires: s.now().Add(5 * time.Minute)}, keys{})
	})
}

// Activation stores an activation code.
func (sd *Seeder) Activation(ctx context.Context, tenant, id, code, outlet, kind, by string) error {
	s := sd.s
	return s.Store.Tx(ctx, tenant, func(tx repository.Tx) error {
		ac := activationDoc{ID: id, TenantID: tenant, OutletID: outlet, Kind: kind, By: by, Expires: s.now().Add(10 * time.Minute), Created: s.now()}
		ac.Key = crypto.MAC(s.Cfg.MACKey, "activation", code)
		return ac.store(tx, ac.Key)
	})
}

// PackHistory records that a pack version was issued to a device listing members and series.
// perms gives each listed member the permissions the pack granted (members without an entry hold none);
// the pack is valid offline for the configured offline days from now.
func (sd *Seeder) PackHistory(ctx context.Context, tenant, deviceID string, packV int, members, series []string, perms map[string][]string) error {
	s := sd.s
	return s.Store.Tx(ctx, tenant, func(tx repository.Tx) error {
		pm := make([]gen.PackMember, 0, len(members))
		for _, m := range members {
			pm = append(pm, gen.PackMember{MemberId: m, Permissions: perms[m]})
		}
		gd, err := s.storePackGrants(tx, tenant, pm)
		if err != nil {
			return err
		}
		now := s.now()
		h := packHist{ID: deviceID + ":" + itoa(packV), Device: deviceID, PackV: packV, Members: members, Series: series, At: now,
			Until: now.Add(time.Duration(s.Cfg.OfflineDays) * 24 * time.Hour), Grants: gd}
		if err := put(tx, kPackVer, tenant, deviceID, packVer{Latest: packV}, keys{}); err != nil {
			return err
		}
		return put(tx, kPackHist, tenant, h.ID, h, keys{k1: deviceID})
	})
}

// KeyLossRecovery records that device newID adopted the key-lost device oldID under recovery id, approved by
// approver: the old device is revoked with reason key_lost and the recovery stays open until its drain is
// recorded (ADR-0002 A1.3; ADR-0005 A3.2 rows 4 and 5). No identity route creates one yet.
func (sd *Seeder) KeyLossRecovery(ctx context.Context, tenant, id, oldID, newID, approver string) error {
	s := sd.s
	return s.Store.Tx(ctx, tenant, func(tx repository.Tx) error {
		old, err := get[device](tx, kDevice, tenant, oldID)
		if err != nil || old == nil {
			return notFoundOr(err)
		}
		nd, err := get[device](tx, kDevice, tenant, newID)
		if err != nil || nd == nil {
			return notFoundOr(err)
		}
		nd.Recovers = oldID
		if err := put(tx, kDevice, tenant, newID, nd, keys{k1: nd.OutletID}); err != nil {
			return err
		}
		old.State, old.RevokedAt = "revoked", s.now()
		if err := put(tx, kDevice, tenant, oldID, old, keys{k1: old.OutletID}); err != nil {
			return err
		}
		if err := s.addRevocationRow(tx, revocationDoc{TenantID: tenant, Type: "device", Subject: oldID, Reason: "key_lost", Recovery: id}); err != nil {
			return err
		}
		return put(tx, kDevRecov, tenant, id, deviceRecovery{ID: id, TenantID: tenant, OldDeviceID: oldID, NewDeviceID: newID, ApproverID: approver, RecoveredAt: s.now()}, keys{k1: oldID})
	})
}

// PinReset stores a PIN reset authorisation.
func (sd *Seeder) PinReset(ctx context.Context, tenant, id, memberID string) error {
	s := sd.s
	return s.Store.Tx(ctx, tenant, func(tx repository.Tx) error {
		return put(tx, kPinReset, tenant, id, pinReset{ID: id, Member: memberID, Expires: s.now().Add(15 * time.Minute)}, keys{k1: memberID})
	})
}

// ApprovalRequest stores a caution approval request.
func (sd *Seeder) ApprovalRequest(ctx context.Context, tenant, id, memberID, accountID, sid, op string) error {
	s := sd.s
	return s.Store.Tx(ctx, tenant, func(tx repository.Tx) error {
		now := s.now()
		r := approvalReq{ID: id, TenantID: tenant, AccountID: accountID, Member: memberID, Session: sid, Operation: op, BodyHash: "sha256:cf03a846706f29a88ba61a212f79e7c224142fdd5df92fc1d7ed8bb1283fb8c8", Method: "POST", Path: "/v1/members",
			Subject: "Add member Latha (Cashier at Main Restaurant)", State: "pending", CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute)}
		return put(tx, kApprReq, repository.Global, id, r, keys{k1: tenant, k2: accountID})
	})
}

// Revocation stores a revocation feed entry.
func (sd *Seeder) Revocation(ctx context.Context, id, tenant, typ, subject string) error {
	s := sd.s
	return s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		return put(tx, kRevocation, repository.Global, id, revocationDoc{ID: id, TenantID: tenant, Type: typ, Subject: subject, RevokedAt: s.now()}, keys{k1: subject})
	})
}

// VendorUser stores an active vendor user with a known password and TOTP secret.
func (sd *Seeder) VendorUser(ctx context.Context, id, email, name, role, password string, totpSecret []byte, credAge time.Duration) error {
	s := sd.s
	return s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		enc, err := crypto.Seal(s.Rand, s.Cfg.TOTPKey, totpSecret)
		if err != nil {
			return err
		}
		now := s.now()
		u := &vendorUser{ID: id, Email: email, Name: name, Role: role, Status: "active", Hash: crypto.HashPassword(s.Rand, s.Cfg.PasswordParams, password), TOTPEnc: enc,
			Enrolled: true, CreatedAt: now.Add(-credAge), CredAt: now.Add(-credAge)}
		return s.putVendorUser(tx, u)
	})
}

// VendorSetup stores a one-time setup link for a setup-pending vendor user.
func (sd *Seeder) VendorSetup(ctx context.Context, userID, tok string) error {
	s := sd.s
	return s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		u, err := get[vendorUser](tx, kVendorUser, repository.Global, userID)
		if err != nil || u == nil {
			return notFoundOr(err)
		}
		d := vendorSetup{ID: crypto.MAC(s.Cfg.MACKey, "setup", tok), UserID: userID, Expires: s.now().Add(s.Cfg.SetupLinkTTL)}
		return put(tx, kVendorSet, repository.Global, d.ID, d, keys{k1: userID})
	})
}

// VendorSessionRec stores a vendor session with a renewal handle.
func (sd *Seeder) VendorSessionRec(ctx context.Context, id, userID, handle string) error {
	s := sd.s
	return s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		now := s.now()
		return put(tx, kVendorSess, repository.Global, id, vendorSession{ID: id, UserID: userID, Started: now, EndsAt: now.Add(12 * time.Hour)}, keys{k1: crypto.MAC(s.Cfg.MACKey, "renew", handle), k2: userID})
	})
}

// SeedSupport describes a support session.
type SeedSupport struct{ ID, UserID, Org, Ticket string }

// SupportSession stores an active view-mode support session.
func (sd *Seeder) SupportSession(ctx context.Context, p SeedSupport) error {
	s := sd.s
	return s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		now := s.now()
		return put(tx, kSupport, repository.Global, p.ID, supportSession{ID: p.ID, UserID: p.UserID, Org: p.Org, Mode: "view", Reason: "seeded for the contract run", Ticket: p.Ticket,
			Started: now, EndsAt: now.Add(30 * time.Minute)}, keys{k1: p.UserID, k2: p.Org})
	})
}

// OwnerInvitationWithID stores a pending owner invitation with a fixed id.
func (sd *Seeder) OwnerInvitationWithID(ctx context.Context, id, tenant, mobile, name string) error {
	s := sd.s
	return s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		now := s.now()
		i := invitation{ID: id, Kind: "owner", TenantID: tenant, MobileKey: s.mobileKey(mobile), Mobile: mobile, OwnerName: name, Status: "pending", CreatedAt: now,
			ExpiresAt: now.Add(s.Cfg.InvitationTTL), MemberID: string(s.NewID())}
		return put(tx, kInvitation, repository.Global, id, i, keys{k1: i.MobileKey, k2: tenant})
	})
}

// SeedApproval describes a vendor approval.
type SeedApproval struct {
	ID, Kind, Requester, Approver, Org, Mobile, NewMobile, State string
	CompletesAt                                                  time.Time
	// Lifetime of the record; zero keeps the 5 minutes of a sign-in request. Grant kinds lapse after 24 hours.
	Lifetime time.Duration
}

// VendorApproval stores a vendor approval record.
func (sd *Seeder) VendorApproval(ctx context.Context, p SeedApproval) error {
	s := sd.s
	return s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		now := s.now()
		life := p.Lifetime
		if life == 0 {
			life = 5 * time.Minute
		}
		a := vendorApproval{ID: p.ID, Kind: p.Kind, Requester: p.Requester, Approver: p.Approver, Org: p.Org, Mobile: p.Mobile, NewMobile: p.NewMobile, Reason: "seeded for the contract run",
			Ticket: "SUP-2041", Verified: "callback_to_registered_number", State: p.State, CreatedAt: now, ExpiresAt: now.Add(life), CompletesAt: p.CompletesAt}
		if p.State == "approved" && p.Kind == "sign_in_code" {
			code := "7QK39XD2"
			a.CodeMAC = crypto.MAC(s.Cfg.MACKey, "vcode", p.Mobile, code)
			a.FirstHalf, _ = crypto.Seal(s.Rand, s.Cfg.TOTPKey, []byte(code[:4]))
			a.CodeUntil = now.Add(10 * time.Minute)
		}
		return put(tx, kVendorAppr, repository.Global, p.ID, a, keys{k1: p.Org, k2: p.Requester})
	})
}

// SetupPending stores a vendor user in setup_pending with a one-time setup link token.
func (sd *Seeder) SetupPending(ctx context.Context, id, email, name, role, tok string) error {
	s := sd.s
	err := s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		now := s.now()
		return s.putVendorUser(tx, &vendorUser{ID: id, Email: email, Name: name, Role: role, Status: "setup_pending", CreatedAt: now, CredAt: now})
	})
	if err != nil {
		return err
	}
	return sd.VendorSetup(ctx, id, tok)
}

// OwnerCount sets the number of owners of an organisation (0 makes it eligible for a first-owner invitation).
func (sd *Seeder) OwnerCount(ctx context.Context, tenant string, n int) error {
	s := sd.s
	return s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		return put(tx, kOwnerCount, repository.Global, tenant, ownerCount{N: n}, keys{})
	})
}

// ClearDeviceBrand empties a device's brand, as a row created before ADR-0014 A3.4 has it (backfill tests).
func (sd *Seeder) ClearDeviceBrand(ctx context.Context, tenant, deviceID string) error {
	s := sd.s
	return s.Store.Tx(ctx, tenant, func(tx repository.Tx) error {
		d, err := get[device](tx, kDevice, tenant, deviceID)
		if err != nil || d == nil {
			return notFoundOr(err)
		}
		d.BrandID = ""
		return put(tx, kDevice, tenant, deviceID, d, keys{k1: d.OutletID})
	})
}

// RevokeDevice revokes a device as the vendor operation does (state, revocation feed, event, audit).
func (sd *Seeder) RevokeDevice(ctx context.Context, tenant, deviceID, reason, by string) error {
	s := sd.s
	return s.Store.Tx(ctx, tenant, func(tx repository.Tx) error {
		d, err := get[device](tx, kDevice, tenant, deviceID)
		if err != nil || d == nil {
			return notFoundOr(err)
		}
		return s.revokeDeviceTx(tx, d, reason, by)
	})
}

// DrainDevice records that a revoked device drained through the given streams.
func (sd *Seeder) DrainDevice(ctx context.Context, tenant, deviceID string, through map[string]int) error {
	s := sd.s
	return s.Store.Tx(ctx, tenant, func(tx repository.Tx) error {
		d, err := get[device](tx, kDevice, tenant, deviceID)
		if err != nil || d == nil {
			return notFoundOr(err)
		}
		d.State, d.DrainedAt = "drained", s.now()
		for st, seq := range through {
			d.DrainedThr = append(d.DrainedThr, stream{Stream: st, Seq: seq})
		}
		return put(tx, kDevice, tenant, deviceID, d, keys{k1: d.OutletID})
	})
}

// PinLocked locks a member's PIN on a device (repeated wrong PINs).
func (sd *Seeder) PinLocked(ctx context.Context, tenant, deviceID, memberID string) error {
	s := sd.s
	return s.Store.Tx(ctx, tenant, func(tx repository.Tx) error {
		return put(tx, kProofFail, tenant, deviceID+":"+memberID, failDoc{Locked: true}, keys{k1: memberID})
	})
}

// AssignRole adds a role assignment to a member (an owner assignment counts as an owner).
func (sd *Seeder) AssignRole(ctx context.Context, tenant, memberID, assignmentID, roleID string) error {
	s := sd.s
	return s.Store.Tx(ctx, tenant, func(tx repository.Tx) error {
		m, err := get[member](tx, kMember, tenant, memberID)
		if err != nil || m == nil {
			return notFoundOr(err)
		}
		m.Assignments = append(m.Assignments, assignment{ID: assignmentID, RoleID: roleID})
		if err := put(tx, kMember, tenant, memberID, m, keys{k1: m.AccountID}); err != nil {
			return err
		}
		if _, ownerID, _ := s.loadRoles(tx, tenant); ownerID == roleID {
			return s.adjustOwners(tx, tenant, +1)
		}
		return nil
	})
}

// ApproveRequest marks a caution approval request approved by another member and issues its approval
// token, as a real decision does.
func (sd *Seeder) ApproveRequest(ctx context.Context, tenant, id, approver string) error {
	s := sd.s
	return s.Store.Tx(ctx, tenant, func(tx repository.Tx) error {
		r, err := get[approvalReq](tx, kApprReq, repository.Global, id)
		if err != nil || r == nil {
			return notFoundOr(err)
		}
		now := s.now()
		claims := auth.Claims{Subject: r.Member, Type: auth.TypeApproval, TenantID: r.TenantID, SessionID: r.Session, Operation: r.Operation,
			BodyHash: claimBodyHash(r.BodyHash), IssuedAt: now.Unix(), ExpiresAt: now.Add(s.Cfg.ApprovalTokTTL).Unix(), JTI: string(s.NewID())}
		tok, err := s.Tokens.Access(claims)
		if err != nil {
			return err
		}
		r.State, r.Approver, r.Token = "approved", approver, tok
		return put(tx, kApprReq, repository.Global, r.ID, r, keys{k1: r.TenantID, k2: r.AccountID})
	})
}
