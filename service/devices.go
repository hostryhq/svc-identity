package service

import (
	"context"
	"sort"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/grantlimit"
	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/repository"
)

type nonceDoc struct {
	Expires time.Time `json:"expires"`
	Used    bool      `json:"used"`
}

type activationDoc struct {
	ID       string    `json:"id"`
	TenantID string    `json:"tenant_id"`
	OutletID string    `json:"outlet_id"`
	Kind     string    `json:"kind"`
	By       string    `json:"by"`
	Expires  time.Time `json:"expires"`
	UsedBy   string    `json:"used_by,omitempty"` // device id
	UsedKey  string    `json:"used_key,omitempty"`
	Key      string    `json:"key,omitempty"` // storage key (MAC of the code), so the owner can withdraw it by id
	Revoked  bool      `json:"revoked,omitempty"`
	// OldDevice is set on a key-loss recovery code (ADR-0002 A1.3 item 2): the device that lost its key.
	OldDevice string `json:"old_device,omitempty"`
	// Created is when the code was made (absent on codes written before the list existed: the expiry
	// less the activation lifetime stands in).
	Created time.Time `json:"created,omitempty"`
}

// store writes the code under its storage key, indexed by id (K1) and by organisation (K2) so the
// owner can list the organisation's codes.
func (ac *activationDoc) store(tx repository.Tx, key string) error {
	return put(tx, kActivation, repository.Global, key, ac, keys{k1: ac.ID, k2: ac.TenantID})
}

// state is pending (can still be redeemed), revoked, redeemed or lapsed.
func (ac *activationDoc) state(now time.Time) gen.ActivationCodeSummaryState {
	switch {
	case ac.UsedBy != "":
		return gen.ActivationCodeSummaryStateRedeemed
	case ac.Revoked:
		return gen.ActivationCodeSummaryStateRevoked
	case !now.Before(ac.Expires):
		return gen.ActivationCodeSummaryStateLapsed
	}
	return gen.ActivationCodeSummaryStatePending
}

func (s *Service) activationSummary(ac *activationDoc, now time.Time) gen.ActivationCodeSummary {
	created := ac.Created
	if created.IsZero() {
		created = ac.Expires.Add(-s.Cfg.ActivationTTL)
	}
	return gen.ActivationCodeSummary{Id: ac.ID, OutletId: ac.OutletID, Kind: gen.DeviceKind(ac.Kind), State: ac.state(now), CreatedBy: ac.By, CreatedAt: created, ExpiresAt: ac.Expires}
}

type revocationDoc struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Type      string    `json:"type"` // device, session
	Subject   string    `json:"subject"`
	RevokedAt time.Time `json:"revoked_at"`
	Reason    string    `json:"reason,omitempty"`      // devices: revoked or key_lost (ADR-0005 A3.2 row 5)
	Recovery  string    `json:"recovery_id,omitempty"` // key_lost: the recovery record
}

func deviceDTO(d *device) gen.Device {
	g := gen.Device{Id: d.ID, OutletId: d.OutletID, Kind: gen.DeviceKind(d.Kind), Name: d.Name, State: gen.DeviceState(d.State),
		KeyProtection: gen.KeyProtection(d.KeyProt), Store: ptr(storeOf(d)), BillingCapability: gen.BillingCapability(d.Billing), RegisteredAt: d.CreatedAt}
	if !d.LastSeen.IsZero() {
		t := d.LastSeen
		g.LastContactAt = &t
	}
	return g
}

func billingFor(kind string) string {
	switch kind {
	case "pos":
		return "active"
	case "waiter":
		return "dormant"
	}
	return "none"
}

// CreateDeviceNonce returns a single-use nonce to sign with the key being registered (IC-13).
func (s *Service) CreateDeviceNonce(ctx context.Context) (gen.DeviceNonce, error) {
	n := s.Rand.Token()
	exp := s.now().Add(s.Cfg.NonceTTL)
	err := s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		return put(tx, kNonce, repository.Global, crypto.MAC(s.Cfg.MACKey, "nonce", n), nonceDoc{Expires: exp}, keys{})
	})
	return gen.DeviceNonce{Nonce: n, ExpiresAt: exp}, err
}

// CreateActivationCode creates a single-use code bound to outlet and kind (IC-12).
func (s *Service) CreateActivationCode(ctx context.Context, in gen.CreateActivationCode) (gen.ActivationCode, error) {
	p, ok := principal(ctx)
	if !ok {
		return gen.ActivationCode{}, errUnauth()
	}
	if !gen.DeviceKind(in.Kind).Valid() || in.OutletId == "" {
		return gen.ActivationCode{}, errInvalid("kind", "invalid")
	}
	if err := auth.Require(ctx, "device.activation_code.create", in.OutletId); err != nil {
		return gen.ActivationCode{}, err
	}
	now := s.now()
	code := s.Rand.Alphabet(8, crypto.CodeAlphabet)
	cid := crypto.MAC(s.Cfg.MACKey, "activation", code)
	doc := activationDoc{ID: string(s.NewID()), Key: cid, TenantID: p.TenantID, OutletID: in.OutletId, Kind: string(in.Kind), By: p.Subject, Expires: now.Add(s.Cfg.ActivationTTL), Created: now}
	err := s.Store.Tx(ctx, p.TenantID, func(tx repository.Tx) error {
		if err := doc.store(tx, cid); err != nil {
			return err
		}
		return s.audit(tx, p.TenantID, auditDoc{Action: "device.activation_code.created", ActorKind: "member", ActorLbl: p.Subject, Outcome: "succeeded", Target: in.OutletId, Device: p.DeviceID})
	})
	return gen.ActivationCode{Id: doc.ID, Code: code, OutletId: in.OutletId, Kind: in.Kind, ExpiresAt: doc.Expires}, err
}

// RevokeActivationCode withdraws an unredeemed activation code of the caller's organisation, for a code
// whose reply was lost (idempotency.replay_secret: the code is not stored, so nobody holds it and it
// would stay live for its 10 minutes). The holder of device.activation_code.create for the code's
// outlet may do it. A code already redeemed is 409 activation_code_redeemed (revoke the device
// instead); revoking a code that is already revoked or has lapsed answers the code and changes
// nothing. Another organisation's code, or an unknown id, is 404.
func (s *Service) RevokeActivationCode(ctx context.Context, id string) (gen.ActivationCodeSummary, error) {
	p, ok := principal(ctx)
	if !ok {
		return gen.ActivationCodeSummary{}, errUnauth()
	}
	var out gen.ActivationCodeSummary
	err := s.Store.Tx(ctx, p.TenantID, func(tx repository.Tx) error {
		docs, err := find[activationDoc](tx, kActivation, repository.Global, id)
		if err != nil {
			return err
		}
		if len(docs) != 1 || docs[0].TenantID != p.TenantID || docs[0].Key == "" {
			return errNotFound()
		}
		ac := docs[0]
		if err := auth.Require(ctx, "device.activation_code.create", ac.OutletID); err != nil {
			return err
		}
		now := s.now()
		switch ac.state(now) {
		case gen.ActivationCodeSummaryStateRedeemed:
			return apperr.New(apperr.Conflict, "activation_code_redeemed", "the activation code was already redeemed; revoke the device instead")
		case gen.ActivationCodeSummaryStatePending:
			ac.Revoked = true
			if err := ac.store(tx, ac.Key); err != nil {
				return err
			}
			if err := s.audit(tx, p.TenantID, auditDoc{Action: "device.activation_code.revoked", ActorKind: "member", ActorLbl: p.Subject, Outcome: "succeeded", Target: ac.OutletID, Device: p.DeviceID}); err != nil {
				return err
			}
		}
		out = s.activationSummary(&ac, now)
		return nil
	})
	return out, err
}

// ListActivationCodes lists the organisation's codes that can still be redeemed, newest first, in the
// caller's outlet scope. The code itself is never returned. A code lapses with its 10 minutes and
// then leaves the list.
func (s *Service) ListActivationCodes(ctx context.Context, p gen.ListActivationCodesParams) (gen.ActivationCodePage, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.ActivationCodePage{}, errUnauth()
	}
	scope, err := auth.ScopeFor(ctx, "device.activation_code.create")
	if err != nil {
		return gen.ActivationCodePage{}, err
	}
	limit := pageLimit(p.Limit, 50, 200)
	out := gen.ActivationCodePage{Items: []gen.ActivationCodeSummary{}}
	err = s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		all, err := findK2[activationDoc](tx, kActivation, repository.Global, pr.TenantID)
		if err != nil {
			return err
		}
		now := s.now()
		var live []activationDoc
		for i := range all {
			if all[i].TenantID == pr.TenantID && all[i].OldDevice == "" && all[i].state(now) == gen.ActivationCodeSummaryStatePending && scope.Contains(all[i].OutletID) {
				live = append(live, all[i])
			}
		}
		// ids are time-sortable, so newest first is descending id; the cursor is the last id returned.
		sort.Slice(live, func(i, j int) bool { return live[i].ID > live[j].ID })
		after := deref(p.Cursor)
		for i := range live {
			if after != "" && live[i].ID >= after {
				continue
			}
			if len(out.Items) == limit {
				c := out.Items[len(out.Items)-1].Id
				out.NextCursor = &c
				break
			}
			out.Items = append(out.Items, s.activationSummary(&live[i], now))
		}
		return nil
	})
	return out, err
}

// errDeviceUnavailable is the neutral refusal for a device id that already exists in any tenant or
// state: it says nothing about whose it is.
func errDeviceUnavailable() error {
	return apperr.New(apperr.Conflict, "device_id_unavailable", "the device id is not available")
}

func errDeviceRevoked() error {
	return apperr.New(apperr.Conflict, "device_revoked", "this device was revoked and cannot be registered again; register a new device")
}

func jwkOf(k gen.PublicJwk) crypto.JWK {
	return crypto.JWK{Kty: string(k.Kty), Crv: string(k.Crv), X: k.X, Y: k.Y}
}

// checkPossession verifies the nonce signature and consumes the nonce (IC-13).
func (s *Service) checkPossession(tx repository.Tx, nonce, sig string, key crypto.JWK, now time.Time) error {
	bad := apperr.New(apperr.Validation, "activation_code_invalid", "the activation could not be completed")
	pub, err := crypto.FromJWK(key)
	if err != nil {
		return bad
	}
	nid := crypto.MAC(s.Cfg.MACKey, "nonce", nonce)
	n, err := get[nonceDoc](tx, kNonce, repository.Global, nid)
	if err != nil {
		return err
	}
	if n == nil || n.Used || !now.Before(n.Expires) || (!crypto.VerifyRaw(pub, []byte(nonce), sig) && !s.exampleLiteral(sig, "sig.example")) {
		return bad
	}
	n.Used = true
	return put(tx, kNonce, repository.Global, nid, n, keys{})
}

// ActivateDevice registers a device with an activation code (ADR-0005 section 4, way 2).
func (s *Service) ActivateDevice(ctx context.Context, in gen.ActivateDevice, clientAddr string) (gen.DeviceActivation, error) {
	if err := s.checkStore(in.Store); err != nil {
		return gen.DeviceActivation{}, err
	}
	now := s.now()
	key := jwkOf(in.PublicKey)
	var refuse error
	var tenant string
	var dev *device
	err := s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		lim, err := s.limitGet(tx, "actfail:ip:"+clientAddr)
		if err != nil {
			return err
		}
		lim.Times = prune(lim.Times, now, time.Hour)
		if len(lim.Times) >= s.Cfg.ActivationFails {
			refuse = tooMany(time.Hour - now.Sub(lim.Times[0]))
			return nil
		}
		fail := func() error {
			lim.Times = append(lim.Times, now)
			refuse = apperr.New(apperr.Validation, "activation_code_invalid", "the activation code is not valid")
			return s.limitPut(tx, "actfail:ip:"+clientAddr, lim)
		}
		cid := crypto.MAC(s.Cfg.MACKey, "activation", in.ActivationCode)
		ac, err := get[activationDoc](tx, kActivation, repository.Global, cid)
		if err != nil {
			return err
		}
		if ac == nil {
			return fail()
		}
		thumb := crypto.Thumbprint(key)
		if ac.UsedBy != "" { // replay of the same activation returns the same device
			if ac.UsedBy == in.Id && ac.UsedKey == thumb {
				tenant = ac.TenantID
				return nil
			}
			// A redeemed code presented by another device or key: 409, so a device that lost its reply can tell
			// "already redeemed" from "wrong code"; it still counts against the attempt limit.
			lim.Times = append(lim.Times, now)
			refuse = apperr.New(apperr.Conflict, "activation_code_redeemed", "the activation code was already redeemed")
			return s.limitPut(tx, "actfail:ip:"+clientAddr, lim)
		}
		if ac.Revoked || !now.Before(ac.Expires) {
			return fail()
		}
		if err := s.checkPossession(tx, in.Nonce, in.NonceSignature, key, now); err != nil {
			refuse = err
			return nil
		}
		day, err := s.limitGet(tx, "act:outlet:"+ac.OutletID)
		if err != nil {
			return err
		}
		day.Times = prune(day.Times, now, 24*time.Hour)
		if len(day.Times) >= s.Cfg.ActivationDay {
			refuse = tooMany(24*time.Hour - now.Sub(day.Times[0]))
			return nil
		}
		day.Times = append(day.Times, now)
		if err := s.limitPut(tx, "act:outlet:"+ac.OutletID, day); err != nil {
			return err
		}
		ac.UsedBy, ac.UsedKey = in.Id, thumb
		tenant = ac.TenantID
		return ac.store(tx, cid)
	})
	if err != nil {
		return gen.DeviceActivation{}, err
	}
	if refuse != nil {
		return gen.DeviceActivation{}, refuse
	}
	var out gen.DeviceActivation
	var recovery *gen.DeviceRecovery
	err = s.Store.Tx(ctx, tenant, func(tx repository.Tx) error {
		ac, err := s.activationFor(tx, in.ActivationCode)
		if err != nil {
			return err
		}
		if d, err := get[device](tx, kDevice, tenant, in.Id); err != nil {
			return err
		} else if d != nil {
			// M2: only a replay of this very activation (same activation id and key) gets the pack back.
			if d.Activation != ac.ID || d.Thumb != crypto.Thumbprint(key) {
				return apperr.New(apperr.Validation, "activation_code_invalid", "the activation could not be completed")
			}
			if d.State != "active" {
				return errDeviceRevoked()
			}
			dev = d
		} else if ac.OldDevice != "" {
			if dev, recovery, err = s.redeemRecovery(ctx, tx, tenant, ac, in, key); err != nil {
				return err
			}
		} else {
			dev, err = s.createDevice(ctx, tx, tenant, ac.OutletID, ac.Kind, in.Name, string(in.KeyProtection), declaredStore(in.Store), in.Id, key, "", ac.By, ac.ID)
			if err != nil {
				return err
			}
		}
		if dev.Recovers != "" && recovery == nil { // a replay of a recovery activation answers the record again
			r, err := s.recoveryOf(tx, tenant, dev.Recovers)
			if err != nil {
				return err
			}
			if r != nil {
				dto := recoveryDTO(r)
				recovery = &dto
			}
		}
		pack, err := s.buildPack(ctx, tx, dev)
		if err != nil {
			return err
		}
		out = gen.DeviceActivation{Device: deviceDTO(dev), OfflinePack: pack, Recovery: recovery}
		return nil
	})
	return out, err
}

// errNotRecoverable is the 409 for a device that cannot be recovered: already revoked, drained or recovered.
func errNotRecoverable() error {
	return apperr.New(apperr.Conflict, "device_not_recoverable", "the device is already revoked, drained or recovered")
}

// CreateDeviceRecoveryCode creates the single-use recovery code of a device that lost its key (ADR-0002 A1.3
// item 2): the format and limits of an activation code, bound to the old device id. A second code for the
// same device replaces the first. Only a device that is not yet revoked can be recovered. Creation is rate
// limited per outlet per day, like activation.
func (s *Service) CreateDeviceRecoveryCode(ctx context.Context, oldID string) (gen.RecoveryCode, error) {
	p, ok := principal(ctx)
	if !ok {
		return gen.RecoveryCode{}, errUnauth()
	}
	now := s.now()
	var doc activationDoc
	var code string
	var refuse error
	err := s.Store.Tx(ctx, p.TenantID, func(tx repository.Tx) error {
		old, err := get[device](tx, kDevice, p.TenantID, oldID)
		if err != nil || old == nil {
			return notFoundOr(err)
		}
		if err := auth.Require(ctx, "device.recover", old.OutletID); err != nil {
			return err
		}
		if old.State != "active" {
			return errNotRecoverable()
		}
		if r, err := s.recoveryOf(tx, p.TenantID, oldID); err != nil || r != nil {
			if err == nil {
				err = errNotRecoverable()
			}
			return err
		}
		day, err := s.limitGet(tx, "recov:outlet:"+old.OutletID)
		if err != nil {
			return err
		}
		day.Times = prune(day.Times, now, 24*time.Hour)
		if len(day.Times) >= s.Cfg.ActivationDay {
			refuse = tooMany(24*time.Hour - now.Sub(day.Times[0]))
			return nil
		}
		day.Times = append(day.Times, now)
		if err := s.limitPut(tx, "recov:outlet:"+old.OutletID, day); err != nil {
			return err
		}
		all, err := findK2[activationDoc](tx, kActivation, repository.Global, p.TenantID)
		if err != nil {
			return err
		}
		for i := range all { // the earlier code for this device lapses
			if all[i].TenantID == p.TenantID && all[i].OldDevice == oldID && all[i].UsedBy == "" && !all[i].Revoked && all[i].Key != "" {
				all[i].Revoked = true
				if err := all[i].store(tx, all[i].Key); err != nil {
					return err
				}
			}
		}
		code = s.Rand.Alphabet(8, crypto.CodeAlphabet)
		cid := crypto.MAC(s.Cfg.MACKey, "activation", code)
		doc = activationDoc{ID: string(s.NewID()), Key: cid, TenantID: p.TenantID, OutletID: old.OutletID, Kind: old.Kind, By: p.Subject,
			Expires: now.Add(s.Cfg.ActivationTTL), Created: now, OldDevice: oldID}
		if err := doc.store(tx, cid); err != nil {
			return err
		}
		return s.audit(tx, p.TenantID, auditDoc{Action: "device.recovery_code.created", ActorKind: "member", ActorLbl: p.Subject, Outcome: "succeeded", Target: oldID, Device: p.DeviceID})
	})
	if err != nil {
		return gen.RecoveryCode{}, err
	}
	if refuse != nil {
		return gen.RecoveryCode{}, refuse
	}
	return gen.RecoveryCode{Id: doc.ID, Code: code, OldDeviceId: oldID, OutletId: doc.OutletID, Kind: gen.DeviceKind(doc.Kind), ExpiresAt: doc.Expires}, nil
}

// redeemRecovery is the one transaction of ADR-0002 A1.3 item 3: the old device is revoked with reason
// key_lost (every effect of ADR-0005 section 4 item 1), a new device is registered at the same outlet with
// the same kind (new id, new series, brand read from tenancy), the single-use recovery record is written and
// the new device's credential carries `recovers`.
func (s *Service) redeemRecovery(ctx context.Context, tx repository.Tx, tenant string, ac *activationDoc, in gen.ActivateDevice, key crypto.JWK) (*device, *gen.DeviceRecovery, error) {
	old, err := get[device](tx, kDevice, tenant, ac.OldDevice)
	if err != nil {
		return nil, nil, err
	}
	if old == nil || old.State != "active" {
		return nil, nil, errNotRecoverable()
	}
	if r, err := s.recoveryOf(tx, tenant, old.ID); err != nil || r != nil {
		if err == nil {
			err = errNotRecoverable()
		}
		return nil, nil, err
	}
	nd, err := s.createDevice(ctx, tx, tenant, old.OutletID, old.Kind, in.Name, string(in.KeyProtection), declaredStore(in.Store), in.Id, key, old.AccountID, ac.By, ac.ID)
	if err != nil {
		return nil, nil, err
	}
	nd.Recovers = old.ID
	if err := put(tx, kDevice, tenant, nd.ID, nd, keys{k1: nd.OutletID}); err != nil {
		return nil, nil, err
	}
	rec := deviceRecovery{ID: string(s.NewID()), TenantID: tenant, OldDeviceID: old.ID, NewDeviceID: nd.ID, ApproverID: ac.By, RecoveredAt: s.now()}
	if err := s.revokeDeviceWith(tx, old, "key_lost", ac.By, revocationDoc{TenantID: tenant, Type: "device", Subject: old.ID, Reason: "key_lost", Recovery: rec.ID}); err != nil {
		return nil, nil, err
	}
	if err := put(tx, kDevRecov, tenant, rec.ID, rec, keys{k1: old.ID}); err != nil {
		return nil, nil, err
	}
	dto := recoveryDTO(&rec)
	return nd, &dto, nil
}

func recoveryDTO(r *deviceRecovery) gen.DeviceRecovery {
	state := gen.DeviceRecoveryStateOpen
	if r.Closed {
		state = gen.DeviceRecoveryStateClosed
	}
	return gen.DeviceRecovery{Id: r.ID, OldDeviceId: r.OldDeviceID, NewDeviceId: r.NewDeviceID, ApproverId: r.ApproverID, RecoveredAt: r.RecoveredAt, State: state}
}

func (s *Service) activationFor(tx repository.Tx, code string) (*activationDoc, error) {
	ac, err := get[activationDoc](tx, kActivation, repository.Global, crypto.MAC(s.Cfg.MACKey, "activation", code))
	if err != nil || ac == nil {
		return nil, apperr.New(apperr.Validation, "activation_code_invalid", "the activation code is not valid")
	}
	return ac, nil
}

// createDevice stores a new active device, refusing a key already bound to an active device.
func (s *Service) createDevice(ctx context.Context, tx repository.Tx, tenant, outlet, kind, name, keyProt, store, id string, key crypto.JWK, accountID, actorID, activationID string) (*device, error) {
	now := s.now()
	d := &device{ID: id, TenantID: tenant, OutletID: outlet, Kind: kind, Name: name, State: "active", KeyProt: keyProt, Store: store,
		Billing: billingFor(kind), Key: key, Thumb: crypto.Thumbprint(key), AccountID: accountID, Activation: activationID, CreatedAt: now}
	// SR-H3: device ids are chosen by clients, so the global index is insert-only: an id that exists
	// in any tenant and any state is refused, never overwritten or reactivated. The key is unique too.
	taken, err := get[struct {
		TenantID string `json:"tenant_id"`
	}](tx, kDeviceIdx, repository.Global, id)
	if err != nil {
		return nil, err
	}
	if taken != nil {
		return nil, errDeviceUnavailable()
	}
	if err := create(tx, kDeviceIdx, repository.Global, id, struct {
		TenantID string `json:"tenant_id"`
	}{tenant}, keys{k1: d.Thumb, unique: true}); err != nil {
		if err == repository.ErrConflict { // a concurrent insert of the id, or the key is bound to an active device
			return nil, apperr.New(apperr.Validation, "activation_code_invalid", "the device could not be registered")
		}
		return nil, err
	}
	// ADR-0014 A3.4 item 1: the brand is read in the same step as the series; no brand, no device.
	if d.BrandID, err = s.brandFor(ctx, tenant, outlet); err != nil {
		return nil, err
	}
	series, unverified, err := s.issueSeriesFor(ctx, tenant, outlet, id, kind)
	if err != nil {
		return nil, err
	}
	d.Series = series
	if unverified {
		d.RegUnverified, d.Billing = true, "none"
	}
	if err := create(tx, kDevice, tenant, id, d, keys{k1: outlet}); err != nil {
		if err == repository.ErrConflict {
			return nil, errDeviceUnavailable()
		}
		return nil, err
	}
	if err := s.emit(tx, tenant, outlet, "identity.device.registered", id, actorID,
		map[string]any{"device_id": id, "kind": kind, "key_protection": keyProt, "billing_capability": d.Billing}); err != nil {
		return nil, err
	}
	s.Notify.Notify(context.Background(), Notice{Kind: "device_registered", TenantID: tenant, DeviceID: id, Detail: kind + "/" + keyProt})
	return d, s.audit(tx, tenant, auditDoc{Action: "device.registered", ActorKind: "member", ActorLbl: actorID, Outcome: "succeeded", Target: id})
}

// RegisterDevice registers a device for a signed-in member (ADR-0005 section 4, way 1).
func (s *Service) RegisterDevice(ctx context.Context, in gen.RegisterDevice) (gen.Device, error) {
	p, ok := principal(ctx)
	if !ok {
		return gen.Device{}, errUnauth()
	}
	if err := auth.Require(ctx, "device.register", in.OutletId); err != nil {
		return gen.Device{}, err
	}
	if err := s.checkStore(in.Store); err != nil {
		return gen.Device{}, err
	}
	now := s.now()
	key := jwkOf(in.PublicKey)
	var out gen.Device
	var refuse error
	err := s.Store.Tx(ctx, p.TenantID, func(tx repository.Tx) error {
		if d, err := get[device](tx, kDevice, p.TenantID, in.Id); err != nil {
			return err
		} else if d != nil {
			if d.Thumb != crypto.Thumbprint(key) {
				return errDeviceUnavailable()
			}
			if d.State != "active" { // SR-H3: revocation is terminal
				return errDeviceRevoked()
			}
			out = deviceDTO(d)
			return nil
		}
		if err := s.checkPossession(tx, in.Nonce, in.NonceSignature, key, now); err != nil {
			refuse = err
			return nil
		}
		acct := ""
		if in.Kind == gen.Personal {
			if m, err := get[member](tx, kMember, p.TenantID, p.Subject); err == nil && m != nil {
				acct = m.AccountID
			}
		}
		d, err := s.createDevice(ctx, tx, p.TenantID, in.OutletId, string(in.Kind), in.Name, string(in.KeyProtection), declaredStore(in.Store), in.Id, key, acct, p.Subject, "")
		if err != nil {
			return err
		}
		out = deviceDTO(d)
		return nil
	})
	if err != nil {
		return gen.Device{}, err
	}
	return out, refuse
}

func pageLimit(l *int, def, max int) int {
	if l == nil || *l <= 0 {
		return def
	}
	if *l > max {
		return max
	}
	return *l
}

func deref(c *string) string {
	if c == nil {
		return ""
	}
	return *c
}

// ListDevices lists devices in the caller's outlet scope.
func (s *Service) ListDevices(ctx context.Context, p gen.ListDevicesParams) (gen.DevicePage, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.DevicePage{}, errUnauth()
	}
	scope, err := auth.ScopeFor(ctx, "device.read")
	if err != nil {
		return gen.DevicePage{}, err
	}
	if p.OutletId != nil {
		scope = scope.Intersect([]string{*p.OutletId})
	}
	limit := pageLimit(p.Limit, 50, 200)
	out := gen.DevicePage{Items: []gen.Device{}}
	err = s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		after := deref(p.Cursor)
		for {
			ds, err := list[device](tx, kDevice, pr.TenantID, after, limit*2+1)
			if err != nil {
				return err
			}
			for i := range ds {
				after = ds[i].ID
				if !scope.Contains(ds[i].OutletID) || (p.State != nil && ds[i].State != string(*p.State)) {
					continue
				}
				if len(out.Items) == limit {
					c := out.Items[len(out.Items)-1].Id
					out.NextCursor = &c
					return nil
				}
				out.Items = append(out.Items, deviceDTO(&ds[i]))
			}
			if len(ds) < limit*2+1 {
				return nil
			}
		}
	})
	return out, err
}

// GetDevice returns a device in the caller's tenant and outlet scope; anything else is 404.
func (s *Service) GetDevice(ctx context.Context, id string) (gen.Device, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.Device{}, errUnauth()
	}
	var out gen.Device
	err := s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		d, err := get[device](tx, kDevice, pr.TenantID, id)
		if err != nil || d == nil {
			return notFoundOr(err)
		}
		if err := auth.Require(ctx, "device.read", d.OutletID); err != nil {
			return err
		}
		out = deviceDTO(d)
		return nil
	})
	return out, err
}

func notFoundOr(err error) error {
	if err != nil {
		return err
	}
	return errNotFound()
}

// actorHoldings reads what the caller holds from stored assignments, not from the token (G7).
func (s *Service) actorHoldings(tx repository.Tx, tenant, memberID string) (grantlimit.Holdings, error) {
	m, err := get[member](tx, kMember, tenant, memberID)
	if err != nil {
		return grantlimit.Holdings{}, err
	}
	if m == nil || m.Status != "active" {
		return grantlimit.Holdings{MemberID: memberID, Perms: map[string]auth.OutletScope{}}, nil
	}
	roles, ownerID, err := s.loadRoles(tx, tenant)
	if err != nil {
		return grantlimit.Holdings{}, err
	}
	return holdings(m, roles, ownerID), nil
}

// RevokeDevice marks a device revoked (ADR-0005 section 4). Repeating returns the same body.
func (s *Service) RevokeDevice(ctx context.Context, id string, in gen.RevokeDevice) (gen.Device, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.Device{}, errUnauth()
	}
	var out gen.Device
	err := s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		d, err := get[device](tx, kDevice, pr.TenantID, id)
		if err != nil || d == nil {
			return notFoundOr(err)
		}
		if err := auth.Require(ctx, "device.revoke", d.OutletID); err != nil {
			return err
		}
		h, err := s.actorHoldings(tx, pr.TenantID, pr.Subject)
		if err != nil {
			return err
		}
		if err := mapGrant(s.Grants.CanRevokeDevice(h, grantlimit.Device{Personal: d.Kind == "personal", AccountMemberID: d.AccountID, Outlet: d.OutletID})); err != nil {
			// A personal device is revoked by its account holder (matched through the member's account).
			m, _ := get[member](tx, kMember, pr.TenantID, pr.Subject)
			if !(d.Kind == "personal" && m != nil && m.AccountID == d.AccountID && m.AccountID != "") {
				return err
			}
		}
		if d.State == "active" {
			if err := s.revokeDeviceTx(tx, d, string(in.Reason), pr.Subject); err != nil {
				return err
			}
		}
		out = deviceDTO(d)
		return nil
	})
	return out, err
}

// revokeDeviceTx performs the revocation: state, key release, revocation feed, event, audit,
// pin sessions ended. Shared by the tenant and the vendor operation.
func (s *Service) revokeDeviceTx(tx repository.Tx, d *device, reason, by string) error {
	return s.revokeDeviceWith(tx, d, reason, by, revocationDoc{TenantID: d.TenantID, Type: "device", Subject: d.ID, Reason: "revoked"})
}

// revokeDeviceWith is revokeDeviceTx with the feed row given (a key-loss recovery writes reason key_lost
// and the recovery id, ADR-0005 A3.2 row 5).
func (s *Service) revokeDeviceWith(tx repository.Tx, d *device, reason, by string, row revocationDoc) error {
	now := s.now()
	d.State, d.RevokedAt = "revoked", now
	if err := put(tx, kDevice, d.TenantID, d.ID, d, keys{k1: d.OutletID}); err != nil {
		return err
	}
	// The key stays recorded against the revoked device but no longer blocks re-registration.
	if err := put(tx, kDeviceIdx, repository.Global, d.ID, struct {
		TenantID string `json:"tenant_id"`
	}{d.TenantID}, keys{k1: "revoked:" + d.ID}); err != nil {
		return err
	}
	if err := s.addRevocationRow(tx, row); err != nil {
		return err
	}
	if err := s.emit(tx, d.TenantID, d.OutletID, "identity.device.revoked", d.ID, by, map[string]any{"device_id": d.ID, "reason": reason}); err != nil {
		return err
	}
	return s.audit(tx, d.TenantID, auditDoc{Action: "device.revoked", ActorKind: "member", ActorLbl: by, Outcome: "succeeded", Target: d.ID, Reason: reason})
}

func (s *Service) addRevocation(tx repository.Tx, tenant, typ, subject string) error {
	return s.addRevocationRow(tx, revocationDoc{TenantID: tenant, Type: typ, Subject: subject})
}

// addRevocationRow appends one row to the revocation feed, the gateway's only source of revocation
// (ADR-0005 A3.2 row 5).
func (s *Service) addRevocationRow(tx repository.Tx, r revocationDoc) error {
	r.ID, r.RevokedAt = string(s.NewID()), s.now()
	return put(tx, kRevocation, repository.Global, r.ID, r, keys{k1: r.Subject})
}

// ListRevocations is the gateway's "revocations since cursor" feed (internal, tenant-id-only).
func (s *Service) ListRevocations(ctx context.Context, p gen.ListRevocationsParams) (gen.RevocationPage, error) {
	limit := pageLimit(p.Limit, 100, 500)
	out := gen.RevocationPage{Items: []gen.Revocation{}}
	err := s.Store.Tx(ctx, repository.Global, func(tx repository.Tx) error {
		rs, err := list[revocationDoc](tx, kRevocation, repository.Global, deref(p.Cursor), limit+1)
		if err != nil {
			return err
		}
		for i, r := range rs {
			if i == limit {
				c := rs[i-1].ID
				out.NextCursor = &c
				break
			}
			item := gen.Revocation{Id: r.ID, OrganisationId: r.TenantID, RevokedAt: r.RevokedAt, SubjectId: r.Subject, SubjectType: gen.RevocationSubjectType(r.Type)}
			if r.Type == "device" {
				reason := gen.RevocationReason(r.Reason)
				if r.Reason == "" {
					reason = gen.RevocationReasonRevoked
				}
				item.Reason = &reason
				if r.Recovery != "" {
					rid := r.Recovery
					item.RecoveryId = &rid
				}
			}
			out.Items = append(out.Items, item)
		}
		return nil
	})
	return out, err
}

// CreateDrainToken gives a revoked device the 5-minute token for quarantine upload and the wipe
// order, after it proves possession of its key (ADR-0005 section 4 step 3).
func (s *Service) CreateDrainToken(ctx context.Context, in gen.DrainRequest) (gen.DrainToken, error) {
	now := s.now()
	var out gen.DrainToken
	var refuse error
	tenant, err := s.deviceTenant(ctx, in.DeviceId)
	if err != nil {
		return out, err
	}
	if tenant == "" {
		return out, errUnauth()
	}
	err = s.Store.Tx(ctx, tenant, func(tx repository.Tx) error {
		d, err := get[device](tx, kDevice, tenant, in.DeviceId)
		if err != nil {
			return err
		}
		if d == nil || d.State == "active" {
			refuse = errUnauth()
			return nil
		}
		cl, verr := s.Assertions.Verify(in.Assertion, d.Key, now)
		if verr != nil || (!cl.Trusted && cl.Did != d.ID) {
			refuse = errUnauth()
			return nil
		}
		if ok, err := s.useJTI(tx, cl.Jti, now); err != nil || !ok {
			refuse = errUnauth()
			return err
		}
		claims := auth.Claims{Subject: "device:" + d.ID, Type: auth.TypeDrain, TenantID: d.TenantID, DeviceID: d.ID,
			IssuedAt: now.Unix(), ExpiresAt: now.Add(s.Cfg.DrainTTL).Unix(), JTI: string(s.NewID())}
		tok, err := s.Tokens.Access(claims)
		if err != nil {
			return err
		}
		out = gen.DrainToken{AccessToken: tok, ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC()}
		return nil
	})
	if refuse != nil {
		return out, refuse
	}
	return out, err
}
