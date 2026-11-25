package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/hostryhq/go-common/apperr"
	gsync "github.com/hostryhq/go-common/sync"
	"github.com/hostryhq/svc-identity/internal/crypto"
	"github.com/hostryhq/svc-identity/internal/gen"
	"github.com/hostryhq/svc-identity/repository"
)

// DrainTag is the domain tag of the device-signed drain statement (ADR-0005 A3.3).
const DrainTag = "hostry-drain-v1"

// StatementHash is the SHA-256 (lowercase hex) of the canonical JSON (RFC 8785) of a drain statement,
// signature included. The wipe order quotes it (A3.3 item 6).
func StatementHash(st gen.DrainStatement) (string, error) {
	b, err := json.Marshal(st)
	if err != nil {
		return "", err
	}
	c, err := gsync.Canonicalize(b)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return hex.EncodeToString(sum[:]), nil
}

// StatementMessage is what the device signs: the domain tag, a newline, and the canonical JSON of the
// statement without its signature.
func StatementMessage(st gen.DrainStatement) ([]byte, error) {
	b, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	delete(m, "sig")
	if b, err = json.Marshal(m); err != nil {
		return nil, err
	}
	c, err := gsync.Canonicalize(b)
	if err != nil {
		return nil, err
	}
	return append([]byte(DrainTag+"\n"), c...), nil
}

// drainRefusal is a statement or series set that cannot be accepted: 422 with a stable code.
func drainRefusal(code string) error {
	return apperr.New(apperr.Validation, code, "the drain report cannot be accepted")
}

// verifyStatement checks a drain statement for device d: it names d as origin, is signed with the key
// of its signer (d itself, or for a key-loss recovery the adopting device named by the recovery record),
// and carries the signer's key id. It returns the statement's hash.
func (s *Service) verifyStatement(tx repository.Tx, d *device, st gen.DrainStatement) (string, error) {
	if st.Origin != d.ID || st.By == "" {
		return "", drainRefusal("drain.statement_invalid")
	}
	signer := d
	if st.By != d.ID {
		// Key loss: signed with the new key of the adopting device under the recovery record (ADR-0002 A1.3).
		r, err := s.recoveryOf(tx, d.TenantID, d.ID)
		if err != nil {
			return "", err
		}
		if r == nil || st.Rec == nil || *st.Rec != r.ID || st.By != r.NewDeviceID {
			return "", drainRefusal("drain.statement_invalid")
		}
		if signer, err = get[device](tx, kDevice, d.TenantID, st.By); err != nil || signer == nil {
			return "", drainRefusal("drain.statement_invalid")
		}
	} else if st.Rec != nil {
		return "", drainRefusal("drain.statement_invalid")
	}
	if st.Kid != DeviceKID(signer.ID) {
		return "", drainRefusal("drain.statement_invalid")
	}
	pub, err := crypto.FromJWK(signer.Key)
	if err != nil {
		return "", drainRefusal("drain.statement_invalid")
	}
	msg, err := StatementMessage(st)
	if err != nil || !crypto.VerifyRaw(pub, msg, st.Sig) {
		return "", drainRefusal("drain.statement_invalid")
	}
	return StatementHash(st)
}

// seriesSetIsIssued reports whether the stated series are exactly the series identity issued to the
// device: each stated series matches a distinct issued one by id (or by code when tenancy's id was not
// kept with the device), and none is left over on either side.
func seriesSetIsIssued(d *device, stated []drainSeries) bool {
	if len(stated) != len(d.Series) {
		return false
	}
	used := make([]bool, len(d.Series))
	for _, x := range stated {
		found := false
		for i, c := range d.Series {
			if used[i] {
				continue
			}
			if (c.SeriesID != "" && c.SeriesID == x.SeriesID) || (c.SeriesID == "" && x.Code != "" && c.Code == x.Code) {
				used[i], found = true, true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// seriesAreIssued reports whether every stated series was issued to the device (by id).
func seriesAreIssued(d *device, stated []drainSeries) bool {
	for _, x := range stated {
		found := false
		for _, c := range d.Series {
			found = found || (c.SeriesID != "" && c.SeriesID == x.SeriesID)
		}
		if !found {
			return false
		}
	}
	return true
}

// RecordDeviceDrained is the gateway's report that a revoked device's operations are stored, resting on
// the drain statement the device signed itself (ADR-0005 A3.3). Identity verifies the signature and the
// series set and copies the numbers into identity.device.drained; the numbers are the device's, identity
// only attests that the device said so. A second, different statement is refused (409).
func (s *Service) RecordDeviceDrained(ctx context.Context, id string, in gen.RecordDrain) (gen.Device, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.Device{}, errUnauth()
	}
	var out gen.Device
	var refuse error
	err := s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		d, err := get[device](tx, kDevice, pr.TenantID, id)
		if err != nil || d == nil {
			return notFoundOr(err)
		}
		if d.State == "active" {
			return apperr.New(apperr.Conflict, "device_not_revoked", "the device is not revoked")
		}
		if d.State != "revoked" {
			// Already drained: the same statement is a repeat, another is refused and kept as evidence by the gateway.
			if in.Statement != nil && d.DrainStmtHash != "" {
				if h, err := StatementHash(*in.Statement); err != nil || h != d.DrainStmtHash {
					return apperr.New(apperr.Conflict, "drain.statement_conflict", "the device is already drained on another statement")
				}
			}
			out = deviceDTO(d)
			return nil
		}
		var series []drainSeries
		hash := ""
		if in.Statement != nil {
			if hash, err = s.verifyStatement(tx, d, *in.Statement); err != nil {
				refuse = err
				return nil
			}
			streams := map[string]int{}
			for _, st := range in.Statement.Streams {
				streams[st.Stream] = int(st.Seq)
			}
			if len(streams) != len(in.DrainedThrough) {
				refuse = drainRefusal("drain.streams_mismatch")
				return nil
			}
			for _, t := range in.DrainedThrough {
				if seq, ok := streams[t.Stream]; !ok || seq != t.Seq {
					refuse = drainRefusal("drain.streams_mismatch")
					return nil
				}
			}
			for _, x := range in.Statement.Series {
				series = append(series, drainSeries{SeriesID: x.SeriesId, Code: x.Code, FY: x.Fy, LastNumber: x.LastNumber})
			}
			if in.Series != nil && !sameSeries(series, *in.Series) {
				refuse = drainRefusal("drain.series_mismatch")
				return nil
			}
		} else {
			// Without a statement nothing identity could attest to exists (A3.3 item 7). Only the contract run of the
			// double, whose spec example carries none, accepts the gateway's list as given.
			if !s.Cfg.ExampleLiterals {
				refuse = drainRefusal("drain.statement_required")
				return nil
			}
			if in.Series != nil {
				for _, x := range *in.Series {
					series = append(series, drainSeries{SeriesID: x.SeriesId, FY: x.Fy, LastNumber: int64(x.LastNumber)})
				}
			}
		}
		// The spec's drain example (no statement) names one series of the invoice and credit-note pair the world issued, so
		// the contract run checks only that what it names was issued; every real report is held to the exact set.
		if ok := seriesSetIsIssued(d, series); !ok && !(in.Statement == nil && seriesAreIssued(d, series)) {
			// A series set that is not exactly what was issued: nothing is recorded and the vendor is told.
			s.Notify.Notify(ctx, Notice{Kind: "drain_series_mismatch", TenantID: d.TenantID, DeviceID: d.ID})
			if err := s.audit(tx, d.TenantID, auditDoc{Action: "device.drain_refused", ActorKind: "system", ActorLbl: "identity", Outcome: "refused", Target: d.ID, Reason: "series_mismatch"}); err != nil {
				return err
			}
			refuse = drainRefusal("drain.series_mismatch")
			return nil
		}
		now := s.now()
		d.State, d.DrainedAt, d.DrainStmtHash, d.DrainSeries = "drained", now, hash, series
		for _, st := range in.DrainedThrough {
			d.DrainedThr = append(d.DrainedThr, stream{Stream: st.Stream, Seq: st.Seq})
		}
		if err := put(tx, kDevice, pr.TenantID, id, d, keys{k1: d.OutletID}); err != nil {
			return err
		}
		if r, err := s.recoveryOf(tx, d.TenantID, d.ID); err != nil {
			return err
		} else if r != nil && !r.Closed {
			r.Closed = true
			if err := put(tx, kDevRecov, d.TenantID, r.ID, r, keys{k1: r.OldDeviceID}); err != nil {
				return err
			}
		}
		// identity.device.drained (ADR-0014 A2.5 item 2), once, in the transaction of the state change. The series
		// are copied from the statement the device signed (A3.3 item 5).
		evSeries := make([]map[string]any, 0, len(series))
		for _, x := range series {
			evSeries = append(evSeries, map[string]any{"series_id": x.SeriesID, "fy": x.FY, "last_number": x.LastNumber})
		}
		if err := s.emit(tx, d.TenantID, d.OutletID, "identity.device.drained", d.ID, pr.Subject,
			map[string]any{"device_id": d.ID, "drained_at": d.DrainedAt, "series": evSeries}); err != nil {
			return err
		}
		out = deviceDTO(d)
		return s.audit(tx, d.TenantID, auditDoc{Action: "device.drained", ActorKind: "system", ActorLbl: "identity", Outcome: "succeeded", Target: d.ID})
	})
	if refuse != nil {
		return gen.Device{}, refuse
	}
	return out, err
}

func sameSeries(a []drainSeries, b []gen.DrainSeries) bool {
	if len(a) != len(b) {
		return false
	}
	have := map[string]drainSeries{}
	for _, x := range a {
		have[x.SeriesID] = x
	}
	for _, x := range b {
		y, ok := have[x.SeriesId]
		if !ok || y.FY != x.Fy || y.LastNumber != int64(x.LastNumber) {
			return false
		}
	}
	return true
}

// GetWipeOrder issues the signed wipe order, never sooner than 15 minutes after the drain, on
// the server's clock (ADR-0005 section 4 step 5). It quotes the hash of the statement the drain
// rests on (A3.3 item 6). A key-loss recovery has no wipe order.
func (s *Service) GetWipeOrder(ctx context.Context, id string) (gen.WipeOrder, error) {
	pr, ok := principal(ctx)
	if !ok {
		return gen.WipeOrder{}, errUnauth()
	}
	var out gen.WipeOrder
	err := s.Store.Tx(ctx, pr.TenantID, func(tx repository.Tx) error {
		d, err := get[device](tx, kDevice, pr.TenantID, id)
		if err != nil || d == nil || pr.DeviceID != id {
			return notFoundOr(err)
		}
		if r, err := s.recoveryOf(tx, pr.TenantID, id); err != nil || r != nil {
			return notFoundOr(err)
		}
		now := s.now()
		if d.State != "drained" || now.Before(d.DrainedAt.Add(s.Cfg.WipeDelay)) {
			return apperr.New(apperr.Conflict, "wipe_order_not_ready", "the wipe order is not ready yet")
		}
		thr := make([]gen.StreamSequence, 0, len(d.DrainedThr))
		for _, t := range d.DrainedThr {
			thr = append(thr, gen.StreamSequence{Stream: t.Stream, Seq: t.Seq})
		}
		claims := map[string]any{"typ": "wipe", "device_id": d.ID, "drained_through": thr, "issued_at": now}
		out = gen.WipeOrder{DeviceId: d.ID, DrainedThrough: thr, IssuedAt: now}
		if h := strings.TrimSpace(d.DrainStmtHash); h != "" {
			claims["statement_hash"] = h
			out.StatementHash = &h
		}
		jws, err := s.Tokens.Pack(claims)
		if err != nil {
			return err
		}
		out.Jws = jws
		return nil
	})
	return out, err
}
