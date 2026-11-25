package api_test

import (
	"net/http"
	"testing"

	tdouble "github.com/hostryhq/svc-tenancy/double"

	"github.com/hostryhq/svc-identity/double"
	"github.com/hostryhq/svc-identity/internal/gen"
)

// The pack of a billing device carries the outlet's registered paper books entry-only, from tenancy's own double
// (ADR-0014 A1.6 item 4); a device with no billing carries none.
func TestPackCarriesRegisteredManualBooks(t *testing.T) {
	e, tok := tenancyEnv(t, "book-registered")
	status, act := e.activateAt(tok, tenOutlet, gen.Pos, double.NewDevice("0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5e"))
	if status != 201 {
		t.Fatalf("activation %d", status)
	}
	mb := act.OfflinePack.Claims.ManualBooks
	if mb == nil || len(*mb) != 1 || (*mb)[0].Code != "BKB" || (*mb)[0].TaxRegistrationId != tenReg {
		t.Fatalf("manual_books: %+v", mb)
	}
	for _, s := range act.OfflinePack.Claims.Series {
		if s.Code == "BKB" {
			t.Fatal("a manual book is never one of the device's own series")
		}
	}
	status, kact := e.activateAt(tok, tenOutlet, gen.Kds, double.NewDevice(newID()))
	if status != 201 || kact.OfflinePack.Claims.ManualBooks != nil {
		t.Fatalf("kds: %d %+v", status, kact.OfflinePack.Claims.ManualBooks)
	}
}

// A tenancy outage must not move pack_v: the books of the last good answer stay in the pack (and with none ever
// read, nil and empty digest the same), so a failed lookup never makes a device download a new pack.
func TestPackIsStableWhileTenancyIsDown(t *testing.T) {
	for _, tc := range []struct {
		name, world string
		wantBooks   int
	}{{"books carried from the last good lookup", "book-registered", 1}, {"no books", "registration-verified", 0}} {
		t.Run(tc.name, func(t *testing.T) {
			e, tok := tenancyEnv(t, tc.world)
			pos := double.NewDevice(newID())
			status, act := e.activateAt(tok, tenOutlet, gen.Pos, pos)
			if status != 201 {
				t.Fatalf("activation %d", status)
			}
			remove := e.d.Tenancy.Inject(tdouble.Fault{Status: http.StatusServiceUnavailable, Match: func(*http.Request) bool { return true }})
			defer remove()
			for i := 0; i < 2; i++ {
				var p gen.OfflinePack
				e.mustJSON(200, "GET", "/v1/devices/"+pos.ID+"/offline-packs/latest", tok, nil, &p)
				n := 0
				if p.Claims.ManualBooks != nil {
					n = len(*p.Claims.ManualBooks)
				}
				if p.PackV != act.OfflinePack.PackV || n != tc.wantBooks {
					t.Fatalf("fetch %d with tenancy down: pack_v %d (was %d), %d books (want %d)", i, p.PackV, act.OfflinePack.PackV, n, tc.wantBooks)
				}
			}
		})
	}
}
