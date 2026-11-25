package api_test

import (
	"testing"

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
