package api_test

import (
	"net/http"
	"testing"

	"github.com/hostryhq/go-common/events"
	"github.com/hostryhq/go-common/ids"
	tdouble "github.com/hostryhq/svc-tenancy/double"

	"github.com/hostryhq/svc-identity/double"
	"github.com/hostryhq/svc-identity/internal/gen"
)

// ADR-0014 T10: the pack carries the organisation's entitlement snapshot from tenancy, a newer snapshot takes a
// new pack_v, and tenancy being down never stops a pack: the last snapshot is carried instead.
func TestPackCarriesEntitlementSnapshotAndRefreshesOnSubscriptionChange(t *testing.T) {
	e, tok := tenancyEnv(t, "registration-verified")
	pos := double.NewDevice(newID())
	status, act := e.activateAt(tok, tenOutlet, gen.Pos, pos)
	if status != 201 {
		t.Fatalf("activation %d", status)
	}
	first := packClaims(act.OfflinePack).Entitlements
	if first == nil || first.EntitlementsV != 1 || len(first.Features) != 0 || first.PlanKey != nil {
		t.Fatalf("no plan yet: %+v", first)
	}

	// Staff assign a plan; identity has not heard yet, tenancy is then unreachable, and the event arrives later.
	if err := e.d.Tenancy.SeedWorld(e.ctx, "subscribed"); err != nil {
		t.Fatal(err)
	}
	remove := e.d.Tenancy.Inject(tdouble.Fault{Status: http.StatusServiceUnavailable, Match: func(*http.Request) bool { return true }})
	defer remove()
	var down gen.OfflinePack
	e.mustJSON(200, "GET", "/v1/devices/"+pos.ID+"/offline-packs/latest", tok, nil, &down)
	if packClaims(down).Entitlements == nil || packClaims(down).Entitlements.EntitlementsV != 1 {
		t.Fatalf("with tenancy down the pack carries the last snapshot: %+v", packClaims(down).Entitlements)
	}
	remove()

	ev := events.Envelope{ID: ids.ID(newID()), Type: "tenancy.subscription.changed", V: 1, Source: "tenancy", TenantID: ids.ID(tenOrg)}
	if err := e.d.Service.ConsumeTenancy(e.ctx, ev); err != nil {
		t.Fatal(err)
	}
	if err := e.d.Service.ConsumeTenancy(e.ctx, ev); err != nil { // a redelivery changes nothing
		t.Fatal(err)
	}
	removeAgain := e.d.Tenancy.Inject(tdouble.Fault{Status: http.StatusServiceUnavailable, Match: func(*http.Request) bool { return true }})
	defer removeAgain()
	var after gen.OfflinePack
	e.mustJSON(200, "GET", "/v1/devices/"+pos.ID+"/offline-packs/latest", tok, nil, &after)
	got := packClaims(after).Entitlements
	if got == nil || got.EntitlementsV != 3 || got.PlanKey == nil || *got.PlanKey != "table_service" || got.Limits["outlets"] != 1 ||
		got.OrganisationStatus != gen.EntitlementSnapshotOrganisationStatusActive || len(got.Features) != 4 || after.PackV <= down.PackV {
		t.Fatalf("after the event: v%d %+v", after.PackV, got)
	}
}
