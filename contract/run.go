package contract

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/hostryhq/api-specs/contracttest"
	"github.com/hostryhq/svc-identity/service"
)

// SpecPath is the identity OpenAPI document of the api-specs checkout (HOSTRY_API_SPECS selects it).
func SpecPath() string {
	if v := os.Getenv("HOSTRY_API_SPECS"); v != "" {
		return v + "/openapi/identity/v1/openapi.yaml"
	}
	return "../../api-specs/openapi/identity/v1/openapi.yaml"
}

// SpecOperations lists the operationIds of the specification.
func SpecOperations(t testing.TB) []string {
	t.Helper()
	l := openapi3.NewLoader()
	l.IsExternalRefsAllowed = true
	doc, err := l.LoadFromFile(SpecPath())
	if err != nil {
		t.Fatalf("load spec %s: %v", SpecPath(), err)
	}
	var ops []string
	for _, item := range doc.Paths.Map() {
		for _, op := range item.Operations() {
			ops = append(ops, op.OperationID)
		}
	}
	sort.Strings(ops)
	return ops
}

// Run executes the contract suite once per operation against a fresh world built by newWorld.
// The result counts are logged: passed, failed and skipped (with reasons).
func Run(t *testing.T, newWorld func(t *testing.T, cfg func(*service.Config)) *World) {
	ops := SpecOperations(t)
	for _, op := range ops {
		if _, ok := Scenarios[op]; !ok {
			t.Errorf("operation %s has no contract scenario", op)
		}
	}
	for _, op := range ops {
		sc, ok := Scenarios[op]
		if !ok {
			continue
		}
		t.Run(op, func(t *testing.T) {
			if sc.Skip != "" {
				t.Skip(sc.Skip)
			}
			t.Parallel()
			ctx := context.Background()
			w := newWorld(t, sc.Config)
			if err := Common(ctx, w); err != nil {
				t.Fatalf("common seed: %v", err)
			}
			if sc.Seed != nil {
				sd := w.D.Service.Seed()
				if err := sc.Seed(ctx, w, sd); err != nil {
					t.Fatalf("scenario seed: %v", err)
				}
			}
			srv := httptest.NewServer(w.D.Handler)
			defer srv.Close()
			skip := map[string]string{}
			for _, o := range ops {
				if o != op {
					skip[o] = "run in its own subtest"
				}
			}
			reports, err := contracttest.Verify(ctx, contracttest.Options{SpecPath: SpecPath(), BaseURL: srv.URL, Client: http.DefaultClient, Header: w.Header(sc.Class), Skip: skip})
			if err != nil {
				t.Fatalf("contract setup: %v", err)
			}
			for _, r := range reports {
				if r.OperationID != op && r.OperationID != "unknown-route" {
					continue
				}
				for _, f := range r.Failures {
					t.Errorf("%s: %s", r.OperationID, f)
				}
			}
		})
	}
}
