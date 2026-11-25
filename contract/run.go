package contract

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/hostryhq/api-specs/contracttest"
	"github.com/hostryhq/svc-identity/service"
)

// SpecPath is the identity OpenAPI document of the api-specs checkout (HOSTRY_API_SPECS selects it). Without
// it the sibling api-specs-p2 checkout (the one go.work uses) is taken when present, else api-specs.
func SpecPath() string {
	const rel = "/openapi/identity/v1/openapi.yaml"
	if v := os.Getenv("HOSTRY_API_SPECS"); v != "" {
		return v + rel
	}
	if _, err := os.Stat("../../api-specs-p2" + rel); err == nil {
		return "../../api-specs-p2" + rel
	}
	return "../../api-specs" + rel
}

// Operation is one operation of the specification with what the run needs to know about it.
type Operation struct {
	ID, Path, Method string
	World            string // x-example-world, default base
	Class            string // caller class, see World.Header
}

// Operations loads the operations of the specification, sorted by operationId.
func Operations(t testing.TB) []Operation {
	t.Helper()
	l := openapi3.NewLoader()
	l.IsExternalRefsAllowed = true
	doc, err := l.LoadFromFile(SpecPath())
	if err != nil {
		t.Fatalf("load spec %s: %v", SpecPath(), err)
	}
	var ops []Operation
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			perm, _ := op.Extensions["x-permission"].(string)
			ops = append(ops, Operation{ID: op.OperationID, Path: path, Method: method, World: contracttest.WorldOf(op), Class: classOf(path, perm, op.OperationID)})
		}
	}
	sort.Slice(ops, func(i, j int) bool { return ops[i].ID < ops[j].ID })
	return ops
}

// classOf says who calls an operation: a public route takes no user credential (the vendor sign-in
// routes take the admin service token); getWipeOrder takes the drain token; the other internal routes
// are the vendor realm's (vendor token and admin service token) or the sync gateway's (service token);
// everything else is the organisation's owner.
func classOf(path, perm, op string) string {
	switch {
	case op == "getWipeOrder":
		return "drain"
	case perm == "public":
		return "public"
	case strings.HasPrefix(path, "/internal/v1/vendor/"):
		return "vendor"
	case strings.HasPrefix(path, "/internal/v1/"):
		return "sync"
	}
	return "tenant"
}

// configFor is the service configuration an operation's world assumes: the vendor-assisted flows its
// examples use are on (they are off by default in every real environment).
func configFor(Operation) func(*service.Config) {
	return func(c *service.Config) { c.SignInCodeEnabled, c.RecoveryEnabled = true, true }
}

// headerTransport adds the caller's credentials to each request at the moment it is sent.
type headerTransport struct {
	w            *World
	class, world string
}

func (t headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for k, vs := range t.w.Header(t.class, t.world) {
		for _, v := range vs {
			r.Header.Set(k, v)
		}
	}
	return http.DefaultTransport.RoundTrip(r)
}

// Run executes the contract suite once per operation, each in a fresh target built by newWorld and put
// into the operation's example world by the harness. Failures are reported per operation.
func Run(t *testing.T, newWorld func(t *testing.T, cfg func(*service.Config)) *World) {
	all := Operations(t)
	for _, op := range all {
		t.Run(op.ID, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t, configFor(op))
			w.op = op.ID
			srv := httptest.NewServer(w.D.Handler)
			defer srv.Close()
			skip := map[string]string{}
			for _, o := range all {
				if o.ID != op.ID {
					skip[o.ID] = "run in its own subtest"
				}
			}
			// Credentials are minted when each request is sent: a world may move the clock (a device revoked
			// ten minutes in) and tokens are short-lived.
			client := &http.Client{Transport: headerTransport{w: w, class: op.Class, world: op.World}}
			reports, err := contracttest.Verify(context.Background(), contracttest.Options{SpecPath: SpecPath(), BaseURL: srv.URL, Client: client,
				Skip: skip, SeedWorld: w.SeedWorld})
			if err != nil {
				t.Fatalf("contract setup: %v", err)
			}
			ran := false
			for _, r := range reports {
				if r.OperationID != op.ID && r.OperationID != "unknown-route" {
					continue
				}
				ran = ran || r.OperationID == op.ID
				for _, f := range r.Failures {
					t.Errorf("%s: %s", r.OperationID, f)
				}
			}
			if !ran {
				t.Errorf("%s was not run", op.ID)
			}
		})
	}
}
