# svc-identity. Local development uses an uncommitted go.work listing ../go-common and ../go-auth;
# private modules need GOPRIVATE=github.com/hostryhq/*.
SHELL := /bin/bash
API_SPECS ?= ../api-specs
OAPI_CODEGEN ?= $(API_SPECS)/.tools/bin/oapi-codegen
OAPI_CODEGEN_VERSION := v2.9.0
export GOPRIVATE ?= github.com/hostryhq/*

.PHONY: gen test vet lint integration contract-docker

# gen regenerates internal/gen (types and net/http server), api/policy_gen.go and
# service/catalogue_gen.go from api-specs, plus internal/gen/tenancy (the client of tenancy's series
# issuance route, from the tenancy contract), and records the api-specs commit in GEN_SOURCE.
# It needs a bundled spec: run `make bundle` in api-specs first (npx redocly).
gen:
	@test -f $(API_SPECS)/build/identity.yaml || (echo "run 'make bundle' in $(API_SPECS) first" && exit 1)
	$(OAPI_CODEGEN) -config oapi-codegen.yaml $(API_SPECS)/build/identity.yaml
	go run ./cmd/gen -spec $(API_SPECS)/build/identity.yaml -permissions $(API_SPECS)/common/permissions.yaml \
		-commit "$$(git -C $(API_SPECS) rev-parse HEAD)"
	$(OAPI_CODEGEN) -config oapi-codegen-tenancy.yaml $(API_SPECS)/build/tenancy.yaml
	git -C $(API_SPECS) rev-parse HEAD > GEN_SOURCE
	@echo "generated from api-specs $$(cat GEN_SOURCE) with oapi-codegen $(OAPI_CODEGEN_VERSION)"

vet:
	go vet ./...

test:
	go test -race ./...

# Integration tests need Postgres (see infra dev/compose.yaml): HOSTRY_PG_PORT selects the host port.
integration:
	go test -race -tags integration ./integration/... ./repository/postgres/...

lint:
	gofmt -l . | (! grep .)
	go vet ./...
