# svc-identity

The Hostry identity service: OTP login and sessions, devices and offline packs, members, roles and grant limits,
staff PIN with session proofs, new-device caution, the vendor realm (vendor users, support sessions, two-person
approvals) and the internal operations the sync gateway calls. It ships with its test double (`double/`).

Contract: `api-specs` `openapi/identity/v1` (source of truth). Decisions: ADR-0005 (A1, A2), ADR-0003 A1.6, ADR-0011,
ADR-0013. Which operations exist today: [docs/operations-status.md](docs/operations-status.md).

## Layout

```
cmd/svc-identity/   wiring only: serve | migrate | vendor bootstrap | vendor recover
cmd/gen/            reads the bundled spec and permissions.yaml, writes api/policy_gen.go and service/catalogue_gen.go
api/                controller layer: generated routes through go-auth's Guard, decoding, idempotency, problem mapping
service/            business rules; no HTTP, no SQL
repository/         persistence interface; memory/ (double, unit tests) and postgres/ (migrations in postgres/migrations)
double/             the in-memory test double: the same service and api layers over the memory repository
contract/           the api-specs contract suite run per operation against the double and against Postgres
integration/        tests on a real PostgreSQL (build tag integration)
internal/gen        generated server types (oapi-codegen v2.9.0); never hand-edited
```

Storage model: identity is a document service. Tenant documents sit in `records` under row-level security on
`app.tenant_id`; service-global documents (accounts, challenges, refresh tokens, device index, vendor realm;
ADR-0003 A1.6) sit in `global_records`. The audit log is append-only and hash-chained; events go to the
transactional outbox in the same transaction as the state change.

## Run

```
make gen                          # needs api-specs bundled: make bundle in ../api-specs
HOSTRY_ENV=dev HOSTRY_IDENTITY_DSN=postgres://... HOSTRY_IDENTITY_ALLOW_TEST_SMS=1 go run ./cmd/svc-identity migrate
HOSTRY_ENV=dev HOSTRY_IDENTITY_DSN=... HOSTRY_IDENTITY_ALLOW_TEST_SMS=1 go run ./cmd/svc-identity serve
go run ./cmd/svc-identity vendor bootstrap --email you@example.test    # prints a one-time setup token to the terminal
```

Local development needs an uncommitted `go.work` listing `.`, `../go-common`, `../go-auth` and `../api-specs`, and
`GOPRIVATE=github.com/hostryhq/*`.

## Configuration (environment only)

| Variable | Meaning |
|---|---|
| `HOSTRY_ENV` | `dev`, `test`, `ci` or a named environment. Required |
| `HOSTRY_IDENTITY_DSN` | Postgres DSN (a secret; reference the secret store, never commit) |
| `HOSTRY_IDENTITY_DB_ROLE` | dev only: `SET ROLE` to the application role when connecting as a superuser, so RLS applies |
| `HOSTRY_IDENTITY_LISTEN` | listen address, default `:8080` |
| `HOSTRY_IDENTITY_{TENANT,VENDOR,PACK}_KEY_FILE` | PEM PKCS#8 P-256 signing keys (required outside dev/test/ci) |
| `HOSTRY_IDENTITY_{MAC,PROOF,TOTP}_KEY_FILE` | base64 files, 32 random bytes each: keyed hashes, PIN proof-key encryption, TOTP encryption |
| `HOSTRY_SERVICE_KEYS_DIR` | service key registry: `<service>.pub.pem` public keys (ADR-0005 section 9) |
| `HOSTRY_OP_SIGNING_PUB_FILE` | the sync gateway's op-signing public key, carried in packs |
| `HOSTRY_IDENTITY_SMS` / `..._ALLOW_TEST_SMS` | only `test` exists (no DLT-registered provider yet). It refuses to start unless `HOSTRY_ENV` is dev, test or ci **and** `ALLOW_TEST_SMS=1` |
| `HOSTRY_IDENTITY_VENDOR_SIGNIN_CODE`, `..._VENDOR_RECOVERY` | `1` switches the vendor-assisted flows on (off by default) |
| `HOSTRY_NATS_URL`, `HOSTRY_NATS_SEED_FILE` | optional: relay the outbox to NATS; without it events stay in the outbox |

Missing or invalid settings are all reported together at start-up and the service does not start.

## Tests

```
go vet ./... && go test -race ./...                                   # unit, behaviour (over the double) and contract (double)
HOSTRY_PG_DSN=postgres://hostry:hostry-dev-only@127.0.0.1:55442/hostry?sslmode=disable \
  go test -race -tags integration ./integration/... ./contract/...    # on the infra dev stack (Postgres 17)
```

The contract suite (`contract/`) seeds a fresh target per operation and runs `api-specs/contracttest` for that
operation, against the double and against the service assembled over Postgres. The double is not a second
implementation: it composes the same `service` and `api` layers over the in-memory repository, a fake clock,
deterministic ids and a recording SMS sender.

## Known limits (Phase 1)

- No deployment, no image publishing, no staging configuration (ADR-0001 AM12).
- SMS: provider interface and a test sender only (DLT registration is not available). Email: setup links for vendor
  users created through the API are handed to a mail interface with no real implementation; use the CLI.
- The document-series registry belongs to tenancy: packs carry an empty `series` list and `registration_unverified`
  is not produced until the tenancy client exists. Outlets are not checked against tenancy.
- Request bodies are decoded strictly (unknown fields refused) but not validated against the full schema; required
  fields are checked where a rule needs them.
