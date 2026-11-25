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
| `HOSTRY_TENANCY_URL`, `HOSTRY_SERVICE_SIGNING_KEY_FILE` | base URL of the tenancy service and identity's own service-token key (PEM PKCS#8 P-256, key id `identity`). Required outside dev/test/ci; without them (dev only) billing devices are issued no series and outlets are not checked |
| `HOSTRY_OP_SIGNING_PUB_FILE` | the sync gateway's op-signing public key, carried in packs |
| `HOSTRY_IDENTITY_SMS` / `..._ALLOW_TEST_SMS` | only `test` exists (no DLT-registered provider yet). It refuses to start unless `HOSTRY_ENV` is dev, test or ci **and** `ALLOW_TEST_SMS=1` |
| `HOSTRY_IDENTITY_DEV_CAPTURE` / `..._DEV_CLOCK` | `1` turns on the development aids of the end-to-end suite (E1 to E3): `GET /dev/otp/{mobile}` (last sign-in code), `GET /dev/mail/{email}` (last vendor setup link) and `GET/POST/DELETE /dev/clock` (`{"now": RFC 3339}` or `{"advance": "168h"}`; identity's clock only, so tokens issued while it is moved are not valid at other services). Not part of the API. Refused at start-up with the guard of the test SMS sender: `HOSTRY_ENV` dev, test or ci, `ALLOW_TEST_SMS=1` and `HOSTRY_IDENTITY_SMS=test` |
| `HOSTRY_IDENTITY_VENDOR_SIGNIN_CODE`, `..._VENDOR_RECOVERY` | `1` switches the vendor-assisted flows on (off by default) |
| `HOSTRY_NATS_URL`, `HOSTRY_NATS_SEED_FILE` | optional: relay the outbox to NATS; without it events stay in the outbox |

Missing or invalid settings are all reported together at start-up and the service does not start.

## Tests

```
go vet ./... && go test -race ./...                                   # unit, behaviour (over the double) and contract (double)
HOSTRY_PG_DSN=postgres://hostry:hostry-dev-only@127.0.0.1:55442/hostry?sslmode=disable \
  go test -race -tags integration ./integration/... ./contract/...    # on the infra dev stack (Postgres 17)
```

The contract suite reads the spec from `HOSTRY_API_SPECS` (a checkout root); unset, it uses the sibling `api-specs-p2`
checkout when present, else `api-specs`. The bus startup test (`cmd/svc-identity/main_bus_integration_test.go`,
`-tags integration`) starts NATS from `infra/dev/compose.yaml` under its own project and port (`HOSTRY_INFRA_DIR`,
`HOSTRY_EVENTS_DIR` override the sibling defaults; it skips without Docker) and needs the Postgres of `HOSTRY_PG_DSN`.

The contract suite (`contract/`) runs `api-specs/contracttest` once per operation in a fresh target, which the
harness puts into the operation's example world (`SeedWorld`, `contract/worlds.go`: base, session-open,
device-revoked, vendor-approval-pending and the rest of `info.x-example-worlds`), against the double and against
the service assembled over Postgres. Nothing is skipped. Tenancy's own double (`double.Options{WithTenancy: true}`,
`Double.Tenancy`) is the series registry in that run, in its matching world. `contract/contract.go` (`specGaps`) lists
the five operations whose example cannot be true as written and what the run does instead. The double is not a second
implementation: it composes the same `service` and `api` layers over the in-memory repository, a fake clock,
deterministic ids and a recording SMS sender.

## Known limits (Phase 1)

- No deployment, no image publishing, no staging configuration (ADR-0001 AM12).
- SMS: provider interface and a test sender only (DLT registration is not available). Email: setup links for vendor
  users created through the API are handed to a mail interface with no real implementation; use the CLI.
- Series come from tenancy (`internal/tenancyclient`, generated from the tenancy contract): a pos device is issued
  an active, a waiter a dormant series for the document types in `Config.SeriesDocTypes` (default `tax_invoice`) when
  it registers, and the codes are stored with the device and carried in its pack. A device whose outlet's tax
  registration is not verified registers with `billing_capability: none` and no series (the 409
  `registration_unverified` of tenancy is not surfaced); it is issued them on the pack fetch after verification. An
  outlet unknown to the caller's tenant is refused (422) for billing kinds; kinds with no billing (kds, hub,
  personal) are not checked, because tenancy has no internal outlet-existence route. The call is made inside the
  registration transaction, bounded by a 5 s timeout and one retry.
- Hub packs and the `store` claim (ADR-0002 A3.4, A3.5). A device of kind `hub` is activated like any other and its
  pack carries `HubPackClaims` (outlet's member ids with status and permissions, revoked device ids, identity keys,
  op-signing key; no names, PIN verifiers, salts, series, manual books or entitlements). Every pack's `device.credential`
  is the LAN credential: a compact ES256 JWS, header typ `hostry-cred+jws`, signed with the current identity (tenant
  realm) key, payload the sorted-key JSON of the credential plus `not_after` = `offline_valid_until` (unix seconds).
  The build declares `store` (`protected`, or `unprotected`; absent means `unprotected`) on `activateDevice` and
  `registerDevice`; it is recorded on the device row, signed into the credential and fixed for the life of the id.
  `unprotected` is refused with 422 `store.unprotected_refused` unless `HOSTRY_ENV` is dev, test or ci (checked before
  the code is spent). The browser build always declares `unprotected`, so live identity refuses it a pack.
- Vendor approval grants (`org_suspend`, `org_reinstate`, `org_close`, `tax_rule_set_publish`) follow ADR-0014 A2.6
  and verify under go-auth's `GrantVerifier` (round-trip test in `api/vendor_grant_test.go`; subject-hash vectors
  in `service/testdata`, a copy of api-specs `common/vendor-grant.vectors.v1.json` at feat/phase2-specs 1462fb8).
  `aud` is `tenancy` (org kinds) or `billing`; `org` is `platform` for `tax_rule_set_publish` (provisional, O2-9).
- Lost replies (security re-review, `idempotency.replay_secret`). A response that carries a secret is never stored,
  so a retry with the same `Idempotency-Key` is 409. Activation codes lapse after 10 minutes and the service can
  withdraw an unused one (`Service.RevokeActivationCode`; there is no route until the contract has one). A device
  whose activation reply was lost recovers with a device token and `getDeviceOfflinePack`, or by repeating the
  same activation (same id, key and code) under a new `Idempotency-Key`; it is never stranded. A sign-in code or
  a grant whose approval reply was lost is re-issued when the same approver approves again (fresh TOTP).
- Approval requests show the approver what the body would do (M8): role and member names, outlet counts and
  permission lists, never a secret, rendered at filing from an allow-list of fields (`service/approval_summary.go`).
- Request bodies are decoded strictly (unknown fields refused) but not validated against the full schema; required
  fields are checked where a rule needs them.
