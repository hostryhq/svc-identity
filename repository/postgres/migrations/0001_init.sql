-- svc-identity schema, forward-only. Identity is a document service (see repository.go): tenant-owned
-- documents live in records under row-level security keyed on app.tenant_id (ADR-0003 section 6);
-- service-global documents (accounts, challenges, refresh tokens, device index, vendor realm;
-- ADR-0003 A1.6) live in global_records and are never tenant data.

CREATE TABLE IF NOT EXISTS records (
  tenant_id  text        NOT NULL,
  kind       text        NOT NULL,
  id         text        NOT NULL,
  k1         text        NOT NULL DEFAULT '',
  k2         text        NOT NULL DEFAULT '',
  uniq       boolean     NOT NULL DEFAULT false,
  doc        jsonb       NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, kind, id)
);
CREATE INDEX IF NOT EXISTS records_k1 ON records (tenant_id, kind, k1) WHERE k1 <> '';
CREATE INDEX IF NOT EXISTS records_k2 ON records (tenant_id, kind, k2) WHERE k2 <> '';
CREATE UNIQUE INDEX IF NOT EXISTS records_uniq ON records (tenant_id, kind, k1) WHERE uniq AND k1 <> '';
ALTER TABLE records ENABLE ROW LEVEL SECURITY;
ALTER TABLE records FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON records;
CREATE POLICY tenant_isolation ON records
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

CREATE TABLE IF NOT EXISTS global_records (
  kind       text        NOT NULL,
  id         text        NOT NULL,
  k1         text        NOT NULL DEFAULT '',
  k2         text        NOT NULL DEFAULT '',
  uniq       boolean     NOT NULL DEFAULT false,
  doc        jsonb       NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (kind, id)
);
CREATE INDEX IF NOT EXISTS global_records_k1 ON global_records (kind, k1) WHERE k1 <> '';
CREATE INDEX IF NOT EXISTS global_records_k2 ON global_records (kind, k2) WHERE k2 <> '';
CREATE UNIQUE INDEX IF NOT EXISTS global_records_uniq ON global_records (kind, k1) WHERE uniq AND k1 <> '';

-- Append-only, hash-chained audit log (IC-28). The application role may INSERT and SELECT only.
-- tenant_id is a tenant id or the platform pseudo-tenant of the vendor log.
CREATE TABLE IF NOT EXISTS audit_log (
  seq       bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id text   NOT NULL,
  id        text   NOT NULL,
  doc       text   NOT NULL, -- exact bytes: the chain hashes them, and jsonb would renormalise
  prev_hash text   NOT NULL,
  hash      text   NOT NULL,
  UNIQUE (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS audit_log_tenant ON audit_log (tenant_id, seq);
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON audit_log;
CREATE POLICY tenant_isolation ON audit_log
  USING (tenant_id = current_setting('app.tenant_id', true) OR tenant_id = '00000000-0000-7000-8000-000000000000')
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true) OR tenant_id = '00000000-0000-7000-8000-000000000000');

-- go-auth's vendor access log (ADR-0013 V5): written in the request's own transaction.
CREATE TABLE IF NOT EXISTS vendor_access_log (
  id              uuid        PRIMARY KEY,
  at              timestamptz NOT NULL,
  tenant_id       text        NOT NULL DEFAULT '',
  vendor_user     text        NOT NULL,
  token_type      text        NOT NULL,
  support_session text        NOT NULL DEFAULT '',
  action_key      text        NOT NULL,
  target_id       text        NOT NULL DEFAULT '',
  ticket          text        NOT NULL DEFAULT '',
  outcome         text        NOT NULL,
  result_count    integer     NOT NULL DEFAULT 0,
  request_id      text        NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS idempotency_keys (
  tenant_id    text        NOT NULL,
  key          text        NOT NULL,
  fingerprint  text        NOT NULL,
  done         boolean     NOT NULL DEFAULT false,
  status       integer     NOT NULL DEFAULT 0,
  content_type text        NOT NULL DEFAULT '',
  body         bytea       NOT NULL DEFAULT ''::bytea,
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, key)
);

-- The application role. Production connects as a login role that is a member of identity_app;
-- development and tests connect as the compose superuser and SET ROLE to it so RLS applies.
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'identity_app') THEN
    CREATE ROLE identity_app NOLOGIN;
  END IF;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON records, global_records, idempotency_keys TO identity_app;
GRANT SELECT, INSERT ON audit_log, vendor_access_log TO identity_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO identity_app;
