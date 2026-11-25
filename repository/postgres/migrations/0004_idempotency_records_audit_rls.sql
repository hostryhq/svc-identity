-- SR-H4, CR M1: idempotency records move to go-common's idempotency_records (claim, business write
-- and result in one transaction; 24 h expiry; secret-bearing bodies are never stored). The old table
-- held bearer tokens, refresh tokens and one-time codes in plain text: its rows are purged now and the
-- table is dropped in the next release (expand/contract).
CREATE TABLE IF NOT EXISTS idempotency_records (
  tenant_id    text        NOT NULL,
  key          text        NOT NULL,
  fingerprint  text        NOT NULL,
  done         boolean     NOT NULL DEFAULT false,
  status       integer     NOT NULL DEFAULT 0,
  content_type text        NOT NULL DEFAULT '',
  body         bytea,
  body_sha256  text        NOT NULL DEFAULT '',
  created_at   timestamptz NOT NULL,
  expires_at   timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, key)
);
CREATE INDEX IF NOT EXISTS idempotency_records_expires ON idempotency_records (expires_at);
GRANT SELECT, INSERT, UPDATE, DELETE ON idempotency_records TO identity_app;
DELETE FROM idempotency_keys;
REVOKE INSERT, UPDATE ON idempotency_keys FROM identity_app;

-- CR M2: tenants cannot read or append the platform (vendor) audit chain, and vendor_access_log is
-- row-level secured on its tenant. The platform chain is reachable only inside a transaction that
-- raised app.platform, which the repository does for AppendAudit and ListAudit of the platform scope
-- and nowhere else.
DROP POLICY IF EXISTS tenant_isolation ON audit_log;
CREATE POLICY tenant_isolation ON audit_log
  USING (tenant_id = current_setting('app.tenant_id', true)
         OR (tenant_id = '00000000-0000-7000-8000-000000000000' AND current_setting('app.platform', true) = 'on'))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
         OR (tenant_id = '00000000-0000-7000-8000-000000000000' AND current_setting('app.platform', true) = 'on'));

ALTER TABLE vendor_access_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE vendor_access_log FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON vendor_access_log;
CREATE POLICY tenant_isolation ON vendor_access_log
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
