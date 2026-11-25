-- Vendor access on organisation-less routes (ADR-0013 V5 item 3). A platform table: it has no tenant
-- column and no row-level security, so no pseudo-tenant is needed; the application role may only
-- insert and read.
CREATE TABLE IF NOT EXISTS platform_access_log (
  id              uuid        PRIMARY KEY,
  at              timestamptz NOT NULL,
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
GRANT SELECT, INSERT ON platform_access_log TO identity_app;
