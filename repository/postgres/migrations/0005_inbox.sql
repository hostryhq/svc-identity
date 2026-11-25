-- Consumer side of the bus (ADR-0011 B5), copied from go-common inbox.Schema: identity consumes
-- tenancy.vendor_access.recorded and billing.vendor_access.recorded (ADR-0005 A3.4).
CREATE TABLE IF NOT EXISTS inbox (
  consumer     text        NOT NULL,
  event_id     uuid        NOT NULL,
  processed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (consumer, event_id)
);
CREATE TABLE IF NOT EXISTS event_parked (
  id          bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  consumer    text        NOT NULL,
  event_id    text        NOT NULL,
  subject     text        NOT NULL,
  payload     bytea       NOT NULL,
  error       text        NOT NULL,
  attempts    bigint      NOT NULL,
  parked_at   timestamptz NOT NULL DEFAULT now(),
  resolved_at timestamptz
);

GRANT SELECT, INSERT, DELETE ON inbox TO identity_app;
GRANT SELECT, INSERT, UPDATE ON event_parked TO identity_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO identity_app;
