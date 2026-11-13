-- Control-plane schema, transcribed from docs/design.md §8.1.
--
-- Tables not written at this point (release, upgrade_job, backup,
-- access_grant, audit_anchor, attestation) are created now anyway: they cost
-- nothing empty, and adding them later would mean a migration running against
-- live tenants.
--
-- This DDL is the source of truth for table and column names. The bun models in
-- this package must mirror it exactly, including the singular table names — bun
-- would otherwise pluralise "tenant" to "tenants" by default.
--
-- The .tx. in the filename tells bun/migrate to run the whole file in one
-- transaction.

CREATE TABLE runtime_version (
  version         TEXT PRIMARY KEY,      -- "0.40.4"
  hardening_rev   INTEGER NOT NULL,
  image_digest    TEXT NOT NULL,         -- sha256:..., never a tag
  state           TEXT NOT NULL,         -- current | supported | deprecated | eol
  eol_at          TIMESTAMP,
  release_notes   TEXT,
  created_at      TIMESTAMP NOT NULL
);

CREATE TABLE principal (
  id                TEXT PRIMARY KEY,
  kind              TEXT NOT NULL,       -- person | service_account | platform
  external_id       TEXT,                -- IdP subject, for SSO (D16 decided local accounts)
  email             TEXT,
  email_verified_at TIMESTAMP,
  display_name      TEXT NOT NULL,
  status            TEXT NOT NULL,       -- active | suspended | deleted
  created_at        TIMESTAMP NOT NULL
);

-- The platform itself is a principal (§14.1). Automated actions get a real
-- actor, and an orphaned tenant has somewhere to land while still having an owner.
-- strftime, not datetime: every TIMESTAMP in this database is RFC3339 text, and
-- datetime('now') would write a space-separated variant the models cannot parse.
INSERT INTO principal (id, kind, display_name, status, created_at)
VALUES ('platform', 'platform', 'citadel platform', 'active',
        strftime('%Y-%m-%dT%H:%M:%SZ', 'now'));

CREATE TABLE tenant (
  id              TEXT PRIMARY KEY,
  slug            TEXT NOT NULL UNIQUE,  -- becomes <slug>.apps.example.com
  hostname        TEXT NOT NULL UNIQUE,
  -- NO owner_id column. Ownership is tenant_owner + the current_owner view; a
  -- denormalised copy is a second source of truth for the one fact §14 exists
  -- to protect.
  owner_orphaned  INTEGER NOT NULL DEFAULT 0,
  desired_state   TEXT NOT NULL,         -- running | stopped | suspended | deleted
  runtime_version TEXT NOT NULL REFERENCES runtime_version(version),
  image_digest    TEXT NOT NULL,         -- pinned; changed ONLY by upgrade jobs
  current_release TEXT REFERENCES release(id),
  current_artifact TEXT,                 -- sha256 of app/current, until releases exist
  network_name    TEXT NOT NULL,         -- docker network, internal: true
  subnet          TEXT NOT NULL,         -- explicit /29, needed for firewall rules
  gateway_ip      TEXT NOT NULL,
  edge_ip         TEXT NOT NULL,         -- the edge proxy's address on this network
  container_ip    TEXT,                  -- static; assigned by the control plane
  egress_enabled  INTEGER NOT NULL DEFAULT 0,
  cpus            REAL NOT NULL DEFAULT 1.0,
  mem_mib         INTEGER NOT NULL DEFAULT 256,
  disk_mib        INTEGER NOT NULL DEFAULT 2048,
  body_cap        TEXT NOT NULL DEFAULT '32MB',
  -- Whether a destroyed tenant's data is discarded or kept.
  --
  -- Retention after deletion is D10: kept until an operator purges it (D10a:
  -- nothing auto-purges). The platform KEEPS the data image, the mount point and the
  -- encryption keys, and the reconciler reports the leftover directory as an
  -- orphan — a visible reminder rather than a silent loss. This flag records an
  -- operator explicitly asking for the opposite, so the reconciler (which owns
  -- teardown) acts on the same decision the API audited.
  purge_on_delete INTEGER NOT NULL DEFAULT 0,
  enc_key_ref     TEXT NOT NULL,
  created_at      TIMESTAMP NOT NULL
);

CREATE TABLE tenant_owner (              -- history, not current state
  id              TEXT PRIMARY KEY,
  tenant_id       TEXT NOT NULL REFERENCES tenant(id),
  principal_id    TEXT NOT NULL REFERENCES principal(id),
  role            TEXT NOT NULL,         -- owner | admin | deployer | viewer
  granted_by      TEXT NOT NULL REFERENCES principal(id),
  granted_at      TIMESTAMP NOT NULL,
  revoked_by      TEXT REFERENCES principal(id),
  revoked_at      TIMESTAMP
);

-- One active owner per tenant, enforced in SQL, which is the only place it cannot
-- be forgotten.
CREATE UNIQUE INDEX one_owner_per_tenant ON tenant_owner(tenant_id)
  WHERE role = 'owner' AND revoked_at IS NULL;

CREATE INDEX tenant_owner_by_principal ON tenant_owner(principal_id);

CREATE VIEW current_owner AS
  SELECT tenant_id, principal_id FROM tenant_owner
  WHERE role = 'owner' AND revoked_at IS NULL;

CREATE TABLE release (
  id              TEXT PRIMARY KEY,
  tenant_id       TEXT NOT NULL REFERENCES tenant(id),
  sha256          TEXT NOT NULL,
  manifest        TEXT NOT NULL,         -- raw pbapp.json
  pb_min          TEXT,
  pb_max          TEXT,
  egress_hosts    TEXT,                  -- JSON array; the REQUEST, never enforcement
  status          TEXT NOT NULL,         -- uploaded | validated | deployed | rolled_back | failed
  deployed_at     TIMESTAMP,
  created_at      TIMESTAMP NOT NULL
);

CREATE TABLE instance (
  tenant_id       TEXT PRIMARY KEY REFERENCES tenant(id),
  container_id    TEXT,
  observed_state  TEXT NOT NULL,         -- stopped | starting | healthy | unhealthy | failed
  running_digest  TEXT,
  restart_count   INTEGER NOT NULL DEFAULT 0,
  last_restart_at TIMESTAMP,
  last_health_at  TIMESTAMP,
  last_request_at TIMESTAMP,             -- drives scale-to-zero, once it exists
  last_error      TEXT,
  updated_at      TIMESTAMP NOT NULL
);

CREATE TABLE upgrade_job (
  id              TEXT PRIMARY KEY,
  tenant_id       TEXT NOT NULL REFERENCES tenant(id),
  from_version    TEXT NOT NULL,
  to_version      TEXT NOT NULL,
  snapshot_id     TEXT,
  rehearsal       TEXT,                  -- skipped | passed | failed
  state           TEXT NOT NULL,         -- pending | rehearsing | snapshotting | applying
                                         -- | verifying | succeeded | rolling_back | failed
  log             TEXT,
  created_at      TIMESTAMP NOT NULL,
  finished_at     TIMESTAMP
);

CREATE TABLE backup (
  id              TEXT PRIMARY KEY,
  tenant_id       TEXT NOT NULL REFERENCES tenant(id),
  kind            TEXT NOT NULL,         -- routine | pre_deploy | pre_upgrade | manual
  path            TEXT NOT NULL,
  size_bytes      INTEGER,
  pb_version      TEXT NOT NULL,         -- which binary wrote this data (restore gate)
  retain_until    TIMESTAMP,
  created_at      TIMESTAMP NOT NULL
);

-- Named access_grant, not grant: SQLite accepts `grant` as an identifier, but
-- GRANT is reserved in every other SQL dialect and in most tooling.
CREATE TABLE access_grant (              -- every capability crossing the sandbox boundary
  id              TEXT PRIMARY KEY,
  tenant_id       TEXT NOT NULL REFERENCES tenant(id),
  kind            TEXT NOT NULL,         -- egress_host | smtp_relay | object_storage
                                         -- | custom_domain | oauth_provider
                                         -- | operator_data_access | backup_export
                                         -- | log_access | support_impersonation
  direction       TEXT NOT NULL,         -- outbound | inbound
  subject         TEXT NOT NULL,
  tier            INTEGER NOT NULL,      -- 0 denied | 1 auto | 2 human | 3 break-glass
  decision        TEXT NOT NULL,         -- pending | auto_approved | approved
                                         -- | denied | expired | revoked
  requested_by    TEXT NOT NULL REFERENCES principal(id),
  requested_at    TIMESTAMP NOT NULL,
  decided_by      TEXT REFERENCES principal(id),
  decided_at      TIMESTAMP,
  policy_version  TEXT,
  justification   TEXT,
  evidence_ref    TEXT,
  expires_at      TIMESTAMP NOT NULL,
  revoked_by      TEXT REFERENCES principal(id),
  revoked_at      TIMESTAMP
);

CREATE INDEX grant_active ON access_grant(tenant_id, kind)
  WHERE decision IN ('auto_approved','approved') AND revoked_at IS NULL;

CREATE TABLE audit_event (
  seq             INTEGER PRIMARY KEY AUTOINCREMENT,  -- monotonic, chain order
  id              TEXT NOT NULL UNIQUE,
  occurred_at     TIMESTAMP NOT NULL,
  actor_id        TEXT NOT NULL REFERENCES principal(id),
  actor_kind      TEXT NOT NULL,         -- person | service_account | platform
  on_behalf_of    TEXT REFERENCES principal(id),
  -- Deliberately NOT a foreign key and never cascaded: a tenant row can be
  -- deleted, its audit rows must not follow (and D10 retention).
  tenant_id       TEXT,
  action          TEXT NOT NULL,         -- namespaced, e.g. tenant.provisioned
  subject_ref     TEXT,                  -- a reference, NEVER a payload (§14.4)
  detail_json     TEXT,
  request_id      TEXT,
  source_ip       TEXT,
  prev_hash       TEXT NOT NULL,
  hash            TEXT NOT NULL
);

CREATE INDEX audit_by_tenant ON audit_event(tenant_id, seq);
CREATE INDEX audit_by_actor  ON audit_event(actor_id, seq);
CREATE INDEX audit_by_action ON audit_event(action, seq);

-- Append-only. Enforced by the database, not only by convention:
-- internal/auditlog being the single writer is the first line, these are the
-- second, and they also stop an operator with a sqlite3 shell.
CREATE TRIGGER audit_event_no_update BEFORE UPDATE ON audit_event
BEGIN
  SELECT RAISE(ABORT, 'audit_event is append-only');
END;

CREATE TRIGGER audit_event_no_delete BEFORE DELETE ON audit_event
BEGIN
  SELECT RAISE(ABORT, 'audit_event is append-only');
END;

CREATE TABLE audit_anchor (              -- offsite tamper-evidence (§14.4)
  seq             INTEGER NOT NULL,
  head_hash       TEXT NOT NULL,
  signature       TEXT NOT NULL,
  anchored_at     TIMESTAMP NOT NULL,
  location        TEXT NOT NULL
);

CREATE TABLE attestation (               -- §14.5; host-derived, not DB-derived
  id              TEXT PRIMARY KEY,
  tenant_id       TEXT NOT NULL REFERENCES tenant(id),
  generated_at    TIMESTAMP NOT NULL,
  observed_json   TEXT NOT NULL,
  outcome         TEXT NOT NULL,         -- match | grant_without_enforcement
                                         -- | enforcement_without_grant
  mismatch_json   TEXT,
  signature       TEXT NOT NULL
);
