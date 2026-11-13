-- Package pipeline and portal: what they need and §8.1 does
-- not already describe.
--
-- release, backup, access_grant and upgrade_job are NOT here: migration 001
-- created them empty for exactly this moment. This file adds only the three
-- new tables — portal credentials, CI tokens, and the record of a
-- transfer offer that has been made but not yet accepted.
--
-- The .tx. in the filename tells bun/migrate to run the whole file in one
-- transaction.

-- Portal login (design §8.4: control-plane identity, never a tenant's
-- PocketBase). D16 decided local accounts; were SSO ever added, the
-- credential source would change and this table empty, but nothing else moves.
CREATE TABLE principal_credential (
  principal_id  TEXT PRIMARY KEY REFERENCES principal(id),
  algo          TEXT NOT NULL,         -- argon2id
  hash          TEXT NOT NULL,         -- $argon2id$v=19$m=...,t=...,p=...$salt$digest
  updated_at    TIMESTAMP NOT NULL
);

-- API tokens for CLI and CI deploys. Bound to a principal — usually a
-- service_account — so a CI deploy has a real actor in the audit log rather
-- than an anonymous write.
CREATE TABLE api_token (
  id            TEXT PRIMARY KEY,
  principal_id  TEXT NOT NULL REFERENCES principal(id),
  name          TEXT NOT NULL,
  hash          TEXT NOT NULL,         -- sha256 of the secret half; the secret is shown once
  created_by    TEXT NOT NULL REFERENCES principal(id),
  created_at    TIMESTAMP NOT NULL,
  expires_at    TIMESTAMP NOT NULL,    -- every token expires, like every grant (§14.2)
  last_used_at  TIMESTAMP,
  revoked_by    TEXT REFERENCES principal(id),
  revoked_at    TIMESTAMP
);

CREATE INDEX api_token_active ON api_token(principal_id) WHERE revoked_at IS NULL;

-- A transfer offer. Ownership itself stays in tenant_owner: this table
-- holds the half-finished state between "the owner offered" and "the target
-- accepted", because §14.1 requires both sides on the record and a tenant is
-- never pushed onto someone who did not agree to be accountable for it.
CREATE TABLE owner_transfer (
  id             TEXT PRIMARY KEY,
  tenant_id      TEXT NOT NULL REFERENCES tenant(id),
  from_principal TEXT NOT NULL REFERENCES principal(id),
  to_principal   TEXT NOT NULL REFERENCES principal(id),
  offered_by     TEXT NOT NULL REFERENCES principal(id),
  offered_at     TIMESTAMP NOT NULL,
  expires_at     TIMESTAMP NOT NULL,   -- an unaccepted offer expires (§14.1)
  accepted_at    TIMESTAMP,
  declined_at    TIMESTAMP,
  cancelled_at   TIMESTAMP,
  reason         TEXT                  -- required for an operator-forced transfer
);

-- At most one open offer per tenant, enforced where it cannot be forgotten.
CREATE UNIQUE INDEX one_open_transfer_per_tenant ON owner_transfer(tenant_id)
  WHERE accepted_at IS NULL AND declined_at IS NULL AND cancelled_at IS NULL;
