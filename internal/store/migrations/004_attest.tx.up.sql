-- Accountability capability (§14): notification, break-glass review, and
-- Tier-2 re-affirmation on transfer.
--
-- The two tables this phase most obviously needs -- attestation and
-- audit_anchor -- are NOT here. Migration 001 created them up front precisely
-- so that adding them later would not mean a migration running against live
-- tenants; this file adds only what 001 did not foresee.
--
-- The .tx. in the filename tells bun/migrate to run the whole file in one
-- transaction.

-- What the platform told someone, as opposed to what it recorded.
--
-- §14.6 turns on notification happening at GRANT time rather than at review
-- time: an operator opening a customer's database learns that the customer is
-- being told as it happens. An audit row alone cannot carry that property,
-- because nobody is obliged to read the audit log. This table is the read side
-- of the same transaction that writes the audit row, and it is deliberately a
-- separate table: audit_event is append-only (INV-18) and has exactly one
-- writer (§14.4), and a read_at column would be an UPDATE against it.
--
-- principal_id NULL means "everyone holding a role on this tenant", which is
-- how a tenant-facing notice reaches whoever is accountable today rather than
-- whoever was when it was written. tenant_id NULL is a platform-wide notice,
-- which is how the second operator hears about a break-glass session.
--
-- body is prose shown verbatim to the recipient. It carries no tenant payload
-- for the same reason detail_json does not (§14.4): these rows outlive the
-- data they describe.
-- No foreign key on tenant_id, deliberately. A notice about a tenant is the
-- record of what somebody was TOLD, and like the audit rows it describes it
-- must survive the tenant it names (§14.7): "we destroyed their data and we had
-- already told them an operator read it" is exactly the pair that has to remain
-- answerable after deletion. A reference here would instead make the deletion
-- fail, which is the worst of both.
CREATE TABLE notification (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT,
  principal_id  TEXT REFERENCES principal(id),
  audience      TEXT NOT NULL,          -- tenant | operator
  kind          TEXT NOT NULL,          -- grant.pending | grant.decided
                                        -- | breakglass.opened | breakglass.overdue
                                        -- | transfer.offered | grant.reaffirm_due
                                        -- | attestation.mismatch
  subject_ref   TEXT,                   -- a grant id, a transfer id: a reference
  body          TEXT NOT NULL,
  created_at    TIMESTAMP NOT NULL,
  read_at       TIMESTAMP
);

CREATE INDEX notification_feed ON notification(tenant_id, created_at DESC);
CREATE INDEX notification_unread ON notification(audience, created_at DESC)
  WHERE read_at IS NULL;

-- The review of a break-glass session (§14.3, Tier 3).
--
-- Separate from access_grant rather than a column on it because the review is a
-- second party's act at a later time, by someone other than the requester, and
-- because an unreviewed row is the thing that blocks further break-glass by the
-- same principal. Absence of a row is the block; that is easier to get right
-- than a nullable column nobody sets.
CREATE TABLE breakglass_review (
  grant_id      TEXT PRIMARY KEY REFERENCES access_grant(id),
  reviewed_by   TEXT NOT NULL REFERENCES principal(id),
  reviewed_at   TIMESTAMP NOT NULL,
  outcome       TEXT NOT NULL,          -- justified | unjustified
  notes         TEXT NOT NULL
);

-- Tier-2 grants inherited through an ownership transfer (§14.7).
--
-- A transfer must not silently carry grants: the person newly accountable for
-- an instance should have to look at what it can reach. An unaffirmed row past
-- due_at stops the grant being an input to the next ACL regeneration -- the
-- same "it stops being an input" mechanism expiry uses, not a separate
-- revocation path that could disagree with it.
CREATE TABLE grant_reaffirmation (
  grant_id      TEXT PRIMARY KEY REFERENCES access_grant(id),
  transfer_id   TEXT NOT NULL REFERENCES owner_transfer(id),
  due_at        TIMESTAMP NOT NULL,
  affirmed_by   TEXT REFERENCES principal(id),
  affirmed_at   TIMESTAMP
);

CREATE INDEX grant_reaffirmation_due ON grant_reaffirmation(due_at)
  WHERE affirmed_at IS NULL;


-- Rebuild `attestation` without its foreign key on tenant_id.
--
-- Migration 001 created the table ahead of the code, and gave it a reference to
-- tenant(id) by symmetry with every other tenant-scoped table. That is wrong
-- for this one: §14.7 keeps a tenant's FINAL attestation as the closing record
-- of what it could reach on the day it went away, so the report has to outlive
-- the row it names. With the reference in place, destroying a tenant that had
-- ever been attested failed on a constraint instead — the delete rolled back,
-- the tenant row survived teardown, and the next provision of the same slug hit
-- a unique-constraint error that said nothing about why.
--
-- Safe to rebuild rather than migrate in place: nothing wrote this table before
-- the attestation code existed, and the copy below carries any rows anyway.
ALTER TABLE attestation RENAME TO attestation_old;

CREATE TABLE attestation (
  id              TEXT PRIMARY KEY,
  tenant_id       TEXT NOT NULL,         -- no FK: outlives the tenant (§14.7)
  generated_at    TIMESTAMP NOT NULL,
  observed_json   TEXT NOT NULL,
  outcome         TEXT NOT NULL,         -- match | grant_without_enforcement
                                         -- | enforcement_without_grant
  mismatch_json   TEXT,
  signature       TEXT NOT NULL
);

INSERT INTO attestation SELECT * FROM attestation_old;
DROP TABLE attestation_old;

-- After the rebuild, not before: RENAME carries indexes with the old table.
-- The read path is always "this tenant's latest report" or "every mismatch,
-- newest first".
CREATE INDEX attestation_recent ON attestation(tenant_id, generated_at DESC);
CREATE INDEX attestation_mismatch ON attestation(generated_at DESC)
  WHERE outcome != 'match';
