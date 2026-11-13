-- Audit chain v2 (design §14.4).
--
-- The v1 commitment covered seq, occurred_at, actor_id, action, subject_ref,
-- detail_json and prev_hash. It left out tenant_id, on_behalf_of, actor_kind,
-- source_ip, request_id and id, so somebody with database access could move a
-- platform read of a tenant's data out of that tenant's access log (§14.6) by
-- editing tenant_id, or erase the impersonation from an on_behalf_of, without
-- breaking a single hash. Rows written from here on commit to every column.
--
-- Existing rows keep hash_version 1 and keep verifying under the v1 rule, so
-- every anchor already written stays valid. Verification refuses a v1 row after
-- the first v2 row: the cutover happens once, and a row claiming the old rule
-- after it is a downgrade.
--
-- The .tx. in the filename tells bun/migrate to run the whole file in one
-- transaction.

ALTER TABLE audit_event ADD COLUMN hash_version INTEGER NOT NULL DEFAULT 1;

-- Anchors are evidence about the chain, and evidence that can be deleted from
-- the same database it constrains is only half the check. The on-disk copies
-- are the other half (auditlog.LoadAnchorFiles); these stop the accident and
-- the second writer, as audit_event's own triggers do.
CREATE TRIGGER audit_anchor_no_update BEFORE UPDATE ON audit_anchor
BEGIN
  SELECT RAISE(ABORT, 'audit_anchor is append-only');
END;

CREATE TRIGGER audit_anchor_no_delete BEFORE DELETE ON audit_anchor
BEGIN
  SELECT RAISE(ABORT, 'audit_anchor is append-only');
END;
