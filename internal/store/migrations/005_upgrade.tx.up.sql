-- Backups and independent upgrades (§11, §12).
--
-- upgrade_job and backup were both created by migration 001 and have been
-- sitting empty since; this file adds only the columns 001 could not foresee,
-- plus the indexes the new query shapes need.
--
-- Unlike 004, every statement here is a plain ADD COLUMN or CREATE INDEX. No
-- constraint changes, so the rename-old/create/copy/drop table rebuild that
-- 004 had to perform is not needed — SQLite's ALTER TABLE handles this case
-- directly.
--
-- The .tx. in the filename tells bun/migrate to run the whole file in one
-- transaction.

-- An image snapshot and a live logical snapshot are not the same artifact, and
-- the restore path must not have to guess from a filename.
--
--   image : the tenant was stopped; the file is a compressed copy of data.img.
--   files : the tenant kept serving; the file is a tar of a VACUUM INTO of
--           pb_data. §11 blesses exactly this for a routine backup of a busy
--           instance and nothing looser -- `cp` of a live WAL database stays
--           forbidden.
--
-- DEFAULT 'image' is correct for every existing row: until this migration the
-- only snapshot path stopped the container first.
ALTER TABLE backup ADD COLUMN format TEXT NOT NULL DEFAULT 'image';

-- The portal's per-tenant list and the reconciler's "when did this tenant last
-- get a routine backup?" question.
CREATE INDEX backup_tenant_recent ON backup(tenant_id, created_at DESC);

-- The retention sweep (§11). Partial, because a row with no retain_until is
-- kept forever by definition and never needs visiting.
CREATE INDEX backup_sweep ON backup(retain_until) WHERE retain_until IS NOT NULL;

-- upgrade_job gains what the job row could not previously answer: who asked,
-- whether the platform forced it at EOL, and the structured rehearsal report
-- shown to the tenant (§12). rehearsal stays as 001 wrote it -- the one-word
-- verdict -- because that is what the fleet view and the INV-6 interlock read;
-- rehearsal_json is the detail behind it.
ALTER TABLE upgrade_job ADD COLUMN requested_by TEXT REFERENCES principal(id);
ALTER TABLE upgrade_job ADD COLUMN forced INTEGER NOT NULL DEFAULT 0;
ALTER TABLE upgrade_job ADD COLUMN rehearsal_json TEXT;

-- Two states beyond 001's comment, which the column was always free enough to
-- carry:
--
--   blocked   : the compatibility gate refused. Nothing was touched, no
--               snapshot was taken, and the reason is in `log`. Terminal.
--   rehearsed : a rehearse-only run finished. Terminal, and deliberately not
--               `succeeded` -- nothing was upgraded.
--
-- The interlock that matters (INV-6) is "is there a non-terminal job?", so the
-- index below is what deploys and upgrades both consult.
CREATE INDEX upgrade_job_active ON upgrade_job(tenant_id)
  WHERE state NOT IN ('succeeded','failed','blocked','rehearsed');
CREATE INDEX upgrade_job_recent ON upgrade_job(tenant_id, created_at DESC);

-- EOL automation walks the registry by state every tick (§12).
CREATE INDEX runtime_version_state ON runtime_version(state);
