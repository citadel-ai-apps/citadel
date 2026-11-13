-- Session revocation and backup integrity.
--
-- session_epoch: portal sessions are signed cookies with no server-side row,
-- so until now signing out or changing a password left every copy of a cookie
-- valid for the rest of its TTL. Each cookie now carries the epoch it was
-- issued under; sign-out and a password change bump it, and a cookie from an
-- older epoch is refused.
--
-- sha256: a backup archive is checked against the digest recorded when it was
-- written before a restore decompresses it over a tenant's data.
--
-- The .tx. in the filename tells bun/migrate to run the whole file in one
-- transaction.

ALTER TABLE principal_credential ADD COLUMN session_epoch INTEGER NOT NULL DEFAULT 0;

ALTER TABLE backup ADD COLUMN sha256 TEXT;
