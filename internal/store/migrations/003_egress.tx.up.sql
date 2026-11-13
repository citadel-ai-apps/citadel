-- Egress enforcement: what ENFORCEMENT needs, as opposed to the egress
-- decision record migration 001 already carries in access_grant.
--
-- Nothing here is a second source of truth for a grant. access_grant remains the
-- only input to enforcement; these columns record where the enforcement
-- was applied and what it turned away.
--
-- The .tx. in the filename tells bun/migrate to run the whole file in one
-- transaction.

-- The tenant's static address on the egress network.
--
-- Explicit rather than Docker-assigned for the same reason tenant.subnet and
-- tenant.container_ip are (§8.1): the DOCKER-USER accept and the proxy's
-- source-IP ACL are both written against this address, so letting Docker pick
-- means the rules and the reality can drift apart silently.
--
-- NULL until the tenant's first active grant. It is not released when the last
-- grant goes: re-using an address a tenant recently held would make a stale
-- proxy log line attributable to the wrong tenant.
ALTER TABLE tenant ADD COLUMN egress_ip TEXT;

-- Operator quarantine (§10, §12): the edge returns 503 and the data is left
-- entirely alone. The alternative to a forced upgrade during a security
-- incident (D11).
ALTER TABLE tenant ADD COLUMN quarantined INTEGER NOT NULL DEFAULT 0;

-- Egress denials, aggregated per (tenant, host, port).
--
-- One row per denial would let a hook in a retry loop grow the control-plane
-- database without limit, which is a denial-of-service against the platform
-- reached from inside the sandbox. Aggregation makes the cost of a loop a
-- single UPDATE.
--
-- Note what is NOT stored: the reason. §9.4 requires four distinct reasons
-- (never requested, awaiting approval, denied — <reason>, expired on <date>),
-- and all four are derived from access_grant when the row is read. Copying the
-- reason in at denial time would let the displayed reason and the grant
-- decision disagree the moment an approver acts.
CREATE TABLE egress_denial (
  tenant_id     TEXT NOT NULL REFERENCES tenant(id),
  host          TEXT NOT NULL,
  port          INTEGER NOT NULL,
  hits          INTEGER NOT NULL DEFAULT 1,
  first_seen_at TIMESTAMP NOT NULL,
  last_seen_at  TIMESTAMP NOT NULL,
  PRIMARY KEY (tenant_id, host, port)
);

CREATE INDEX egress_denial_recent ON egress_denial(tenant_id, last_seen_at);
