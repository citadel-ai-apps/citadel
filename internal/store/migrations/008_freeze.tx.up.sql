-- Freeze (design §14.5).
--
-- An attestation that finds enforcement with no grant behind it is a security
-- incident, and the tenant's state is frozen until an operator has looked:
-- deploys, upgrades and grant changes are refused, so the configuration under
-- investigation does not move. Enforcement keeps failing closed — expired and
-- revoked grants still lapse — and nothing found is removed.
--
-- frozen_reason is non-NULL exactly while the tenant is frozen.

ALTER TABLE tenant ADD COLUMN frozen_reason TEXT;
ALTER TABLE tenant ADD COLUMN frozen_at TIMESTAMP;

-- The grants an attestation was diffed against, so the tenant's summary can
-- say who approved each access and when it lapses (§14.6) without re-reading
-- today's grant table, which would describe the present, not the report.
ALTER TABLE attestation ADD COLUMN grants_json TEXT;
