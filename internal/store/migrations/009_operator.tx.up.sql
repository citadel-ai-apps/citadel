-- Named operators (design §14.3).
--
-- Break-glass is the one path by which a person without host root reaches the
-- data of a tenant they hold no role on, so who may hold it has to be a fact
-- about the principal
-- rather than "whoever is at the root shell". Only a person can carry the
-- flag; the shared platform login names nobody (INV-16) and never does.
--
-- Set and cleared over the unix socket only (`citadel principal operator`),
-- and every change is an audit event, so the chain is the flag's history.

ALTER TABLE principal ADD COLUMN operator INTEGER NOT NULL DEFAULT 0;
