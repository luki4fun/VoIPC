-- Who did what to whom (1.10). No foreign keys: a row outlives the accounts it names,
-- until `modlog_days` takes it. Names are copies, as anyone but an admin saw them; under
-- a pseudonym `target` stays NULL, so nothing here ties the two. `channel_key` is the
-- channel's log conversation id: ids of channels change at every start.
CREATE TABLE IF NOT EXISTS voipc_modlog (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at BIGINT NOT NULL,
  action VARCHAR(32) NOT NULL,
  actor BLOB NULL,
  actor_name VARCHAR(64) NOT NULL,
  target BLOB NULL,
  target_name VARCHAR(64) NOT NULL,
  channel_key VARCHAR(80) NULL,
  channel_name VARCHAR(64) NULL,
  reason VARCHAR(200) NOT NULL DEFAULT '',
  detail VARCHAR(255) NOT NULL DEFAULT '',
  since_ms BIGINT NULL,
  before_ms BIGINT NULL
);
CREATE INDEX IF NOT EXISTS voipc_modlog_at ON voipc_modlog (at);
CREATE INDEX IF NOT EXISTS voipc_modlog_action ON voipc_modlog (action, id);
CREATE INDEX IF NOT EXISTS voipc_modlog_actor ON voipc_modlog (actor, at);
-- The pseudonym behind a ban an admin made, whose label is the real name: what the
-- log, which others read, goes on calling them when the ban is lifted.
ALTER TABLE voipc_bans ADD COLUMN alias VARCHAR(64) NULL;
-- Who may not speak for now (restrict.rs): an account, or a keyed hash of a guest's
-- address, never the address. A row goes when it is lifted or runs out. `expires_at`
-- NULL: until lifted.
CREATE TABLE IF NOT EXISTS voipc_restrictions (
  addr_key BLOB UNIQUE,
  account BLOB UNIQUE REFERENCES acct_users (id) ON DELETE CASCADE,
  no_voice BOOLEAN NOT NULL,
  no_text BOOLEAN NOT NULL,
  by_name VARCHAR(64) NOT NULL,
  reason VARCHAR(200) NOT NULL,
  created_at BIGINT NOT NULL,
  expires_at BIGINT,
  CHECK ((addr_key IS NULL) <> (account IS NULL))
);
