-- Kept channel messages on chains and buckets (accounts/log.rs, protocol 21): rows the relay
-- cannot open. Direct conversations stay on voipc_wraps. Nothing here goes by recipient, in an
-- index or a foreign key: a row outlives the person it names, which is what makes that writer's
-- next post start a new chain, and they are found per writer (`log::walk`, voipc_tombstones).
-- One writer in one channel. `shares`: `SetHistorySharing` and the privilege, so a join tells
-- only them. `key_bytes`: what the rows below count against the quota, seat rows at half.
-- `open_bytes`: the other half of those of a chain not finished yet.
CREATE TABLE IF NOT EXISTS voipc_writers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  conv VARCHAR(80) NOT NULL,
  owner BLOB NOT NULL REFERENCES acct_users (id) ON DELETE CASCADE,
  newest_chain INTEGER NULL,
  shares BOOLEAN NOT NULL DEFAULT FALSE,
  hour BIGINT NOT NULL DEFAULT 0,
  new_this_hour INTEGER NOT NULL DEFAULT 0,
  last_post_hour BIGINT NOT NULL DEFAULT 0,
  key_bytes BIGINT NOT NULL DEFAULT 0,
  open_bytes BIGINT NOT NULL DEFAULT 0,
  UNIQUE (conv, owner)
);
CREATE INDEX IF NOT EXISTS voipc_writers_owner ON voipc_writers (owner);
-- One chain. `id` is the relay's, never reused; `chain` the wire's 20 bits, which every
-- context binds. `done`: its last frame came. `older`, `link`: the back-link of a writer who
-- shares.
CREATE TABLE IF NOT EXISTS voipc_chains (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  writer INTEGER NOT NULL REFERENCES voipc_writers (id) ON DELETE CASCADE,
  chain INTEGER NOT NULL,
  top SMALLINT NOT NULL,
  done BOOLEAN NOT NULL DEFAULT FALSE,
  self_wrap BLOB NOT NULL,
  older INTEGER NULL,
  link BLOB NULL,
  created_at BIGINT NOT NULL,
  UNIQUE (writer, chain)
);
-- A state wrapped to one reader, at the lowest index they ever held there. `dead`: they have
-- a new log key, or no account, and the row opens for nobody they are now. It still counts:
-- it says someone holds this chain.
CREATE TABLE IF NOT EXISTS voipc_chain_wraps (
  writer INTEGER NOT NULL REFERENCES voipc_writers (id) ON DELETE CASCADE,
  recipient BLOB NOT NULL,
  chain_id INTEGER NOT NULL,
  idx SMALLINT NOT NULL,
  wrapped BLOB NOT NULL,
  dead BOOLEAN NOT NULL DEFAULT FALSE,
  PRIMARY KEY (writer, recipient, chain_id)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS voipc_chain_steps (
  chain_id INTEGER NOT NULL REFERENCES voipc_chains (id) ON DELETE CASCADE,
  idx SMALLINT NOT NULL,
  sealed BLOB NOT NULL,
  PRIMARY KEY (chain_id, idx)
) WITHOUT ROWID;
-- A bucket key, wrapped to one person in one version of a bucket; the writer's own row holds
-- it for the writer's other devices.
CREATE TABLE IF NOT EXISTS voipc_seats (
  writer INTEGER NOT NULL REFERENCES voipc_writers (id) ON DELETE CASCADE,
  recipient BLOB NOT NULL,
  bucket BIGINT NOT NULL,
  version INTEGER NOT NULL,
  wrapped BLOB NOT NULL,
  dead BOOLEAN NOT NULL DEFAULT FALSE,
  PRIMARY KEY (writer, recipient, bucket, version)
) WITHOUT ROWID;
-- A chain's state, sealed to everyone in one version of a bucket.
CREATE TABLE IF NOT EXISTS voipc_seals (
  chain_id INTEGER NOT NULL REFERENCES voipc_chains (id) ON DELETE CASCADE,
  bucket BIGINT NOT NULL,
  version INTEGER NOT NULL,
  idx SMALLINT NOT NULL,
  sealed BLOB NOT NULL,
  PRIMARY KEY (chain_id, bucket, version)
) WITHOUT ROWID;
-- Who is in a version, in the writer's own word and for the writer alone. `chain_id`: the
-- chain it was made for: it goes with that chain if that is never finished.
CREATE TABLE IF NOT EXISTS voipc_bucket_lists (
  writer INTEGER NOT NULL REFERENCES voipc_writers (id) ON DELETE CASCADE,
  bucket BIGINT NOT NULL,
  version INTEGER NOT NULL,
  sealed BLOB NOT NULL,
  chain_id INTEGER NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (writer, bucket, version)
) WITHOUT ROWID;
-- A version's way down to the one before it, since everyone in it held that one.
CREATE TABLE IF NOT EXISTS voipc_bucket_links (
  writer INTEGER NOT NULL REFERENCES voipc_writers (id) ON DELETE CASCADE,
  bucket BIGINT NOT NULL,
  version INTEGER NOT NULL,
  old INTEGER NOT NULL,
  link BLOB NOT NULL,
  PRIMARY KEY (writer, bucket, version)
) WITHOUT ROWID;
-- A deleted account, until no row names it: rows it had in channels it had already left are
-- out of reach of anything but the sweep. No foreign key: the account is gone.
CREATE TABLE IF NOT EXISTS voipc_tombstones (
  account BLOB NOT NULL PRIMARY KEY,
  at BIGINT NOT NULL
);
-- The lowest entry a channel keeps, moved up by the sweep and never down.
CREATE TABLE IF NOT EXISTS voipc_log_floors (
  conv VARCHAR(80) NOT NULL PRIMARY KEY,
  floor BIGINT NOT NULL
);
-- Someone who left a channel's log holding a key in it: a seat there waits. `voipc_reseats`
-- counts how often they came back, across channels, since each time the wait doubles.
CREATE TABLE IF NOT EXISTS voipc_left (
  account BLOB NOT NULL REFERENCES acct_users (id) ON DELETE CASCADE,
  conv VARCHAR(80) NOT NULL,
  left_at BIGINT NOT NULL,
  PRIMARY KEY (account, conv)
);
CREATE TABLE IF NOT EXISTS voipc_reseats (
  account BLOB NOT NULL PRIMARY KEY REFERENCES acct_users (id) ON DELETE CASCADE,
  strikes INTEGER NOT NULL,
  last_at BIGINT NOT NULL
);
-- `used_bytes` reads an account's own wraps at every key frame.
CREATE INDEX IF NOT EXISTS voipc_wraps_owner ON voipc_wraps (owner);
-- A new log key owes a walk over every writer (`log::walk`): the last writer done, until it ends.
ALTER TABLE voipc_logkeys ADD COLUMN walk_after INTEGER NULL;
