-- 1.14: the group epoch key (docs/GROUP-KEY.md §9, accounts/gk.rs). Only stored groups are here:
-- `c:` ids on a relay with accounts. `r:` groups, and relays without accounts, keep it all in memory.
-- `b`, `v` and commit ids are random u64 bound as i64: compared for equality only, never ordered
-- in SQL. Epochs, joins (`j`), seeds and exit `seq` are counters. `seat`: a seat's 33-byte record
-- (§11.5); `m`: a member's 17-byte seat id; `maker`: a keyholder's seat id and KX (17 + 32).
--
-- A commit is stored in two steps (Round C keeps SQLite's single writer free): its material goes
-- in short transactions tagged with its `commit_id` while a `voipc_gk_pending` row names it, and
-- nothing reads a pending commit's rows; then one small transaction moves the head and deletes
-- that row. A commit that never got there is an orphan, swept by its tag.

-- A stored group's head. `incarnation`: the database's `gk_incarnation` when the group's
-- generation began; another one means a restore or the switch, and the group starts a new
-- generation. `exits_next`: the next exit's `seq`. `rolls`: postcard `SeedRolls`.
CREATE TABLE IF NOT EXISTS voipc_gk_groups (
  grp VARCHAR(140) NOT NULL PRIMARY KEY,
  kind SMALLINT NOT NULL,
  gen BLOB NOT NULL,
  gen_time BIGINT NOT NULL,
  incarnation BLOB NOT NULL,
  head_d BLOB NOT NULL,
  head_epoch BIGINT NOT NULL,
  head_join BIGINT NOT NULL,
  exits_next BIGINT NOT NULL,
  rolls BLOB NOT NULL,
  gated BOOLEAN NOT NULL,
  updated BIGINT NOT NULL
);
-- Every generation a group had, so none comes twice, and when each began.
CREATE TABLE IF NOT EXISTS voipc_gk_gens (
  grp VARCHAR(140) NOT NULL,
  gen BLOB NOT NULL,
  started BIGINT NOT NULL,
  PRIMARY KEY (grp, gen)
) WITHOUT ROWID;
-- The headers the relay keeps (§4.4), by digest. `keep`: why, a bit each; at 0 the sweep takes it.
CREATE TABLE IF NOT EXISTS voipc_gk_headers (
  grp VARCHAR(140) NOT NULL,
  d BLOB NOT NULL,
  gen BLOB NOT NULL,
  epoch BIGINT NOT NULL,
  j BIGINT NOT NULL,
  kind SMALLINT NOT NULL,
  time BIGINT NOT NULL,
  body BLOB NOT NULL,
  sig BLOB NOT NULL,
  keep BIGINT NOT NULL,
  PRIMARY KEY (grp, d)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS voipc_gk_headers_at ON voipc_gk_headers (grp, gen, epoch, j);
-- A seat in one generation. `b`: its bucket, NULL until the commit seating it is the head;
-- `next_b` and `next_commit`: where a commit not yet the head puts it. `dh`: its X25519 public
-- key. `seed`: the newest seed it holds. `account`: NULL for a connection's seat.
CREATE TABLE IF NOT EXISTS voipc_gk_seats (
  grp VARCHAR(140) NOT NULL,
  gen BLOB NOT NULL,
  seat BLOB NOT NULL,
  dh BLOB NOT NULL,
  b BIGINT NULL,
  next_b BIGINT NULL,
  next_commit BIGINT NULL,
  pool SMALLINT NOT NULL,
  seed BIGINT NOT NULL,
  last_use BIGINT NOT NULL,
  account BLOB NULL,
  PRIMARY KEY (grp, gen, seat)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS voipc_gk_seats_account ON voipc_gk_seats (account) WHERE account IS NOT NULL;
CREATE INDEX IF NOT EXISTS voipc_gk_seats_next ON voipc_gk_seats (grp, next_commit, b) WHERE next_commit IS NOT NULL;
-- A bucket version's seat list (§5.3): `seats` its records in list order. `via`: the version it
-- ratcheted from; `base_v`: the version a row or welcome reaches it by. `epoch_until`: the epoch
-- it stopped being current in.
CREATE TABLE IF NOT EXISTS voipc_gk_lists (
  grp VARCHAR(140) NOT NULL,
  gen BLOB NOT NULL,
  b BIGINT NOT NULL,
  v BIGINT NOT NULL,
  pool SMALLINT NOT NULL,
  via BIGINT NULL,
  base_v BIGINT NOT NULL,
  epoch_made BIGINT NOT NULL,
  epoch_until BIGINT NULL,
  seats BLOB NOT NULL,
  digest BLOB NOT NULL,
  current BOOLEAN NOT NULL DEFAULT FALSE,
  commit_id BIGINT NOT NULL,
  PRIMARY KEY (grp, gen, b, v)
) WITHOUT ROWID;
-- Queries name `current = TRUE` and select key columns only, so SQLite takes these indexes
-- over the primary key's (grp, gen) prefix even without ANALYZE (accounts/gk.rs).
CREATE INDEX IF NOT EXISTS voipc_gk_lists_current ON voipc_gk_lists (grp, gen, current);
CREATE INDEX IF NOT EXISTS voipc_gk_lists_commit ON voipc_gk_lists (grp, commit_id);
-- The lists that ended, by when: `lists_at` reads the ones current at an epoch from here and
-- the current index, never every list a generation kept.
CREATE INDEX IF NOT EXISTS voipc_gk_lists_until ON voipc_gk_lists (grp, gen, epoch_until, epoch_made) WHERE epoch_until IS NOT NULL;
-- Every version id a generation used (validator rule 16), with its bucket: a rebase takes over
-- its stale attempt's id only for the same bucket. `commit_id` only while its commit is pending,
-- so the index stays small.
CREATE TABLE IF NOT EXISTS voipc_gk_vids (
  grp VARCHAR(140) NOT NULL,
  gen BLOB NOT NULL,
  v BIGINT NOT NULL,
  b BIGINT NOT NULL,
  commit_id BIGINT NULL,
  PRIMARY KEY (grp, gen, v)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS voipc_gk_vids_pending ON voipc_gk_vids (grp, commit_id) WHERE commit_id IS NOT NULL;
-- A gated group's names, 90 days: `kind` 0 an `added` list, 1 a header carrying `removed`, 2 the
-- step before the oldest. `list`: postcard.
CREATE TABLE IF NOT EXISTS voipc_gk_names (
  grp VARCHAR(140) NOT NULL,
  gen BLOB NOT NULL,
  epoch BIGINT NOT NULL,
  j BIGINT NOT NULL,
  kind SMALLINT NOT NULL,
  time BIGINT NOT NULL,
  names_hash BLOB NOT NULL,
  list BLOB NOT NULL,
  PRIMARY KEY (grp, gen, epoch, j, kind)
) WITHOUT ROWID;
-- A welcome waiting for its seat: `kind` 0 a seat welcome to (b, v), 1 a seed welcome (no b, v).
-- `s`: its seed. `commit_id`: NULL for a seed-welcome page, which is no commit.
CREATE TABLE IF NOT EXISTS voipc_gk_welcomes (
  grp VARCHAR(140) NOT NULL,
  gen BLOB NOT NULL,
  seat BLOB NOT NULL,
  kind SMALLINT NOT NULL,
  s BIGINT NOT NULL,
  b BIGINT NULL,
  v BIGINT NULL,
  maker BLOB NOT NULL,
  bytes BLOB NOT NULL,
  made BIGINT NOT NULL,
  commit_id BIGINT NULL,
  PRIMARY KEY (grp, gen, seat, kind, s)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS voipc_gk_welcomes_commit ON voipc_gk_welcomes (grp, commit_id) WHERE commit_id IS NOT NULL;
-- A row seating one seat in one version. No index by commit: a commit's rows are all to versions
-- it made, so an orphan's are found through its lists. A row is read only while the commit that
-- wrote it owns the version's list.
CREATE TABLE IF NOT EXISTS voipc_gk_rows (
  grp VARCHAR(140) NOT NULL,
  gen BLOB NOT NULL,
  b BIGINT NOT NULL,
  v BIGINT NOT NULL,
  seat BLOB NOT NULL,
  s BIGINT NOT NULL,
  maker BLOB NOT NULL,
  bytes BLOB NOT NULL,
  epoch_made BIGINT NOT NULL,
  commit_id BIGINT NOT NULL,
  PRIMARY KEY (grp, gen, b, v, seat)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS voipc_gk_rows_seat ON voipc_gk_rows (grp, gen, seat);
-- An epoch key sealed to one version.
CREATE TABLE IF NOT EXISTS voipc_gk_seals (
  grp VARCHAR(140) NOT NULL,
  gen BLOB NOT NULL,
  epoch BIGINT NOT NULL,
  b BIGINT NOT NULL,
  v BIGINT NOT NULL,
  bytes BLOB NOT NULL,
  commit_id BIGINT NOT NULL,
  PRIMARY KEY (grp, gen, epoch, b, v)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS voipc_gk_seals_commit ON voipc_gk_seals (grp, commit_id);
-- An epoch's keyring: `j` 0 the sealed base, then one delta per Join.
CREATE TABLE IF NOT EXISTS voipc_gk_keyring (
  grp VARCHAR(140) NOT NULL,
  gen BLOB NOT NULL,
  epoch BIGINT NOT NULL,
  j BIGINT NOT NULL,
  bytes BLOB NOT NULL,
  commit_id BIGINT NOT NULL,
  PRIMARY KEY (grp, gen, epoch, j)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS voipc_gk_keyring_commit ON voipc_gk_keyring (grp, commit_id);
-- A KRK welcome to one keyholder, by its KX.
CREATE TABLE IF NOT EXISTS voipc_gk_krk (
  grp VARCHAR(140) NOT NULL,
  gen BLOB NOT NULL,
  epoch BIGINT NOT NULL,
  holder BLOB NOT NULL,
  maker BLOB NOT NULL,
  bytes BLOB NOT NULL,
  commit_id BIGINT NOT NULL,
  PRIMARY KEY (grp, gen, epoch, holder)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS voipc_gk_krk_commit ON voipc_gk_krk (grp, commit_id);
-- A commit whose material is written and whose head move is not.
CREATE TABLE IF NOT EXISTS voipc_gk_pending (
  grp VARCHAR(140) NOT NULL,
  commit_id BIGINT NOT NULL,
  started BIGINT NOT NULL,
  PRIMARY KEY (grp, commit_id)
) WITHOUT ROWID;
-- An exit not yet dealt with by a head, so an open batch outlives a restart.
CREATE TABLE IF NOT EXISTS voipc_gk_exits (
  grp VARCHAR(140) NOT NULL,
  seq BIGINT NOT NULL,
  gen BLOB NOT NULL,
  seat BLOB NOT NULL,
  cause SMALLINT NOT NULL,
  at BIGINT NOT NULL,
  PRIMARY KEY (grp, seq)
) WITHOUT ROWID;
-- A keyholder entry, by its KX: what outlives a restart. `missed`: postcard misses; `pair`: its
-- endorsed pair (postcard), for `KRK` welcomes to it while it is offline.
CREATE TABLE IF NOT EXISTS voipc_gk_holders (
  grp VARCHAR(140) NOT NULL,
  kx BLOB NOT NULL,
  m BLOB NOT NULL,
  device BLOB NULL,
  rank SMALLINT NOT NULL,
  last_online BIGINT NOT NULL,
  missed BLOB NOT NULL,
  pair BLOB NULL,
  PRIMARY KEY (grp, kx)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS voipc_gk_holders_m ON voipc_gk_holders (m, device);
-- A kept chain's start, sealed once under its epoch's key (C4). Goes with its chain.
CREATE TABLE IF NOT EXISTS voipc_gk_chains (
  chain_id INTEGER NOT NULL PRIMARY KEY REFERENCES voipc_chains (id) ON DELETE CASCADE,
  grp VARCHAR(140) NOT NULL,
  gen BLOB NOT NULL,
  epoch BIGINT NOT NULL,
  idx SMALLINT NOT NULL,
  sealed BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS voipc_gk_chains_epoch ON voipc_gk_chains (grp, gen, epoch);
-- An account's Kyber1024 kept key (`item.kept`) and its identity's signature over it: what a
-- sharer seals a newcomer's row of a gk chain's start to, beside the X25519 of the log keys.
CREATE TABLE IF NOT EXISTS voipc_log_kems (
  account BLOB NOT NULL PRIMARY KEY REFERENCES acct_users (id) ON DELETE CASCADE,
  kem BLOB NOT NULL,
  sig BLOB NOT NULL,
  updated_at BIGINT NOT NULL
);
-- An account's self-rows (`kind` 0) and history rows (1), per seed and seat. No foreign key: the
-- tombstone sweep takes them.
CREATE TABLE IF NOT EXISTS voipc_gk_self (
  grp VARCHAR(140) NOT NULL,
  account BLOB NOT NULL,
  gen BLOB NOT NULL,
  seed BIGINT NOT NULL,
  tag_sk BLOB NOT NULL,
  tag_sx BLOB NOT NULL,
  kind SMALLINT NOT NULL,
  sealed BLOB NOT NULL,
  PRIMARY KEY (grp, account, gen, seed, tag_sk, tag_sx, kind)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS voipc_gk_self_account ON voipc_gk_self (account);
-- An account's seat keys by counter `n`, signed by its identity key (origin 0x01); one current.
CREATE TABLE IF NOT EXISTS voipc_gk_seatkeys (
  account BLOB NOT NULL REFERENCES acct_users (id) ON DELETE CASCADE,
  n BIGINT NOT NULL,
  kem BLOB NOT NULL,
  dh BLOB NOT NULL,
  made BIGINT NOT NULL,
  sig BLOB NOT NULL,
  published BIGINT NOT NULL,
  current BOOLEAN NOT NULL,
  PRIMARY KEY (account, n)
);
CREATE UNIQUE INDEX IF NOT EXISTS voipc_gk_seatkeys_current ON voipc_gk_seatkeys (account) WHERE current;
-- How many rows on the owner's gk chains an answer owed to the recipient has had: a sharer's
-- rows to newcomers are not charged to its quota, and this bounds them (GK_ROWS_SLACK past its gk tops).
ALTER TABLE voipc_pending ADD COLUMN gk_rows INTEGER NOT NULL DEFAULT 0;
