-- The move from Discord (1.11). One run of the importer, by its guild's id: the relay is not
-- told the guild's name. Never deleted: an undo marks it, and `archive_done_at` says the
-- worker has taken what the run filed in the archive. `options`: ImportOptions as JSON.
-- `report`: counts and notes about what was imported, nothing about what was left out.
-- `archive_rows`: a running count, so an undo's preview needs no scan.
CREATE TABLE IF NOT EXISTS voipc_imports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  guild_id BIGINT NOT NULL,
  by_name VARCHAR(64) NOT NULL,
  started_at BIGINT NOT NULL,
  finished_at BIGINT NULL,
  undone_at BIGINT NULL,
  options TEXT NOT NULL,
  report TEXT NULL,
  backup TEXT NULL,
  archive_rows BIGINT NOT NULL DEFAULT 0,
  archive_done_at BIGINT NULL
);
-- What a run made that is not a group, by Discord's id. kind: 1 category, 2 channel, 3 emote.
-- local: the category's id, the conv, the emote's name. Only an insert: an existing row is
-- left alone, and keeps the run that made it.
CREATE TABLE IF NOT EXISTS voipc_import_items (
  kind SMALLINT NOT NULL,
  dc_id BIGINT NOT NULL,
  import_id BIGINT NOT NULL REFERENCES voipc_imports (id),
  local VARCHAR(80) NOT NULL,
  PRIMARY KEY (kind, dc_id)
);
CREATE INDEX IF NOT EXISTS voipc_import_items_run ON voipc_import_items (import_id);
-- How far each channel, thread and emote is read, per run, so undoing a delta falls back to
-- the run before. The highest of a uid's rows is its cursor. Never the highest id in the
-- archive: a deleted top row would come back on the next run.
CREATE TABLE IF NOT EXISTS voipc_import_cursors (
  uid BIGINT NOT NULL,
  import_id BIGINT NOT NULL REFERENCES voipc_imports (id),
  high BIGINT NOT NULL,
  PRIMARY KEY (uid, import_id)
);
-- An account the move knows, by its Discord id. `claimed_at` NULL: nobody has opened it, and
-- it goes after `unclaimed_days`. Set once opened, and stays set through `admin reclaim`.
-- `banned`: a disabled row holding the Discord id so its owner cannot sign up with it.
CREATE TABLE IF NOT EXISTS voipc_placeholders (
  account BLOB NOT NULL PRIMARY KEY REFERENCES acct_users (id) ON DELETE CASCADE,
  dc_id BIGINT NOT NULL UNIQUE,
  import_id BIGINT NOT NULL REFERENCES voipc_imports (id),
  banned BOOLEAN NOT NULL,
  joined_at BIGINT NULL,
  imported_at BIGINT NOT NULL,
  claimed_at BIGINT NULL
);
CREATE INDEX IF NOT EXISTS voipc_placeholders_open ON voipc_placeholders (banned, claimed_at, imported_at);
CREATE INDEX IF NOT EXISTS voipc_placeholders_import ON voipc_placeholders (import_id);
-- A group made from a Discord role. `power`: the twin holding what the role could do.
CREATE TABLE IF NOT EXISTS voipc_import_groups (
  role BLOB NOT NULL PRIMARY KEY REFERENCES acct_roles (id) ON DELETE CASCADE,
  dc_role_id BIGINT NOT NULL,
  power BOOLEAN NOT NULL,
  import_id BIGINT NOT NULL REFERENCES voipc_imports (id),
  UNIQUE (dc_role_id, power)
);
-- What a member held on Discord and waits for the owner to say yes to.
CREATE TABLE IF NOT EXISTS voipc_power_waiting (
  account BLOB NOT NULL REFERENCES acct_users (id) ON DELETE CASCADE,
  role BLOB NOT NULL REFERENCES acct_roles (id) ON DELETE CASCADE,
  PRIMARY KEY (account, role)
);
CREATE INDEX IF NOT EXISTS voipc_power_waiting_role ON voipc_power_waiting (role);
-- Discord ids no import touches. `own`: they deleted their account themselves, and nobody may
-- let them back in. `erase`: they asked to be out, or deleted their account: their posts go
-- and stay gone. FALSE: a lifted ban, or held while they link an old account: no account
-- is made, and their posts stay and keep arriving.
CREATE TABLE IF NOT EXISTS voipc_import_excluded (
  dc_id BIGINT NOT NULL PRIMARY KEY,
  own BOOLEAN NOT NULL,
  erase BOOLEAN NOT NULL,
  at BIGINT NOT NULL
);
-- What came from Discord: readable by this server, labelled as such, the one thing here that
-- is. `channel` is the Discord channel's id: the VoIPC channel is `c:dc-<channel>`. `thread` 0
-- is the channel's own flow. No `at`: a Discord id holds its millisecond. No foreign key: a
-- row names a Discord id, not an account. `author_dc_id` NULL: anonymised on the importer,
-- or a webhook's. `attachments`: names for a later backfill, never served.
CREATE TABLE IF NOT EXISTS voipc_archive (
  channel BIGINT NOT NULL,
  thread BIGINT NOT NULL DEFAULT 0,
  dc_id BIGINT NOT NULL,
  author_dc_id BIGINT NULL,
  author_name VARCHAR(64) NOT NULL,
  body TEXT NOT NULL,
  reply_to BIGINT NULL,
  reactions TEXT NULL,
  attachments TEXT NULL,
  thread_name VARCHAR(100) NULL,
  replies INTEGER NOT NULL DEFAULT 0,
  pinned BOOLEAN NOT NULL DEFAULT FALSE,
  import_id BIGINT NOT NULL,
  PRIMARY KEY (channel, thread, dc_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS voipc_archive_author ON voipc_archive (author_dc_id) WHERE author_dc_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS voipc_archive_pins ON voipc_archive (channel, dc_id) WHERE pinned = TRUE;
-- What people said about rows, which outlives them, an undo and a new import. An import obeys
-- it. `author_dc_id` 0: whoever wrote it. `channel` 0: every channel. `low`..`high`: Discord
-- ids, so one message, a time span or everything. `erase` FALSE: hidden from all but its author.
CREATE TABLE IF NOT EXISTS voipc_archive_wishes (
  author_dc_id BIGINT NOT NULL,
  channel BIGINT NOT NULL,
  low BIGINT NOT NULL,
  high BIGINT NOT NULL,
  erase BOOLEAN NOT NULL,
  at BIGINT NOT NULL,
  PRIMARY KEY (author_dc_id, channel, low, high)
);
-- The channel was private on Discord: only `*` may open its gate.
ALTER TABLE voipc_channels ADD COLUMN archive_private BOOLEAN NOT NULL DEFAULT FALSE;
