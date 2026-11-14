-- 1.12, Round C: what the scale review found slow.

-- A deleted channel whose rows are still being taken, a batch at a time (W2-17). The channel
-- itself goes at once with this row; the rows follow in batches, so that no one statement holds
-- SQLite's single writer for long; a restart finishes what one cut short.
CREATE TABLE IF NOT EXISTS voipc_purging (
  conv VARCHAR(80) NOT NULL PRIMARY KEY,
  at BIGINT NOT NULL
);

-- What came from Discord, found by its message id (Round C, W2-3). The archive worker repeats
-- every delete wish at each pass, and without these each one walked a whole channel, or the
-- whole archive for a wish about every channel, holding the writer throughout: a pass over
-- 2 million rows with 600 wishes took 54 s and made other writers fail. A wish by anyone and a
-- span by id use (dc_id), one by its author (author_dc_id, dc_id), the archive_days cut
-- (channel, dc_id). The author index before this one is its first column alone.
CREATE INDEX IF NOT EXISTS voipc_archive_id ON voipc_archive (dc_id);
CREATE INDEX IF NOT EXISTS voipc_archive_channel_id ON voipc_archive (channel, dc_id);
CREATE INDEX IF NOT EXISTS voipc_archive_author_id ON voipc_archive (author_dc_id, dc_id) WHERE author_dc_id IS NOT NULL;
DROP INDEX IF EXISTS voipc_archive_author;

-- An account's direct conversations, where its id is the second in the name (`d:<lo>:<hi>`,
-- the hex from character 36): `log::index` at every connect read every direct row (Round C).
CREATE INDEX IF NOT EXISTS voipc_log_dm_second ON voipc_log ((substr(conv, 36)), conv, seq)
  WHERE conv >= 'd:' AND conv < 'd;';
