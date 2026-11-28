-- 1.14 (rc, dive 4): what a stored group's actor held in memory alone, kept for its next start
-- (docs/GROUP-KEY.md §9, accounts/gk.rs). 0013 is not edited: release candidates applied it.

-- An entry whose removal is proposed outright (its device was removed from its account, or its
-- account was banned, reset or deleted): a restart before another keyholder signs the Remove asks
-- it still. Goes with its row once the entry leaves the set.
ALTER TABLE voipc_gk_holders ADD COLUMN forced BOOLEAN NOT NULL DEFAULT FALSE;
-- An account's eager seat asked (a log join, a seat-key rotation, a new start's pages) and not yet
-- seated: `seat` the record its keys made. Gone once a Join seats it or the relay drops it; an
-- actor's start asks again those left whose account still keeps the log, with its current keys.
CREATE TABLE IF NOT EXISTS voipc_gk_eager (
  grp VARCHAR(140) NOT NULL,
  account BLOB NOT NULL,
  seat BLOB NOT NULL,
  at BIGINT NOT NULL,
  PRIMARY KEY (grp, account)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS voipc_gk_eager_account ON voipc_gk_eager (account);
-- Where a new start's eager pages are (`eager_all`): set with the head move of a new generation
-- (empty: from the first account), the last account asked after each page, NULL once all are
-- asked. An actor's start that finds it set asks the rest.
ALTER TABLE voipc_gk_groups ADD COLUMN eager_after BLOB NULL;
-- An exit of an account's seats in a group asked ahead of the group's actor (a log leave, a
-- gate or a new password, a kick or leave of the channel): `cause` the exit's, `at` when it was
-- asked. Gone once the exits it entered are written; an actor's start enters those left (dive 4
-- F7). A later ask of the account takes the row's place.
CREATE TABLE IF NOT EXISTS voipc_gk_exit_asks (
  grp VARCHAR(140) NOT NULL,
  account BLOB NOT NULL,
  cause SMALLINT NOT NULL,
  at BIGINT NOT NULL,
  PRIMARY KEY (grp, account)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS voipc_gk_exit_asks_account ON voipc_gk_exit_asks (account);
-- The generation the group's channel moved back onto (its id was another's meanwhile: an
-- anonymous or `hide_members` flip): while the head is still of it, the actor's start asks a
-- new generation, as the live relay does at once.
ALTER TABLE voipc_gk_groups ADD COLUMN moved_back BLOB NULL;
