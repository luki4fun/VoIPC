-- Who keeps a channel's log (accounts.rs `log`): the accounts its writers
-- wrap their keys to. An account is added only when it asks to be, while it
-- is in the channel, so this is the list of channels an account opted to
-- keep, as the relay learns it.
CREATE TABLE IF NOT EXISTS voipc_members (
  conv VARCHAR(80) NOT NULL,
  account BLOB NOT NULL REFERENCES acct_users (id) ON DELETE CASCADE,
  joined_at BIGINT NOT NULL,
  PRIMARY KEY (conv, account)
);
CREATE INDEX IF NOT EXISTS voipc_members_account ON voipc_members (account);
-- A member who joined after `owner` last wrapped its keys in `conv`: owner's
-- client answers next time it is here (its older keys, or only new ones).
CREATE TABLE IF NOT EXISTS voipc_pending (
  conv VARCHAR(80) NOT NULL,
  owner BLOB NOT NULL REFERENCES acct_users (id) ON DELETE CASCADE,
  recipient BLOB NOT NULL REFERENCES acct_users (id) ON DELETE CASCADE,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (conv, owner, recipient)
);
CREATE INDEX IF NOT EXISTS voipc_pending_owner ON voipc_pending (owner);
