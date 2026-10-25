-- The stored-message log (accounts.rs `log`): ciphertext only, filed by
-- conversation. What the relay learns from it is who wrote where and when.
-- An account's log key (public) and its identity's signature over it.
CREATE TABLE IF NOT EXISTS voipc_logkeys (
  account BLOB NOT NULL PRIMARY KEY REFERENCES acct_users (id) ON DELETE CASCADE,
  logkey BLOB NOT NULL,
  sig BLOB NOT NULL,
  updated_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS voipc_log (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  conv VARCHAR(80) NOT NULL,
  sender BLOB NOT NULL REFERENCES acct_users (id) ON DELETE CASCADE,
  epoch BIGINT NOT NULL,
  server_at BIGINT NOT NULL,
  keep_until BIGINT NOT NULL,
  ct BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS voipc_log_conv_seq ON voipc_log (conv, seq);
CREATE INDEX IF NOT EXISTS voipc_log_keep_until ON voipc_log (keep_until);
CREATE INDEX IF NOT EXISTS voipc_log_sender ON voipc_log (sender);
-- Each sender's epoch keys, wrapped to each member's log key.
CREATE TABLE IF NOT EXISTS voipc_wraps (
  conv VARCHAR(80) NOT NULL,
  owner BLOB NOT NULL REFERENCES acct_users (id) ON DELETE CASCADE,
  epoch BIGINT NOT NULL,
  recipient BLOB NOT NULL REFERENCES acct_users (id) ON DELETE CASCADE,
  wrapped BLOB NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (conv, owner, epoch, recipient)
);
CREATE INDEX IF NOT EXISTS voipc_wraps_recipient ON voipc_wraps (recipient, conv);
