-- The relay's own rows next to l4f-accounts' acct_* tables.
-- voipc_meta: relay_id, made once with the database.
CREATE TABLE IF NOT EXISTS voipc_meta (
  k VARCHAR(32) NOT NULL PRIMARY KEY,
  v BLOB NOT NULL
);
-- An account's long-term identity key (public half). The private half lives in
-- the account's vault, which only the account opens.
CREATE TABLE IF NOT EXISTS voipc_identity (
  account BLOB NOT NULL PRIMARY KEY REFERENCES acct_users (id) ON DELETE CASCADE,
  identity_key BLOB NOT NULL,
  updated_at BIGINT NOT NULL
);
