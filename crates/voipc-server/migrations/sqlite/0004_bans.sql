-- Bans that outlive a restart (bans.rs). An address ban holds a keyed hash of
-- the address (an IPv4 address, or an IPv6 /64), never the address; an
-- account ban goes with its account. `expires_at` NULL = permanent.
CREATE TABLE IF NOT EXISTS voipc_bans (
  id BIGINT PRIMARY KEY,
  addr_key BLOB UNIQUE,
  account BLOB UNIQUE REFERENCES acct_users (id) ON DELETE CASCADE,
  label VARCHAR(64) NOT NULL,
  reason VARCHAR(200) NOT NULL,
  by_name VARCHAR(64) NOT NULL,
  created_at BIGINT NOT NULL,
  expires_at BIGINT,
  CHECK ((addr_key IS NULL) <> (account IS NULL))
);
