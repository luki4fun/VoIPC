-- 1.12: two promises of the move that an order of steps broke (Round B, W1-31 and W1-34).

-- Lift ban on someone who deleted their own account (`own`): no later import bans them
-- again. Without it the next run made their banned row anew (W1-31). Only an `own` row needs
-- it: any other lifted ban is a row with `own` and `erase` off, which no ban passes.
ALTER TABLE voipc_import_excluded ADD COLUMN lifted BOOLEAN NOT NULL DEFAULT 0;

-- The Discord ids an account had linked and unlinked. Unlinking forgot the id, so deleting
-- the account after it took none of their imported posts (W1-34). Read only when the
-- account is deleted (`voipc_import_excluded`), and in its own data export; goes with it.
CREATE TABLE IF NOT EXISTS voipc_dc_unlinked (
  account BLOB NOT NULL REFERENCES acct_users (id) ON DELETE CASCADE,
  dc_id BIGINT NOT NULL,
  at BIGINT NOT NULL,
  PRIMARY KEY (account, dc_id)
);
