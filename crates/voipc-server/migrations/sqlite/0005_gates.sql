-- Channel gates (gates.rs, 1.7) of channels from channels.json, under the
-- channel's log conversation id: the groups (account role names) that may
-- see and join it, and the ones that may speak there, space-separated. No row,
-- or an empty list: everyone.
CREATE TABLE IF NOT EXISTS voipc_gates (
  conv VARCHAR(64) PRIMARY KEY,
  may_join TEXT NOT NULL,
  may_speak TEXT NOT NULL
);
