-- Channels made in the app (1.9), and where every channel sits. A row with an
-- `entry` (ChannelEntry as JSON) is such a channel; without one it only places
-- a channel from channels.json. `conv` is the channel's log conversation id,
-- which survives a rename; ids of channels change at every start.
CREATE TABLE IF NOT EXISTS voipc_channels (
  conv VARCHAR(80) PRIMARY KEY,
  entry TEXT NULL,
  position INTEGER NOT NULL,
  category INTEGER NULL
);
CREATE TABLE IF NOT EXISTS voipc_categories (
  id INTEGER PRIMARY KEY,
  name VARCHAR(64) NOT NULL,
  position INTEGER NOT NULL
);
-- A group's colour (0xRRGGBB) and place in the server's order. No row, or no
-- position: after the ordered ones, by name.
CREATE TABLE IF NOT EXISTS voipc_group_style (
  role BLOB PRIMARY KEY REFERENCES acct_roles(id) ON DELETE CASCADE,
  color INTEGER NULL,
  position INTEGER NULL
);
-- How a member chose to be shown. Not l4f's display_name, which a provider sign-up
-- fills with a real name.
CREATE TABLE IF NOT EXISTS voipc_profiles (
  account BLOB NOT NULL PRIMARY KEY REFERENCES acct_users (id) ON DELETE CASCADE,
  display_name VARCHAR(64) NULL,
  picture_hash BLOB NULL,
  picture BLOB NULL
);
CREATE INDEX IF NOT EXISTS voipc_profiles_picture ON voipc_profiles (picture_hash);
-- Reusable invite links. The code itself is shown once and only its hash stays.
CREATE TABLE IF NOT EXISTS voipc_invite_links (
  hash BLOB NOT NULL PRIMARY KEY,
  max_uses INTEGER NOT NULL,
  uses INTEGER NOT NULL,
  expires_at BIGINT NULL,
  role_name VARCHAR(64) NULL,
  created_at BIGINT NOT NULL,
  created_by BLOB NULL REFERENCES acct_users (id) ON DELETE SET NULL
);
