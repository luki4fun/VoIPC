-- Server-only settings. Nothing in here is downloaded to a player.
--
-- `config.lua` is a `shared_script`, which means every player has a copy of it
-- on disk: a channel password in there is a password everybody already has.
-- The one below never leaves this machine except as a reply to a player the
-- server has decided belongs in the voice channel, and only at the moment
-- their client is about to join.
--
-- Keep the ingame channel **hidden and password-protected** in the VoIPC
-- server's `channels.json` (see channels.example.json). Hidden keeps it out of
-- everybody's channel list; the password is what actually refuses a join, and
-- with `routed` on, a game server posting route tables silences anyone it does
-- not list even if they do get in.

ServerConfig = {
  --- The password of the channel named in `Config.channel`. `nil` if that
  --- channel has none — which means anybody who learns its name can walk in.
  channelPassword = nil,

  --- May this player be in the voice channel at all? Runs on the server, on
  --- the client's request, before the password goes anywhere. The place for a
  --- whitelist, a "must be spawned in" check, or an anti-cheat verdict.
  mayUseVoice = function(_src)
    return true
  end,
}
