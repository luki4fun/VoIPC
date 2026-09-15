Config = {
  -- Where the VoIPC desktop client listens. Loopback only; the player turns
  -- it on in Settings → Game Integration.
  url = "ws://127.0.0.1:39987/",

  -- The VoIPC server your players are on. Required: a mod naming a different
  -- one is answered with wrong_server, so a player connected elsewhere cannot
  -- be placed with coordinates from this session.
  server = "rp.example.com:9987",

  -- Joined by name before VoIPC answers "ingame". Create it in the server's
  -- channels.json; the recommended entry is hidden, anonymous, password
  -- protected, without screen sharing and without a member list (see
  -- channels.example.json).
  --
  -- The channel's **password lives in `server_config.lua`**, not here: this
  -- file is a `shared_script`, so every player downloads it, and a password in
  -- a file everybody has protects nothing. The server hands it to a client
  -- when that client is about to join, and only if `mayUseVoice` says so.
  channel = "Ingame",

  -- Distance at which a voice becomes inaudible, per talk mode. SaltyChat's
  -- values, which is what players are used to.
  ranges = { 3.5, 8.0, 15.0 },
  rangeNames = { "whisper", "normal", "shout" },
  rangeKey = "F11",

  -- Update rate. VoIPC glides between updates, so faster buys nothing; the
  -- documented ceiling is 20 Hz.
  rateMs = 100,

  -- How muffled a voice is (0 clear … 10 through a wall).
  muffle = {
    noLineOfSight = 4,
    oneInVehicle = 4,
    otherRoom = 7,
  },

  -- ── Radio and phone ────────────────────────────────────────────────────
  --
  -- Both arrive as *layers*: an extra render of the same voice, so somebody
  -- talking into their radio two metres away is heard twice — over the air and
  -- as themselves. Any id from the VoIPC `modes` list works here.
  radioMode = "walkie",
  radioVolume = 0.9,
  phoneMode = "mobile",
  -- Which ear the phone is at: -1 left, 0 centred, 1 right.
  phoneEar = -0.9,
  radioKey = "CAPITAL",

  -- Hold the player's VoIPC push-to-talk while the radio key is down, so the
  -- radio key is the only key they hold. VoIPC ignores this unless the player
  -- has ticked "Let a game press my push-to-talk" in Settings → Game
  -- Integration, so leaving it on here is safe: it asks, it does not take.
  radioPressesPtt = true,

  --- May this player use this radio channel? The hook a framework fills in
  --- with its own job check — ESX `xPlayer.job.name`, QBCore `PlayerData.job`,
  --- whatever you already have. Runs on the server.
  ---
  --- This is the whole of radio entitlement, and it is deliberately here
  --- rather than on the VoIPC server: that one relays encrypted audio to a
  --- channel and never learns that radio channels exist at all.
  canJoinRadio = function(_src, _channel)
    return true
  end,

  --- May this player join this call, when the *client* asked to?
  ---
  --- Your own resources call `setPlayerCallChannel` on the server and never
  --- come through here. This is the client-side path the pma-voice shim has to
  --- answer, because pma-voice lets a client set its own call channel — and a
  --- call id is guessable (a phone resource that uses a phone number, say), so
  --- a cheat client that guesses one is in the call. Default true, which is
  --- what pma-voice itself does; make it a lookup against whoever your phone
  --- resource says is in that call and it stops being guessable.
  canJoinCall = function(_src, _id)
    return true
  end,
}
