Config = {
  -- Where the VoIPC desktop client listens. Loopback only; the player turns
  -- it on in Settings → Game Integration.
  url = "ws://127.0.0.1:39987/",

  -- The VoIPC server your players are on. Required: a mod naming a different
  -- one is answered with wrong_server, so a player connected elsewhere cannot
  -- be placed with coordinates from this session.
  server = "rp.example.com:9987",

  -- Joined by name before VoIPC answers "ingame". Create it in the server's
  -- channels.json; the recommended entry is hidden, anonymous, without screen
  -- sharing and without a member list (see channels.example.json).
  channel = "Ingame",
  password = nil,

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
}
