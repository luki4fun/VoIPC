-- Radio channels, phone calls, and the map of who is who.
--
-- All three live here rather than on the clients, for the same reason
-- pma-voice and SaltyChat put them here: a FiveM player state bag only
-- replicates to clients that have that player in scope, so a client cannot see
-- a radio partner or a caller on the other side of the map. The server can.
--
-- This is also where entitlement lives. `Config.canJoinRadio` is the hook a
-- framework fills in with its job check — and note where it is NOT: the VoIPC
-- server never learns that radio channels exist, let alone who is on which.
-- It relays encrypted audio to a channel and nothing else.
--
-- Trust model: a player can ask to join a radio channel, and can claim a VoIPC
-- id. The first goes through `canJoinRadio`. The second is checked for
-- uniqueness below — without that, claiming somebody else's id is how you get
-- their voice placed at your feet, or culled out of everyone's mix.

--- serverId -> VoIPC user id, and back.
local voipcOf = {}
local serverOf = {}

--- channel name -> { [serverId] = true }
local radios = {}
--- call id -> { [serverId] = true }. A group rather than a pair, because a
--- conference call is the same thing with three people in it, and because
--- pma-voice and SaltyChat both hand their callers a channel id rather than a
--- partner — a shim on top of a pair would have to invent one.
local calls = {}
--- serverId -> the call id they are in, so leaving is one lookup.
local callOf = {}

--- Set while a republish is already on its way, so a burst of registrations is
--- one replication rather than one each. `GlobalState` goes to every client,
--- and a client may trigger `voipc:register` as often as it likes.
local rosterQueued = false

local function publishRoster()
  if rosterQueued then return end
  rosterQueued = true
  SetTimeout(250, function()
    rosterQueued = false
    -- Replicated to every client regardless of scope, which is the whole point.
    local roster = {}
    for serverId, id in pairs(voipcOf) do
      roster[tostring(serverId)] = id
    end
    GlobalState.voipc = roster
  end)
end

-- ── Letting a player into the voice channel ──────────────────────────────
--
-- The channel is hidden and password-protected on the VoIPC server, and the
-- password lives in `server_config.lua` — a file no player downloads. A client
-- asks for it when its bridge page comes up; this decides whether that player
-- gets it.

--- serverId -> when we last answered them, so a client cannot ask in a loop.
local lastJoinAsk = {}
local JOIN_ASK_GAP = 5000

RegisterNetEvent("voipc:join", function()
  local src = source
  local now = GetGameTimer()
  if lastJoinAsk[src] and now - lastJoinAsk[src] < JOIN_ASK_GAP then
    return
  end
  lastJoinAsk[src] = now
  if not ServerConfig.mayUseVoice(src) then
    TriggerClientEvent("voipc:error", src, "you are not allowed in the voice channel")
    return
  end
  TriggerClientEvent("voipc:join", src, ServerConfig.channelPassword)
end)

-- ── Who is who ───────────────────────────────────────────────────────────

RegisterNetEvent("voipc:register", function(userId)
  local src = source
  if type(userId) ~= "number" or userId <= 0 or userId ~= math.floor(userId) then
    return
  end
  -- One VoIPC id, one player. A second claim is somebody trying to be heard
  -- as (or instead of) the player who really has it: VoIPC refuses an update
  -- that lists one id twice, so this would break the whole mix rather than
  -- just their own. Contradicting the old "you can only misreport yourself".
  local holder = serverOf[userId]
  if holder and holder ~= src then
    print(("[voipc] player %s claimed VoIPC id %d, which %s already has — ignored")
      :format(src, userId, holder))
    return
  end
  local previous = voipcOf[src]
  if previous == userId then
    return -- already registered; a client may send this as often as it likes
  end
  if previous then
    serverOf[previous] = nil
  end
  voipcOf[src] = userId
  serverOf[userId] = src
  Player(src).state:set("voipc", userId, true)
  publishRoster()
end)

-- ── Radio ────────────────────────────────────────────────────────────────

--- Per-channel entitlement checks, the shape pma-voice uses so the shim in
--- sdk/fivem-voipc-pma is a rename rather than a translation.
local channelChecks = {}

local function mayJoin(src, channel)
  local check = channelChecks[channel]
  if check and not check(src, channel) then
    return false
  end
  return Config.canJoinRadio(src, channel)
end

local function setRadioChannel(src, channel)
  for name, members in pairs(radios) do
    if members[src] then
      members[src] = nil
      -- Whoever was hearing them stops hearing them, keyed or not
      for member in pairs(members) do
        TriggerClientEvent("voipc:radio:tx", member, name, voipcOf[src], false)
      end
      if next(members) == nil then
        radios[name] = nil
      end
    end
  end
  if channel == nil then
    Player(src).state:set("voipc_radio", nil, true)
    return true
  end
  if not mayJoin(src, channel) then
    TriggerClientEvent("voipc:error", src, ("you may not use radio channel %s"):format(channel))
    Player(src).state:set("voipc_radio", nil, true)
    return false
  end
  radios[channel] = radios[channel] or {}
  radios[channel][src] = true
  Player(src).state:set("voipc_radio", channel, true)
  return true
end

--- The client asking for a channel itself (a radio prop, a menu). It still
--- goes through the same check a resource-side call does.
RegisterNetEvent("voipc:radio:join", function(channel)
  if channel ~= nil and type(channel) ~= "string" then return end
  setRadioChannel(source, channel)
end)

--- Keyed or unkeyed, fanned out to the rest of the channel. The listeners key
--- the radio layer by VoIPC id, so nobody needs the sender in scope.
RegisterNetEvent("voipc:radio:tx", function(talking)
  local src = source
  local channel = Player(src).state.voipc_radio
  if not channel or not radios[channel] or not radios[channel][src] then return end
  local id = voipcOf[src]
  if not id then return end
  for member in pairs(radios[channel]) do
    if member ~= src then
      TriggerClientEvent("voipc:radio:tx", member, channel, id, talking and true or false)
    end
  end
end)

-- ── Phone ────────────────────────────────────────────────────────────────

--- Everyone in a call, as VoIPC ids, to everyone in it. One message per member
--- carrying the others: the client keys its phone layers by VoIPC id, so
--- nobody needs anybody else streamed in.
local function publishCall(id)
  local members = calls[id]
  if not members then return end
  for src in pairs(members) do
    local others = {}
    for peer in pairs(members) do
      if peer ~= src and voipcOf[peer] then
        others[#others + 1] = voipcOf[peer]
      end
    end
    TriggerClientEvent("voipc:call", src, others)
  end
end

--- Put a player in a call, or (nil) take them out of the one they are in.
local function setCallChannel(src, id)
  local previous = callOf[src]
  if previous then
    callOf[src] = nil
    if calls[previous] then
      calls[previous][src] = nil
      if next(calls[previous]) == nil then
        calls[previous] = nil
      else
        publishCall(previous)
      end
    end
    TriggerClientEvent("voipc:call", src, {})
  end
  if id == nil then return end
  calls[id] = calls[id] or {}
  calls[id][src] = true
  callOf[src] = id
  publishCall(id)
end

--- The two-party shorthand: both into a call of their own.
local function setCall(a, b)
  if b == nil then
    setCallChannel(a, nil)
    return
  end
  local id = ("pair:%d:%d"):format(math.min(a, b), math.max(a, b))
  setCallChannel(a, id)
  setCallChannel(b, id)
end

-- ── Exports for your radio, phone and job resources ──────────────────────

--- exports["fivem-voipc"]:setPlayerRadioChannel(src, "police") — nil leaves.
exports("setPlayerRadioChannel", function(src, channel)
  return setRadioChannel(src, channel)
end)

--- exports["fivem-voipc"]:addChannelCheck("police", function(src) … end)
--- The same shape pma-voice has, so a framework's existing check drops in.
exports("addChannelCheck", function(channel, fn)
  channelChecks[channel] = fn
end)

exports("removeChannelCheck", function(channel)
  channelChecks[channel] = nil
end)

exports("getPlayersInRadioChannel", function(channel)
  local out = {}
  for src in pairs(radios[channel] or {}) do
    out[#out + 1] = src
  end
  return out
end)

--- exports["fivem-voipc"]:setPlayerCall(src, partnerSrc) — nil ends the call.
exports("setPlayerCall", function(src, partner)
  setCall(src, partner)
end)

--- exports["fivem-voipc"]:setPlayerCallChannel(src, id) — nil leaves.
--- Any value identifies a call; everyone given the same one hears each other.
exports("setPlayerCallChannel", function(src, id)
  setCallChannel(src, id)
end)

--- The same, for a *client* asking on its own behalf — which is what
--- pma-voice's `setCallChannel` export is, so the shim needs it. A call id is
--- guessable, so this one goes through `Config.canJoinCall`; the server-side
--- export above does not, because your own resource already decided.
exports("clientJoinCall", function(src, id)
  if id ~= nil and not Config.canJoinCall(src, id) then
    TriggerClientEvent("voipc:error", src, "you may not join that call")
    return false
  end
  setCallChannel(src, id)
  return true
end)

exports("getPlayersInCall", function(id)
  local out = {}
  for src in pairs(calls[id] or {}) do
    out[#out + 1] = src
  end
  return out
end)

exports("getVoipcId", function(src)
  return voipcOf[src]
end)

-- ── Leaving ──────────────────────────────────────────────────────────────
--
-- Last, because it calls both of the locals above: in Lua a local is only in
-- scope for what is written after it, and a handler placed earlier would find
-- a nil global at the moment somebody disconnects, which is the worst moment
-- to find out.

AddEventHandler("playerDropped", function()
  local src = source
  lastJoinAsk[src] = nil
  setRadioChannel(src, nil)
  setCallChannel(src, nil)
  local id = voipcOf[src]
  if id then
    serverOf[id] = nil
  end
  voipcOf[src] = nil
  Player(src).state:set("voipc", nil, true)
  publishRoster()
end)
