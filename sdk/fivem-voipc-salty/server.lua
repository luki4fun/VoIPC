-- SaltyChat's server exports, answered by VoIPC.
--
-- These are the ones frameworks and radio resources actually call. Anything
-- that models SaltyChat's own range system (towers, alive/dead) is accepted
-- and logged: VoIPC's ranges are per player and its culling is the mod's, so
-- those belong in the script that knows the world, not here.

local voipc = exports["fivem-voipc"]

local warned = {}
local function warnOnce(what, why)
  if warned[what] then return end
  warned[what] = true
  print(("[voipc-salty] %s: %s"):format(what, why))
end

-- ── Radio ────────────────────────────────────────────────────────────────

exports("SetPlayerRadioChannel", function(netId, name, isPrimary)
  if isPrimary == false then
    warnOnce("secondary radio", "VoIPC has one radio channel; the secondary is ignored")
    return
  end
  voipc:setPlayerRadioChannel(netId, name ~= "" and name or nil)
end)

exports("RemovePlayerRadioChannel", function(netId, _name)
  voipc:setPlayerRadioChannel(netId, nil)
end)

exports("GetPlayersInRadioChannel", function(name)
  return voipc:getPlayersInRadioChannel(name)
end)

exports("SetPlayerRadioSpeaker", function(_netId, _on)
  warnOnce(
    "SetPlayerRadioSpeaker",
    "in VoIPC a radio is a layer on the speaker's own voice, so people nearby hear it anyway"
  )
end)

-- ── Calls ────────────────────────────────────────────────────────────────

exports("AddPlayerToCall", function(callId, netId)
  voipc:setPlayerCallChannel(netId, callId)
end)

exports("AddPlayersToCall", function(callId, netIds)
  for _, netId in ipairs(netIds or {}) do
    voipc:setPlayerCallChannel(netId, callId)
  end
end)

exports("RemovePlayerFromCall", function(_callId, netId)
  voipc:setPlayerCallChannel(netId, nil)
end)

exports("RemovePlayersFromCall", function(_callId, netIds)
  for _, netId in ipairs(netIds or {}) do
    voipc:setPlayerCallChannel(netId, nil)
  end
end)

--- Deprecated upstream, still called by plenty of phone resources.
exports("EstablishCall", function(caller, partner)
  voipc:setPlayerCall(caller, partner)
end)

exports("EndCall", function(caller, _partner)
  voipc:setPlayerCallChannel(caller, nil)
end)

exports("SetPhoneSpeaker", function(_netId, _on)
  warnOnce("SetPhoneSpeaker", "a phone in VoIPC is a layer on the caller's voice, not a speaker")
end)

-- ── Range, alive, towers ─────────────────────────────────────────────────

exports("SetPlayerVoiceRange", function(netId, metres)
  TriggerClientEvent("voipc-salty:setVoiceRange", netId, metres)
end)

exports("GetPlayerVoiceRange", function(netId)
  return Player(netId).state.voipc_range or 8.0
end)

exports("SetPlayerAlive", function(_netId, _alive)
  warnOnce(
    "SetPlayerAlive",
    "VoIPC does not silence the dead; leave them out of the mod's `players` list instead"
  )
end)

exports("GetPlayerAlive", function(_netId) return true end)

exports("SetRadioTowers", function(_towers)
  warnOnce(
    "SetRadioTowers",
    "range in VoIPC is per player and culling is the mod's; put tower logic there"
  )
end)
