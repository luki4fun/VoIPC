-- pma-voice's server exports, answered by VoIPC.
--
-- `addChannelCheck` is the interesting one: it is where ESX and QBCore put
-- their job checks, and VoIPC has exactly the same hook, so this is a rename
-- rather than a translation. That check runs on *your* server and nowhere
-- else — the VoIPC relay is never told that radio channels exist.

local voipc = exports["fivem-voipc"]

local function channelName(n)
  if n == nil or n == 0 then return nil end
  return "pma:" .. tostring(n)
end

exports("setPlayerRadio", function(src, channel)
  return voipc:setPlayerRadioChannel(src, channelName(channel))
end)

exports("setPlayerCall", function(src, channel)
  voipc:setPlayerCallChannel(src, channel == 0 and nil or channel)
end)

exports("addChannelCheck", function(channel, fn)
  -- pma-voice hands the check the source only; VoIPC also passes the channel,
  -- and an extra argument a Lua function does not take is simply dropped.
  voipc:addChannelCheck(channelName(channel), fn)
end)

exports("removeChannelCheck", function(channel)
  voipc:removeChannelCheck(channelName(channel))
end)

exports("getPlayersInRadioChannel", function(channel)
  -- pma-voice returns a set keyed by server id; ours is a list.
  local out = {}
  for _, src in ipairs(voipc:getPlayersInRadioChannel(channelName(channel))) do
    out[src] = true
  end
  return out
end)

exports("getPlayersInCall", function(channel)
  local out = {}
  for _, src in ipairs(voipc:getPlayersInCall(channel)) do
    out[src] = true
  end
  return out
end)

--- The client half of `setCallChannel`, which pma-voice lets a client call.
RegisterNetEvent("voipc-pma:call", function(channel)
  if channel ~= nil and type(channel) ~= "number" and type(channel) ~= "string" then return end
  voipc:setPlayerCallChannel(source, channel == 0 and nil or channel)
end)
