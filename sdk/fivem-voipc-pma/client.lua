-- pma-voice's client exports, answered by VoIPC.
--
-- ESX, QBCore, Qbox and the ox resources are not voice integrations of their
-- own: they call pma-voice or SaltyChat. So a server that already runs one of
-- those frameworks can switch to VoIPC by starting this resource and stopping
-- pma-voice, without touching a single framework script.
--
-- What is honest about the translation:
--
--   * pma-voice channels are integers, VoIPC's are any string. Numbers are
--     passed through as `"pma:<n>"`, so the two namespaces cannot collide with
--     a channel your own scripts set by name.
--   * pma-voice's `radioEnabled`, `micClicks` and submix properties describe a
--     mixer VoIPC does not have; they are accepted and logged once rather than
--     silently ignored, so nobody debugs a setting that was never going to do
--     anything. Every VoIPC radio preset squelches, which is the same effect
--     `micClicks` asks for.
--   * `toggleMutePlayer` has no equivalent: per-user volume in VoIPC is the
--     listener's own mixer, and a resource reaching into it would be exactly
--     the "a script muted me and I cannot tell why" the mixer exists to end.

local voipc = exports["fivem-voipc"]

--- pma-voice speaks in integers; 0 means "no channel".
local function channelName(n)
  if n == nil or n == 0 then return nil end
  return "pma:" .. tostring(n)
end

local warned = {}
local function warnOnce(what, why)
  if warned[what] then return end
  warned[what] = true
  print(("[voipc-pma] %s: %s"):format(what, why))
end

-- ── Radio ────────────────────────────────────────────────────────────────

exports("setRadioChannel", function(channel)
  voipc:setRadioChannel(channelName(channel))
end)
exports("SetRadioChannel", function(channel)
  voipc:setRadioChannel(channelName(channel))
end)

exports("addPlayerToRadio", function(channel)
  voipc:setRadioChannel(channelName(channel))
end)

exports("removePlayerFromRadio", function()
  voipc:setRadioChannel(nil)
end)

exports("setRadioVolume", function(_volume)
  warnOnce("setRadioVolume", "a radio's level is the listener's own fader in VoIPC's mixer")
end)

exports("setMicClickOnVolume", function(_v)
  warnOnce("setMicClickOnVolume", "every VoIPC radio preset squelches; the burst is part of the chain")
end)
exports("setMicClickOffVolume", function(_v)
  warnOnce("setMicClickOffVolume", "every VoIPC radio preset squelches; the burst is part of the chain")
end)

-- ── Calls ────────────────────────────────────────────────────────────────

exports("setCallChannel", function(channel)
  TriggerServerEvent("voipc-pma:call", channel)
end)
exports("SetCallChannel", function(channel)
  TriggerServerEvent("voipc-pma:call", channel)
end)

exports("addPlayerToCall", function(channel)
  TriggerServerEvent("voipc-pma:call", channel)
end)

exports("removePlayerFromCall", function()
  TriggerServerEvent("voipc-pma:call", nil)
end)

exports("setCallVolume", function(_volume)
  warnOnce("setCallVolume", "a call's level is the listener's own fader in VoIPC's mixer")
end)

-- ── Properties ───────────────────────────────────────────────────────────

--- The catch-all pma-voice grew, aliased twice for historical reasons.
local function setVoiceProperty(property, value)
  if property == "radioEnabled" then
    if value == false then voipc:setRadioChannel(nil) end
    return
  end
  if property == "micClicks" then
    warnOnce("micClicks", "every VoIPC radio preset squelches; the burst is part of the chain")
    return
  end
  warnOnce(tostring(property), "not a thing VoIPC has — see docs/GAMES.md")
end

exports("setVoiceProperty", setVoiceProperty)
exports("SetMumbleProperty", setVoiceProperty)
exports("SetTokoProperty", setVoiceProperty)

exports("toggleMutePlayer", function(_serverId)
  warnOnce(
    "toggleMutePlayer",
    "VoIPC's per-person volume belongs to the listener; a resource cannot reach into it"
  )
end)

exports("setVoiceRange", function(metres)
  voipc:setVoiceRange(metres)
end)

-- ── The state and events pma-voice publishes ─────────────────────────────
--
-- Scripts read these rather than calling anything, so a shim that did not
-- mirror them would work right up until something drew a radio icon.

RegisterNetEvent("voipc:radio:tx", function(_channel, _voipcId, _talking) end)

CreateThread(function()
  local wasTalking = false
  while true do
    Wait(100)
    local talking = LocalPlayer.state.voipc_talking == true
      and LocalPlayer.state.voipc_radio ~= nil
    if talking ~= wasTalking then
      wasTalking = talking
      LocalPlayer.state:set("radioActive", talking, true)
      TriggerEvent("pma-voice:radioActive", talking)
    end
    local channel = LocalPlayer.state.voipc_radio
    LocalPlayer.state:set("radioChannel", channel and tonumber(channel:match("^pma:(%d+)$")) or 0, true)
  end
end)
