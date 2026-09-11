-- SaltyChat's client exports, answered by VoIPC.
--
-- The point of this resource is that a server running SaltyChat can try VoIPC
-- without rewriting its radio, phone or job scripts: start this, stop
-- SaltyChat, and everything that called those exports keeps calling them.
-- Nobody has to install a TeamSpeak plugin, and there is no licence server.
--
-- Where the two models differ, honestly:
--
--   * **One radio, not two.** SaltyChat has a primary and a secondary channel.
--     VoIPC has one; a second would be a second radio layer, which is possible
--     but is not what `SetRadioChannel(name, false)` means to existing code.
--     The secondary is logged and dropped rather than quietly aliased onto the
--     primary, which would put somebody on a channel they did not ask for.
--   * **Volume belongs to the listener.** `SetRadioVolume` is a mixer fader in
--     VoIPC, and a resource does not get to move somebody's faders.
--   * **Every radio preset squelches**, so `SetMicClick(false)` cannot be
--     honoured — the burst is part of the chain that makes a radio sound like
--     a radio.
--   * **Radio towers and alive/dead** are SaltyChat's own range model. VoIPC
--     has range per player and culling by the mod, which is where a script
--     that wants those effects should put them.

local voipc = exports["fivem-voipc"]

local primary = nil
local warned = {}
local function warnOnce(what, why)
  if warned[what] then return end
  warned[what] = true
  print(("[voipc-salty] %s: %s"):format(what, why))
end

-- ── Radio ────────────────────────────────────────────────────────────────

exports("SetRadioChannel", function(name, isPrimary)
  if isPrimary == false then
    warnOnce("secondary radio", "VoIPC has one radio channel; the secondary is ignored")
    return
  end
  primary = name ~= "" and name or nil
  voipc:setRadioChannel(primary)
end)

exports("GetRadioChannel", function(isPrimary)
  if isPrimary == false then return nil end
  return primary
end)

exports("SetRadioVolume", function(_volume)
  warnOnce("SetRadioVolume", "a radio's level is the listener's own fader in VoIPC's mixer")
end)

exports("GetRadioVolume", function() return 1.0 end)

exports("SetRadioSpeaker", function(_on)
  warnOnce(
    "SetRadioSpeaker",
    "in VoIPC a radio is a layer on the speaker's own voice, so people nearby hear it anyway"
  )
end)

exports("GetRadioSpeaker", function() return true end)

exports("SetMicClick", function(_on)
  warnOnce("SetMicClick", "every VoIPC radio preset squelches; the burst is part of the chain")
end)

exports("GetMicClick", function() return true end)

-- ── Voice range ──────────────────────────────────────────────────────────

local range = nil

exports("SetVoiceRange", function(metres)
  range = metres
  voipc:setVoiceRange(metres)
end)

exports("GetVoiceRange", function()
  return range or LocalPlayer.state.voipc_range or 8.0
end)

-- ── The rest ─────────────────────────────────────────────────────────────

exports("GetPluginState", function()
  -- SaltyChat's states: 0 = not connected, 1 = connected, others are errors.
  -- There is no plugin here, so the honest answer is "connected".
  return 1
end)

exports("PlaySound", function(_handle, _loop, _name)
  warnOnce("PlaySound", "VoIPC has no sound bank; play it with the game's own audio")
end)

RegisterNetEvent("voipc-salty:setVoiceRange", function(metres)
  range = metres
  voipc:setVoiceRange(metres)
end)
