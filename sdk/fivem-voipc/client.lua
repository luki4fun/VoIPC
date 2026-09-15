-- VoIPC proximity voice, client side.
--
-- Every tick this collects where the local player is looking and where the
-- other players are, and hands it to the NUI page, which pushes it to the
-- VoIPC client over its loopback WebSocket. VoIPC does the mixing.
--
-- Radio and phone are real here, not stubs. Both are **layers**: one speaker
-- can be heard twice at the same moment — over the radio in one ear, and as
-- themselves across the street — which is the thing no TeamSpeak plugin can
-- do. Membership lives on the server (see server.lua), because a player state
-- bag only reaches clients that have that player in scope, and the whole point
-- of a radio is that the other end is not in scope.
--
-- Still deliberately simple: the muffle heuristic knows about vehicles,
-- interiors and line of sight but nothing about doors or windows, which is
-- where a production script earns its keep, and `self.reverb` is never set
-- because the resource has no room data to derive it from.

local myVoipcId = nil
local rangeIndex = 2

--- VoIPC user id -> the radio channel we are hearing them on.
local RadioSpeakers = {}
--- VoIPC user ids of everyone else on our call, as a set. A group rather than
--- one id: a conference call is the same thing with more people in it.
local PhoneCall = {}
--- Are we keying our own radio right now?
local radioTalking = false
--- What this VoIPC build can render, from its `state` reply.
local capabilities = {}

local function can(feature)
  for _, name in ipairs(capabilities) do
    if name == feature then return true end
  end
  return false
end

-- ── Connecting ───────────────────────────────────────────────────────────

local function connect(password)
  SendNUIMessage({
    type = "connect",
    url = Config.url,
    hello = {
      type = "hello",
      sdk = 1,
      game = "fivem",
      resource = GetCurrentResourceName(),
      server = Config.server,
      channel = Config.channel,
      password = password,
    },
  })
end

-- The NUI page says when its message listener is live. Sending `connect`
-- before that (the page loads asynchronously) would be dropped silently, and
-- the resource would sit there doing nothing.
--
-- The channel's password is asked for here rather than read from `Config`:
-- this file's config is a `shared_script`, downloaded to every player, so a
-- password in it is a password everybody has. The server answers with it once,
-- for a player it lets into the channel at all.
RegisterNUICallback("ready", function(_, cb)
  cb({})
  TriggerServerEvent("voipc:join")
end)

RegisterNetEvent("voipc:join", function(password)
  if password ~= nil and type(password) ~= "string" then return end
  connect(password)
end)

AddEventHandler("onClientResourceStop", function(resource)
  if resource ~= GetCurrentResourceName() then return end
  SendNUIMessage({ type = "bye" })
end)

-- VoIPC's reply to `hello`, forwarded by the page.
RegisterNUICallback("state", function(data, cb)
  cb({})
  if data.capabilities then capabilities = data.capabilities end
  if data.state == "ingame" then
    myVoipcId = data.user_id
    -- Publish it so every other player can address us; the game server does
    -- the replicating, exactly as SaltyChat and YACA rely on their own netcode
    TriggerServerEvent("voipc:register", myVoipcId)
    print(("[voipc] in channel %s as %s (%s)"):format(
      tostring(data.channel), tostring(data.username), table.concat(capabilities, ",")))
    if not can("layers") then
      print("[voipc] this VoIPC is older than layers: a radio or a call will replace " ..
        "the speaker's own voice instead of arriving beside it")
    end
  elseif data.state == "disconnected" then
    print("[voipc] VoIPC is not connected to a server — ask the player to connect to " .. Config.server)
  elseif data.state == "wrong_server" then
    print("[voipc] VoIPC is connected to a different server than " .. Config.server)
  end
end)

-- Speaking and mute pushes. `talk` is somebody else, `self` is us.
RegisterNUICallback("talk", function(data, cb)
  cb({})
  if data.type == "talk" then
    TriggerEvent("voipc:talking", data.user_id, data.speaking)
  elseif data.type == "self" then
    -- Replicated, so other clients can draw an overlay over our head
    LocalPlayer.state:set("voipc_talking", data.speaking, true)
  end
end)

RegisterNUICallback("error", function(data, cb)
  cb({})
  print("[voipc] " .. tostring(data.reason))
end)

RegisterNetEvent("voipc:error", function(reason)
  print("[voipc] " .. tostring(reason))
end)

-- ── Voice range ──────────────────────────────────────────────────────────

local function setVoiceRange(index)
  rangeIndex = index
  local range = Config.ranges[rangeIndex]
  -- Replicated, so the others know how far we carry
  LocalPlayer.state:set("voipc_range", range, true)
  BeginTextCommandThefeedPost("STRING")
  AddTextComponentSubstringPlayerName(("Voice range: %s (%.1f m)"):format(
    Config.rangeNames[rangeIndex], range))
  EndTextCommandThefeedPostTicker(false, false)
end

RegisterCommand("voicerange", function()
  setVoiceRange(rangeIndex % #Config.ranges + 1)
end, false)
RegisterKeyMapping("voicerange", "Change voice range", "keyboard", Config.rangeKey)

-- ── Radio and phone ──────────────────────────────────────────────────────

--- The server tells us who is keyed on a channel we are on. Keyed by VoIPC id
--- rather than server id, because the speaker need not be in scope at all.
RegisterNetEvent("voipc:radio:tx", function(_channel, voipcId, talking)
  if type(voipcId) ~= "number" then return end
  RadioSpeakers[voipcId] = talking and true or nil
end)

RegisterNetEvent("voipc:call", function(voipcIds)
  PhoneCall = {}
  for _, id in ipairs(voipcIds or {}) do
    PhoneCall[id] = true
  end
end)

local function setRadioTalking(on)
  on = on and true or false
  if on == radioTalking then return end
  radioTalking = on
  TriggerServerEvent("voipc:radio:tx", on)
  -- Hold the player's push-to-talk while the radio key is down, so the radio
  -- key is the only key they hold. VoIPC refuses this unless the player has
  -- allowed it in Settings, which is why it is safe to send unconditionally.
  if Config.radioPressesPtt then
    SendNUIMessage({ type = "transmit", on = on })
  end
end

RegisterCommand("+voipc_radio", function() setRadioTalking(true) end, false)
RegisterCommand("-voipc_radio", function() setRadioTalking(false) end, false)
RegisterKeyMapping("+voipc_radio", "Talk on the radio", "keyboard", Config.radioKey)

--- exports["fivem-voipc"]:setRadioChannel("police") — nil leaves the channel.
--- The server decides whether we may: see `Config.canJoinRadio`.
exports("setRadioChannel", function(channel)
  setRadioTalking(false)
  TriggerServerEvent("voipc:radio:join", channel)
end)

exports("setRadioTalking", setRadioTalking)
exports("setVoiceRange", function(metres)
  for i, r in ipairs(Config.ranges) do
    if math.abs(r - metres) < 0.01 then setVoiceRange(i) return end
  end
end)
exports("getVoipcId", function() return myVoipcId end)

-- ── Position updates ─────────────────────────────────────────────────────

--- How muffled `other` sounds from `me`, 0..10.
local function muffleBetween(me, other)
  local myCar, theirCar = GetVehiclePedIsIn(me, false), GetVehiclePedIsIn(other, false)
  if myCar ~= 0 and myCar == theirCar then
    return 0 -- same car, no wall between us
  end
  if (myCar ~= 0) ~= (theirCar ~= 0) then
    return Config.muffle.oneInVehicle
  end
  if GetRoomKeyFromEntity(me) ~= GetRoomKeyFromEntity(other)
    or GetInteriorFromEntity(me) ~= GetInteriorFromEntity(other) then
    return Config.muffle.otherRoom
  end
  if not HasEntityClearLosToEntity(me, other, 17) then
    return Config.muffle.noLineOfSight
  end
  return 0
end

--- The extra ways we are hearing this player right now, if any.
local function layersFor(voipcId)
  local layers = nil
  if RadioSpeakers[voipcId] then
    layers = { { mode = Config.radioMode, volume = Config.radioVolume } }
  end
  if PhoneCall[voipcId] then
    layers = layers or {}
    layers[#layers + 1] = { mode = Config.phoneMode, pan = Config.phoneEar }
  end
  return layers
end

CreateThread(function()
  while true do
    Wait(Config.rateMs)
    if myVoipcId then
      local ped = PlayerPedId()
      -- The head bone, not the feet: the ear height is what a listener expects
      local head = GetPedBoneCoords(ped, 0x796e, 0.0, 0.0, 0.0)
      local players = {}
      local placed = {}
      -- Culled generously: a player VoIPC is not told about is silent, which
      -- is how distance culling works in every one of these plugins
      local cull = Config.ranges[#Config.ranges] * 1.5

      for _, player in ipairs(GetActivePlayers()) do
        local serverId = GetPlayerServerId(player)
        local id = Player(serverId).state.voipc
        if id and id ~= myVoipcId then
          local otherPed = GetPlayerPed(player)
          local pos = GetPedBoneCoords(otherPed, 0x796e, 0.0, 0.0, 0.0)
          if #(head - pos) <= cull then
            placed[id] = true
            players[#players + 1] = {
              id = id,
              pos = { pos.x, pos.y, pos.z },
              range = Player(serverId).state.voipc_range or Config.ranges[2],
              muffle = muffleBetween(ped, otherPed),
              layers = layersFor(id),
            }
          end
        end
      end

      -- Radio partners and the person on the phone, from the server's own
      -- roster rather than from the players the game streamed in: the other
      -- end of a radio is by definition somewhere you cannot see. Somebody
      -- both nearby and on the radio was handled above, and is not repeated —
      -- VoIPC refuses an update that lists one id twice.
      local roster = GlobalState.voipc or {}
      for _, id in pairs(roster) do
        if id ~= myVoipcId and not placed[id] then
          local layers = layersFor(id)
          if layers then
            if can("layers") then
              -- No position in our world at all, so no base render: this
              -- person exists for us only as a voice on a device.
              players[#players + 1] = { id = id, mode = "off", layers = layers }
            else
              -- An older VoIPC: one render each, the device winning. Without
              -- this fallback the first mod to use layers goes silent on every
              -- client that has not updated, with nothing to see in a log.
              players[#players + 1] = { id = id, mode = layers[1].mode }
            end
          end
        end
      end

      SendNUIMessage({
        type = "update",
        update = {
          type = "update",
          -- The camera heading is what players expect to hear along, not the
          -- ped's, which lags when they look around. `underwater` muffles and
          -- quietens the whole mix; `reverb` (0-10) would do the same for an
          -- interior, if your map has room data to drive it.
          self = {
            pos = { head.x, head.y, head.z },
            yaw = GetGameplayCamRot(2).z,
            underwater = IsPedSwimmingUnderWater(ped) and 10 or 0,
          },
          players = players,
        },
      })
    end
  end
end)
