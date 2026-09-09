-- VoIPC proximity voice, client side.
--
-- Every tick this collects where the local player is looking and where the
-- streamed players stand, and hands it to the NUI page, which pushes it to the
-- VoIPC client over its loopback WebSocket. VoIPC does the mixing.
--
-- Deliberately left as stubs, so this stays a readable example:
--   * radio and phone: the tables below are filled by two events that nothing
--     currently triggers — wire them to your own radio/phone resource
--   * muffling: line of sight, vehicles and interiors only; no door or window
--     state, which is where a production script earns its keep
--   * no talking-icon overlay; `voipc:talking` and the `voipc_talking` state
--     bag are published for one

local myVoipcId = nil
local rangeIndex = 2

--- user_id -> volume, for players heard over the radio rather than in person.
local RadioSpeakers = {}
--- The user_id of the player on the other end of a phone call, if any.
local PhoneCall = nil

--- Anyone in this table is heard flat, wherever they stand.
local function directMode(id)
  if PhoneCall == id then return "phone", 1.0 end
  local volume = RadioSpeakers[id]
  if volume then return "radio", volume end
  return nil, nil
end

-- ── Connecting ───────────────────────────────────────────────────────────

local function connect()
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
      password = Config.password,
    },
  })
end

-- The NUI page says when its message listener is live. Sending `connect`
-- before that (the page loads asynchronously) would be dropped silently, and
-- the resource would sit there doing nothing.
RegisterNUICallback("ready", function(_, cb)
  cb({})
  connect()
end)

AddEventHandler("onClientResourceStop", function(resource)
  if resource ~= GetCurrentResourceName() then return end
  SendNUIMessage({ type = "bye" })
end)

-- VoIPC's reply to `hello`, forwarded by the page.
RegisterNUICallback("state", function(data, cb)
  cb({})
  if data.state == "ingame" then
    myVoipcId = data.user_id
    -- Publish it so every other player can address us; the game server does
    -- the replicating, exactly as SaltyChat and YACA rely on their own netcode
    TriggerServerEvent("voipc:register", myVoipcId)
    print(("[voipc] in channel %s as %s (%s)"):format(
      tostring(data.channel), tostring(data.username), table.concat(data.capabilities or {}, ",")))
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
    LocalPlayer.state:set("voipc_talking", data.speaking, false)
  end
end)

RegisterNUICallback("error", function(data, cb)
  cb({})
  print("[voipc] " .. tostring(data.reason))
end)

-- ── Voice range ──────────────────────────────────────────────────────────

RegisterCommand("voicerange", function()
  rangeIndex = rangeIndex % #Config.ranges + 1
  local range = Config.ranges[rangeIndex]
  -- Replicated, so the others know how far we carry
  LocalPlayer.state:set("voiceRange", range, true)
  BeginTextCommandThefeedPost("STRING")
  AddTextComponentSubstringPlayerName(("Voice range: %s (%.1f m)"):format(
    Config.rangeNames[rangeIndex], range))
  EndTextCommandThefeedPostTicker(false, false)
end, false)
RegisterKeyMapping("voicerange", "Change voice range", "keyboard", Config.rangeKey)

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

CreateThread(function()
  while true do
    Wait(Config.rateMs)
    if myVoipcId then
      local ped = PlayerPedId()
      -- The head bone, not the feet: the ear height is what a listener expects
      local head = GetPedBoneCoords(ped, 0x796e, 0.0, 0.0, 0.0)
      local players = {}
      -- Culled generously: a player VoIPC is not told about is silent, which
      -- is how distance culling works in every one of these plugins
      local cull = Config.ranges[#Config.ranges] * 1.5

      for _, player in ipairs(GetActivePlayers()) do
        local serverId = GetPlayerServerId(player)
        local id = Player(serverId).state.voipc
        if id and id ~= myVoipcId then
          local mode, volume = directMode(id)
          if mode then
            -- Radio and phone ignore position entirely
            players[#players + 1] = { id = id, mode = mode, volume = volume }
          else
            local otherPed = GetPlayerPed(player)
            local pos = GetPedBoneCoords(otherPed, 0x796e, 0.0, 0.0, 0.0)
            if #(head - pos) <= cull then
              players[#players + 1] = {
                id = id,
                pos = { pos.x, pos.y, pos.z },
                range = Player(serverId).state.voiceRange or Config.ranges[2],
                muffle = muffleBetween(ped, otherPed),
              }
            end
          end
        end
      end

      SendNUIMessage({
        type = "update",
        update = {
          type = "update",
          -- The camera heading is what players expect to hear along, not the
          -- ped's, which lags when they look around
          self = { pos = { head.x, head.y, head.z }, yaw = GetGameplayCamRot(2).z },
          players = players,
        },
      })
    end
  end
end)

-- ── Hooks for your radio and phone resources ─────────────────────────────

--- TriggerEvent("voipc:radio", userId, volume) — nil volume removes them.
RegisterNetEvent("voipc:radio", function(userId, volume)
  RadioSpeakers[userId] = volume
end)

--- TriggerEvent("voipc:phone", userId) — nil ends the call.
RegisterNetEvent("voipc:phone", function(userId)
  PhoneCall = userId
end)
