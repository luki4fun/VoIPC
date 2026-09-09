-- The client learns its own VoIPC user id from the `state` reply and tells us
-- here; we replicate it so every other client can address that player.
--
-- Trust model, the same one YACA has: a player can only misreport their own
-- id, and doing so misroutes their own listeners. Nothing here grants access
-- to anyone's audio.

RegisterNetEvent("voipc:register", function(userId)
  if type(userId) ~= "number" or userId <= 0 then
    return
  end
  Player(source).state:set("voipc", math.floor(userId), true)
end)

AddEventHandler("playerDropped", function()
  Player(source).state:set("voipc", nil, true)
end)
