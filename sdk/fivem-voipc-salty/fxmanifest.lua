fx_version 'cerulean'
game 'gta5'

name 'fivem-voipc-salty'
description 'SaltyChat exports, answered by VoIPC — no TeamSpeak, no plugin, no licence server'
version '0.8.0'

-- Independently written. This resource answers the export *names* SaltyChat's
-- FiveM resource answers — an interface, which is not a work of authorship —
-- and contains none of its code. SaltyChat's FiveM resource is GPL-3.0
-- (https://github.com/SaltyHub-net/saltychat-fivem); its TeamSpeak plugin is
-- proprietary and is exactly the thing VoIPC does not need.
dependency 'fivem-voipc'

client_script 'client.lua'
server_script 'server.lua'
