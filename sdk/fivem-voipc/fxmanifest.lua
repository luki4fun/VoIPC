fx_version 'cerulean'
game 'gta5'

name 'fivem-voipc'
description 'VoIPC proximity voice for FiveM — the open alternative to a TeamSpeak plugin (see docs/SDK.md)'
version '0.7.0'

-- The NUI page is the only thing that can open a WebSocket from inside the
-- game: Lua has no socket API. It bridges SendNUIMessage to the VoIPC client
-- and NUI callbacks back, and its origin (https://cfx-nui-fivem-voipc) is one
-- VoIPC allows out of the box.
ui_page 'html/index.html'
files { 'html/index.html' }

shared_script 'config.lua'
client_script 'client.lua'
server_script 'server.lua'
