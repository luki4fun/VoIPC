fx_version 'cerulean'
game 'gta5'

name 'fivem-voipc-pma'
description 'pma-voice exports, answered by VoIPC — drop in beside fivem-voipc and your framework keeps working'
version '0.8.0'

-- Independently written: this resource answers the export *names* pma-voice
-- answers, which is an interface, and contains none of its code. pma-voice
-- itself is MIT (https://github.com/AvarianKnight/pma-voice).
--
-- Load order matters only in one direction: `fivem-voipc` must be started,
-- because everything here forwards to it.
dependency 'fivem-voipc'

client_script 'client.lua'
server_script 'server.lua'
