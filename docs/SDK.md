# VoIPC Game SDK

Proximity voice for your game, without a TeamSpeak plugin.

Your mod tells the VoIPC desktop client where every player stands; the client
mixes each voice at the right volume and direction. No plugin to install, no
license server, no matching of nicknames — players are addressed by their VoIPC
user id, which your game server hands out through its own netcode.

If you have integrated SaltyChat, YACA or TokoVOIP before, this will look
familiar: a page inside the game runtime opens a WebSocket to `127.0.0.1` and
pushes a bulk position update a few times a second.

## What VoIPC renders today

| Capability | Sent as | Status |
|---|---|---|
| 3D proximity: distance and direction | `pos` + `self.pos`/`fwd` | yes |
| Per-player range (whisper / normal / shout) | `range` | yes |
| Per-player volume override | `volume` | yes |
| Distance culling: a player you leave out is silent | omit from `players` | yes |
| Muffling through walls, vehicles, rooms | `muffle` 0–10 | yes |
| Non-positional audio (radio, phone, megaphone, spectator) | `mode: "direct"` | yes, flat |
| Radio and phone effects (band-limit, noise, squelch) | `mode: "radio"` / `"phone"` | yes on the desktop client; the browser client renders them flat |
| Speaking, mute and deafen pushed back to the mod | `talk` / `self` / `user` messages | yes |
| Underwater and room reverb | — | not yet |

The `state` message lists what this build actually renders in `capabilities`.
Read it instead of assuming: a mod written against a later VoIPC will keep
working against an earlier one, just with fewer effects.

## Turning it on

Settings → Game Integration → *Let a game place people for me*.

The listener binds `127.0.0.1` only and is off until the user enables it. The
default port is **39987**.

## Connecting

```js
const socket = new WebSocket("ws://127.0.0.1:39987/");
socket.onopen = () => socket.send(JSON.stringify({
  type: "hello",
  sdk: 1,
  game: "fivem",
  resource: "my-voice",
  server: "rp.example.com:9987",   // required: the VoIPC server your players are on
  channel: "Ingame",               // joined by name; create it in channels.json
  password: "s3cret",              // only if that channel has one
}));
```

VoIPC answers with a `state` message:

```json
{"type":"state","state":"ingame","user_id":42,"username":"Luki",
 "channel":"Ingame","proximity":"3d","muted":false,"deafened":false,
 "version":"0.7.0","sdk":1,
 "capabilities":["spatial","direct","volume","muffle","radio","phone","talk"]}
```

`state` is one of:

| `state` | Meaning |
|---|---|
| `ingame` | Connected, **in the channel** (the join has completed), ready for updates |
| `disconnected` | VoIPC is not connected to any server; ask the player to connect |
| `wrong_server` | VoIPC is on a different server than the one in `hello.server`, or that field is missing |

A join that the server refuses, or that does not complete within three
seconds, is answered with an error instead of `ingame`:

```json
{"type":"error","reason":"could not join Ingame: incorrect channel password"}
```

Send `hello` again after a reconnect; ids are per connection. VoIPC checks
this for you: an `update` whose ids are from the connection before a reconnect
is refused with `{"type":"error","reason":"reconnected to the server — send
hello again"}` instead of silently culling everyone out of the mix.

Only the newest connection that completed a `hello` drives the mix. Reconnect
freely after a resource restart; the old socket cannot take the positions with
it when it finally closes.

## Position updates

One bulk update, 4–10 times a second. VoIPC glides each player from where it
last had them to the new position over the time between your updates (between
20 and 250 ms), and interpolates the listener's own position and facing the same way,
so 4–10 Hz sounds continuous rather than stepping. A jump of more than 50 m in
one update snaps instead (a respawn or a teleport), as does a player you list
again after leaving them out. A faster rate buys nothing; do not exceed 20 Hz.

```json
{"type":"update",
 "self":{"pos":[1200.5, -430.2, 30.1], "yaw": 90},
 "players":[
   {"id":42,"pos":[1203.0,-431.0,30.1],"range":8.0,"volume":1.0,"muffle":0},
   {"id":7,"mode":"radio","volume":0.8},
   {"id":9,"mode":"direct"}
 ]}
```

- **`self.pos`** — where the listener is, in metres. `fwd` is a unit vector in
  the x/y plane; `yaw` in degrees is accepted instead (0 faces +y, increasing
  counter-clockwise — the GTA heading convention).
- **`players`** is a full replacement each tick. **A player you leave out is
  silent.** That is how you cull by distance, and it is what SaltyChat and YACA
  do too.
- **`range`** is the distance at which that player becomes inaudible. The
  SaltyChat voice ranges map straight across: 3.5 whisper, 8 normal, 15
  shouting, 32 megaphone.
- **`volume`** 0–2 multiplies that player's voice (SaltyChat's `VolumeOverride`,
  pma-voice's `MumbleSetVolumeOverrideByServerId`).
- **`muffle`** 0–10 low-passes and attenuates: 4 for a thin door, 7 for an
  interior wall, 10 for a floor. Compute it as SaltyChat does, from
  `GetRoomKeyFromEntity`, `HasEntityClearLosToEntity` and vehicle openings.
- **`mode`** is `spatial` (default), `direct`, `radio` or `phone`. The last
  three ignore position and range — that is your radio, phone and megaphone
  audio. `phone` is band-limited to roughly 300–3400 Hz, the telephone band;
  `radio` adds drive, a faint hiss and a short squelch burst when a
  transmission starts and ends. The browser client has no game SDK and renders
  both flat, so check `capabilities` rather than assuming.

Coordinates are metres, x/y is the ground plane and z is up, which is GTA's own
frame: pass the game's coordinates straight through.

Other messages: `{"type":"ping"}` (answered with `{"type":"pong"}`) and
`{"type":"bye"}`. Closing the socket does the same as `bye`: every placement is
dropped and the mix goes back to plain per-user volumes.

## What VoIPC pushes

Once a `hello` has succeeded, VoIPC sends these unprompted, on the edge — a
change, not a heartbeat:

```json
{"type":"talk","user_id":42,"speaking":true}
{"type":"self","muted":false,"deafened":false,"speaking":true}
{"type":"user","user_id":7,"muted":true}
```

- **`talk`** is somebody else starting or stopping speaking. It may arrive for
  a player you did not list, so ignore ids you do not know.
- **`self`** is the local player: `speaking` means voice is actually going out,
  so it stays false while muted or while push-to-talk is up. Every field is
  included each time, so the last one you received is the whole state.
- **`user`** is another player's mute or deafen state changing.

Use them for a talking icon over a player's head or a muted marker in a phone
UI. A socket that falls far behind may miss a few edges; the next one for that
player re-syncs it.

## Mapping game players to VoIPC users

The `state` reply tells the client its own `user_id`. Publish it through your
game's own netcode, then read it back for every streamed player:

```lua
-- FiveM, client side
RegisterNUICallback("voipc:state", function(data, cb)
  LocalPlayer.state:set("voipc", data.user_id, true)   -- replicated to everyone
  cb({})
end)

-- every tick, building `players`
for _, player in ipairs(GetActivePlayers()) do
  local id = Player(GetPlayerServerId(player)).state.voipc
  if id then
    local ped = GetPlayerPed(player)
    players[#players + 1] = {
      id = id,
      pos = coords(GetPedBoneCoords(ped, 0x796e)),   -- head bone
      range = Player(GetPlayerServerId(player)).state.voiceRange or 8.0,
      muffle = muffleBetween(myPed, ped),
    }
  end
end
```

alt:V and RAGE:MP work the same way with their own state syncing
(`alt.emitServer` / `mp.events.callRemote`). A player can only misreport their
own id, and doing so misroutes their own listeners — the same trust model YACA
has.

## Security

- Loopback only, and off until the user turns it on. A handshake must finish
  within 5 seconds, a socket that sends nothing at all for 30 seconds is closed
  (send `ping` if your mod is otherwise idle), and at most 4 sockets are served
  at once — the fifth gets `503`.
- Client frames must be masked, as the WebSocket standard requires. Every
  browser does this; a hand-rolled client that does not is closed with 1002.
- A request without an `Origin` header is allowed: only browsers always send
  one, and a native mod (a C# plugin, or `curl` while you debug) cannot. That
  matches the trust model below — any local process can connect.
- If the port cannot be taken (another program has it), Settings → Game
  Integration says so instead of silently never connecting.
- Origins are checked: the game runtimes (`https://cfx-nui-…`, `http://resource/…`,
  `http://package/…`) are matched by prefix, and `localhost` / `127.0.0.1` only
  as the exact host (with an optional port). Everything else is refused,
  because any web page a player has open can otherwise reach a local port — and
  a name like `localhost.example.com` is an ordinary internet host, not
  loopback. Settings → Game Integration takes extra origins, one per line, each
  matched exactly — add `null` to test from a `file://` page.
- `hello.server` is required and must name the server VoIPC is connected to, so
  a mod cannot place people using coordinates from a different session.
- The socket exposes positions and volumes. There is no access to chat, to
  keys, or to any channel other than the one in `hello`.
- Any local process can still connect, exactly as with a TeamSpeak plugin. If
  that matters to you, leave the integration off when you are not playing.

## Testing without a game

`sdk/test-page.html` is a single file with sliders for your own position and one
other player, plus the channel to join, the four modes, the build's
`capabilities` and a live line of who is speaking. Open it in a browser, add
`null` to the allowed origins, put the server you are connected to in its
*VoIPC server* field, and drag: you should hear the other voice move.

## A ready-made FiveM resource

`sdk/fivem-voipc/` is a working resource: drop it in, set `server` and
`channel` in `config.lua`, and `ensure fivem-voipc`. It publishes each player's
VoIPC id through a state bag, sends head-bone positions and the camera heading
at 10 Hz, culls by distance, derives muffling from vehicles, interiors and line
of sight, and cycles the voice range on a key.

Deliberately left as stubs, so it stays readable: radio and phone are driven by
two events (`voipc:radio`, `voipc:phone`) that nothing triggers yet, the muffle
heuristic knows nothing about doors or windows, and the talking state is
published (`voipc:talking`, and a `voipc_talking` state bag) without an overlay
to draw it. alt:V and RAGE:MP work the same way with their own state syncing.

To check your headphones without any of this, use Settings → Spatial Audio →
*Test 2D* / *Test 3D*: a synthetic voice circles you through the same mixer.

## Protocol version

`sdk: 1`. New fields will be added to these messages; unknown fields are
ignored, and a mod that does not send a field gets the documented default. A
breaking change bumps the number, and VoIPC then answers a `hello` that names
a version it does not speak with `{"type":"error","reason":"unsupported SDK
version 2"}`. That check comes after the connection checks, so a mod talking
to a VoIPC that is not connected to a server sees `state: disconnected` first.
