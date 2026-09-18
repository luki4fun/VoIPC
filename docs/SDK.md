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
| Effect chains: five radio grades, five phone grades, megaphone, gramophone, robot | `mode: "<preset id>"` | yes |
| **One speaker heard several ways at once** — radio *and* in the room | `layers` | yes, up to 4 renders |
| **Which ear** a render is in | `pan` −1…1 | yes |
| **A render arriving late** — the radio a beat after the voice | `delay` ms | yes, to 20 ms steps |
| Speaking, mute and deafen pushed back to the mod | `talk` / `self` / `user` messages | yes, for players you listed |
| Reverberation around the listener | `self.reverb` 0–10 | yes |
| Underwater | `self.underwater` 0–10 | yes |
| **Broadcasting the player's own position**, for mods that cannot see the others | `hello.mode: "beacon"` | yes, with the player's consent |
| **Pressing the player's push-to-talk**, so the in-game radio key is the only key | `transmit` | yes, with the player's consent |

The `state` message lists what this build actually renders in `capabilities`,
and every value `mode` may take in `modes`. Read them instead of assuming: a
mod written against a later VoIPC will keep working against an earlier one,
just with fewer effects. **`capabilities` is the only reliable feature probe** —
`version` in the same message is the app version, and two builds that render
different things can carry the same one.

`capabilities` and `modes` are not the same list. `capabilities` carries
feature flags (`layers`, `pan`, `beacon`…) as well as chain ids; `modes` is
only what `mode` accepts, which is what a mod would put in a dropdown.

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
  channel: "Ingame",               // required: joined by name; create it in channels.json
  password: "s3cret",              // only if that channel has one
  mode: "players",                 // or "beacon"; see below
}));
```

VoIPC answers with a `state` message:

```json
{"type":"state","state":"ingame","user_id":42,"username":"Luki",
 "channel":"Ingame","proximity":"3d","muted":false,"deafened":false,
 "version":"0.9.0","sdk":1,
 "capabilities":["spatial","direct","volume","muffle","talk","reverb","underwater",
                 "layers","pan","delay","beacon","transmit",
                 "phone","radio","cb","walkie","aviation","police","landline",
                 "mobile","badvoip","intercom","megaphone","gramophone","robot"],
 "modes":["spatial","direct","off","phone","radio","cb","walkie","aviation",
          "police","landline","mobile","badvoip","intercom","megaphone",
          "gramophone","robot"]}
```

- **`channel` is required.** Without it a mod would arm itself on whichever
  channel the player happens to be in, which may be a private one where
  nothing on screen says a game is driving.
- **`mode`** is `"players"` (the default) or `"beacon"`. In `players` mode your
  mod places everybody and VoIPC culls to what it lists, which is what a GTA-
  like game can do. In `beacon` mode it sends only `self` and VoIPC broadcasts
  that position to the channel, encrypted like voice, so the other members
  place themselves — for games whose client can see where *it* is and nothing
  more. Beacon mode is the one thing here that puts anything on the wire, so
  the player has to allow it in Settings → Game Integration first; until they
  do, `hello` is answered with an error naming the setting.

`state` is one of:

| `state` | Meaning |
|---|---|
| `ingame` | Connected, **in the channel** (the join has completed), ready for updates |
| `disconnected` | VoIPC is not connected to any server; ask the player to connect |
| `wrong_server` | VoIPC is on a different server than the one in `hello.server`, or that field is missing |

A `wrong_server` reply carries no `user_id`, `username` or mute state. Any page
on an allowed origin can provoke one, and it is not entitled to know who is
using this machine.

**One game at a time, and one origin at a time.** The newest `hello` from the
origin that already owns the mix takes over — that is your resource
restarting. A `hello` from a *different* origin while the owner's socket is
alive is refused with `{"type":"error","reason":"another game is already
placing people"}`, so a second script on the same server cannot take the mix
off your voice resource (and two of them cannot fight over it, which sounds
like silence). A native client with no `Origin` header is one class of its own.

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
 "self":{"pos":[1200.5, -430.2, 30.1], "yaw": 90, "reverb": 0, "underwater": 0},
 "players":[
   {"id":42,"pos":[1203.0,-431.0,30.1],"range":8.0,"volume":1.0,"muffle":0},
   {"id":7,"mode":"radio","volume":0.8},
   {"id":9,"mode":"direct"}
 ]}
```

- **`self.pos`** — where the listener is, in metres. `fwd` is a unit vector in
  the x/y plane; `yaw` in degrees is accepted instead (0 faces +y, increasing
  counter-clockwise — the GTA heading convention).
- **`self.reverb`** 0–10 is how much space is around the listener: 0 outdoors,
  4 a room, 7 a garage, 10 a cathedral. While your mod is driving, it is put on
  every incoming voice at once — it is where the listener is, not where any one
  speaker is. Default 0.
- **`self.underwater`** 0–10 is how submerged the listener is. It low-passes
  and quietens every incoming voice, the radio and the phone included.
  Default 0. Careful: leaving `self` out entirely keeps the last pose *and*
  these two, while sending a `self` without them resets both to 0.

  Reverb and underwater are ordinary scalable effects, like `muffle` — the user
  sets them per voice in the mixer, and each voice carries its own. These two
  fields override every incoming voice's pair for as long as your mod drives
  the channel, and the user gets their own back when it stops. They never touch
  the user's microphone: what the user sends is always theirs.
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
- **`mode`** is `spatial` (default), `direct`, `off`, or the id of an effect
  chain. A chain ignores position and range — that is your radio, phone and
  megaphone audio; `off` leaves this player out of the mix entirely, which is
  how you say "heard only through the layers below". The chains are:

  | family | ids |
  |---|---|
  | radio | `radio` (the original), `cb`, `walkie`, `aviation`, `police` |
  | phone | `phone` (the original, and quieter than the rest), `landline`, `mobile`, `badvoip`, `intercom` |
  | other | `megaphone`, `gramophone`, `robot` |

  They differ in band, drive, hiss, bit-crushing and whether they squelch, so a
  CB does not sound like an aviation set. Every id appears in `capabilities`, so
  probe for the one you want rather than assuming. A `mode` this build does not
  recognise is rendered as `spatial` rather than refused, which is what lets a
  mod written against a later VoIPC keep working here.

  **One behaviour change:** any id VoIPC knows implies `direct`. A mod already
  sending `mode: "megaphone"` used to get plain spatial audio and now gets the
  megaphone chain with distance ignored — almost certainly what it wanted, but
  it is a change.
- **A player may also have put an effect on their own microphone**, and a room
  with it, from the client's mixer. That one is inside the encoded voice before it is
  ever sent: the mod cannot see it, cannot override it, and no listener can
  switch it off. If your mod also marks that speaker `radio`, both chains run
  and they stack — pick one side.
- An omitted `range` is 20 m, not unlimited.
- **`proximity: off` takes away the geometry, not the effects.** In a channel
  that is not positional, or for a user who has turned *Hear people where they
  stand* off, `pos`, `range` and direction do nothing — but `mode`, `volume`,
  `muffle`, `self.reverb` and `self.underwater` are all still rendered, and a
  player you leave out of `players` is still silent. A radio is a radio wherever
  it is heard. The `state` reply's `proximity` field tells you which you are in,
  and VoIPC pushes it again whenever it changes.

Coordinates are metres, x/y is the ground plane and z is up, which is GTA's own
frame: pass the game's coordinates straight through.

## Layers: one speaker, heard several ways at once

Somebody is on the phone to you **and** standing across the street. Every other
proximity plugin makes you pick one. Here a player entry may carry up to three
`layers`, each a full spec of its own, so that voice arrives up to four times —
each with its own placement, chain, ear and delay, all from the one Opus stream.

```json
{"id":7, "pos":[1203,-431,30.1], "range":8, "muffle":2,
 "layers":[
   {"mode":"mobile", "pan":-0.9},
   {"mode":"walkie", "delay":40},
   {"mode":"badvoip", "pos":[1201,-430,31.7], "range":2.5,
    "volume":0.35, "muffle":3}
 ]}
```

That is: their real voice where they stand, the phone in your left ear, their
radio arriving a beat later, and — the one nobody else can do — the tinny
earpiece leaking *at their own head*, two metres away, so you hear the person
they are talking to from where they are standing.

- **A layer takes every field a player does**: `pos`, `range`, `volume`,
  `muffle`, `mode`, `pan`, `delay`.
- **`mode` behaves differently on a layer, on purpose.** On the player entry a
  known chain implies `direct`, as it always has. On a **layer**, `pos` decides:
  a layer with a position is positional *and* effected, a layer without one is
  flat. That single asymmetry is what makes the earpiece case expressible.
- **`pan`** is −1 (left ear) to 1 (right), 0 centred. There is no softening
  clamp on it, unlike the world pan: "the phone is at my left ear" is not an
  estimate. Send `pan: 0.85` yourself if you want it gentler. A player with
  spatial audio switched off hears everything centred, pan included, so
  one-eared listeners lose nothing.
- **`delay`** is milliseconds, capped at 100 and quantised to 20 ms frames.
- **Silencing the base render needs `"mode":"off"`**, not `volume: 0`. In a
  channel that is not positional the gains never reach `volume`, so a zeroed
  one plays at full level. `off` is also what you send for somebody with no
  position in your world at all — a call partner across the map.
- Over three layers are **dropped, not refused**: a tick VoIPC will not apply
  is a frozen mix, which is worse than a missing render.
- **Listing one id twice is refused.** On a server where players publish their
  own VoIPC id, a second entry for somebody else's is how you would have their
  voice placed at your feet, or culled out of everyone's mix.

**If `layers` is not in `capabilities`, send the base `mode` instead.** A mod
that adopts layers without that fallback goes silent on every client that has
not updated, with nothing in a log to say why. `sdk/fivem-voipc/client.lua`
does both paths; copy the shape.

## Holding the player's push-to-talk

An RP player holds the in-game radio key *and* their VoIPC push-to-talk key.
Send this while the radio key is down and they only hold one:

```json
{"type":"transmit","on":true}
```

- The player has to tick *Let a game press my push-to-talk* in Settings → Game
  Integration first. Until they do, this is answered with an error naming the
  setting — send it anyway and log the error; it is not something to probe for.
- It **cannot talk over mute**, it lights the same indicator any transmission
  does (labelled so they can see it was the game), and a `transmit: false`
  never cuts a press the player is making themselves.
- It is let go automatically when your socket closes, when another game takes
  the mix, when the player leaves the channel, and after 60 seconds — re-send
  `on: true` to keep a long transmission going.

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

- **`talk`** is somebody else starting or stopping speaking. It arrives **only
  for players you listed in your last update**, plus yourself. A mod is told
  about the people it already knows about; the rest of the channel is not its
  business, and the socket is not a directory of who is in the room with the
  player. (Before 0.7.1 it arrived for everybody.)
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
      range = Player(GetPlayerServerId(player)).state.voipc_range or 8.0,
      muffle = muffleBetween(myPed, ped),
    }
  end
end
```

alt:V and RAGE:MP work the same way with their own state syncing
(`alt.emitServer` / `mp.events.callRemote`).

**Check the id is not already taken.** A player can claim any VoIPC id, and
claiming somebody else's is how you would have their voice placed at your feet
— or culled out of everyone's mix, which is worse, because nobody can tell it
is happening. VoIPC refuses an update that lists one id twice, so a duplicate
breaks the whole tick rather than one person; `sdk/fivem-voipc/server.lua` keeps
an id→player map and ignores the second claim. Misreporting an id you are the
only holder of misroutes nothing but your own listeners, which is the trust
model YACA has.

## Routed channels: letting the relay cull for you

A proximity channel your game drives can hold a whole map. Every listener
receiving and decoding every talker is what stops that scaling, so a channel
may ask the VoIPC server to forward each voice only to the people who should
hear it. **It is off by default**, and it is the only state in which that
server is told anything about who hears whom — so it is a per-channel switch,
the people in the channel are told when they join, and you should turn it on
only where you need it.

Set `"routed": true` on the channel in `channels.json` (or tick it in the
channel dialog). Two things then feed it:

1. **Each client** tells the server which members its mod is currently
   listing. That happens by itself — your mod already worked the set out to
   cull the mix, and VoIPC forwards it. It is self-declared, so it saves
   bandwidth and decoders; it is not enforcement.
2. **Your game server**, if you want enforcement against a patched client:

```
POST /game/v1/routes            (the same host:port the client connects to)
Authorization: Bearer <game_token from the server's settings.json>
Content-Type: application/json
```

```json
{"channel":"Ingame","epoch":918273,"boot":"3f9a1c","ttl_ms":3000,
 "players":[
   {"user":42,"pub":["w:7f3a1c","r:police"],
              "sub":["w:7f3a1b","w:7f3a1c","w:7f3a1d","r:police","c:call-91"]},
   {"user":7, "pub":["w:7f3a1d","c:call-91"],
              "sub":["w:7f3a1c","w:7f3a1d","c:call-91"]}]}
```

- A **bus** is any opaque string. Two players hear each other when what one
  publishes intersects what the other subscribes to, which is all that
  geometry, radio channels, phone calls and job gating ever collapse to. World
  cells, radio names and job names go in as **hashes salted with your own
  `boot` value** — VoIPC hashes them again, resolves them to "who hears whom"
  on receipt, and forgets them. It never learns a coordinate or a channel name,
  and the endpoint refuses a body carrying any field it does not know.
- **`epoch`** rises with every POST so a late one cannot overwrite a newer one;
  **`boot`** identifies this run of your server, and a new one resets the epoch
  — without it a server whose epoch is a tick counter would be refused for ever
  after a restart, and the channel would quietly fall back to full fan-out.
- **`ttl_ms`** is how long the answer holds, capped at 10 seconds. Post a few
  times a second. An expired table hands the whole channel back rather than
  silencing it: if it failed closed here, stopping your game server would be
  the whole attack.
- A player a live table does not mention **hears nobody and is heard by
  nobody** — that half does fail closed, or a client that simply stops asking
  would opt itself out of enforcement.
- Replies: `200` with a player count, `401` for a bad token, `404` if the
  channel is not routed (or `game_token` is unset, which turns the endpoint
  off entirely), `409` if the epoch is not newer — logged at WARN, because a
  server stuck behind its own epoch stops enforcing with nothing to see.

**Say what this is.** It stops packets reaching a cheat client. It is not
cryptographic separation: the channel still shares one media key, so a client
that does receive a packet can read it. That is still strictly more than
SaltyChat, YACA, TokoVOIP, TFAR or ACRE2 enforce, all of which enforce
nothing — and a browser in a routed channel gets culled by the relay even
though it has no SDK socket of its own.

### How far an unrouted channel goes

Without it the relay fans every talker out to every member, and each client
decodes what it receives whether or not its mod then culls it. That cost is
`talkers × listeners`, so it is fine for a long time and then is not:

| | one client | the server |
|---|---|---|
| 64 members, ~10 talking at once | ~0.5 Mbit/s in, 10 Opus decoders | ~30 Mbit/s out |

Ten simultaneous talkers is a busy RP night, not a stress test. Past roughly
**100 members in one proximity channel** the fan-out is the thing that breaks
first, and there are two ways out, which combine: name a channel per district
in `hello` and move players between them as they cross, or turn `routed` on and
let the relay forward only what each player should hear. Districts cost nothing
and tell the server nothing; routing needs neither the mod nor the player to
change anything, at the price named above.

## Security

- Loopback only, and off until the user turns it on. A handshake must finish
  within 5 seconds, a socket that sends nothing at all for 30 seconds is closed
  (send `ping` if your mod is otherwise idle), at most 8 sockets are served at
  once, and **at most 2 of them may come from one origin** — the third gets
  `503`. Two is a resource restarting while its old socket dies; more than that
  is a page hoarding the slots the game needs, which any `cfx-nui-*` script on
  the same server could otherwise do.
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
- `hello.server` and `hello.channel` are both required: the first so a mod
  cannot place people using coordinates from a different session, the second so
  it cannot arm itself on whatever channel the player happens to be in.
- **Protect the channel your game drives.** A VoIPC channel is a VoIPC channel:
  a player who knows its name can join it by hand, with no mod running, and
  then hears every talker in it at full volume with no distance and no
  direction, because nothing is placing anybody for them. Three things stop
  that, and they are not equal:

  | | What it actually does |
  |---|---|
  | `hidden` | Keeps it out of everybody's channel list but an admin's. Discovery only — it does **not** refuse a join |
  | `password` | The gate. A join without it is refused by the server |
  | `routed` + a game server posting route tables | Anyone the table does not list hears nobody and is heard by nobody, even if they are standing in the channel |

  Use all three. `channels.example.json` ships the `Ingame` entry that way.
  Keep the password out of any file your players download — in FiveM that means
  a `server_script`, not `config.lua`, and the shipped resource hands it to a
  client at the moment it joins (`server_config.lua`).
- A `wrong_server` refusal carries no identity — no user id, name or mute
  state. It is the one reply any allowed origin can provoke.
- One game owns the mix, and a second **origin** cannot take it while the first
  socket lives.
- `talk`, `user` and `self` pushes are limited to the players the mod listed,
  and they stop the moment the player leaves the channel the game joined.
- **Broadcasting the player's position** (`hello.mode: "beacon"`) and
  **pressing their push-to-talk** (`transmit`) each need their own switch in
  Settings → Game Integration, both off by default. Nothing else a mod sends
  leaves the machine or opens a microphone.
- **Taking either switch back stops what is happening**, not what happens next:
  unticking *press my push-to-talk* lets the microphone go that instant, and
  unticking *broadcast my position* stops the beacon on the wire (your mod keeps
  placing the player locally). Turning one back on applies from the next
  `hello` — so send one if the player says they have just allowed it.
- Switching the integration off, in the same panel, disconnects every socket,
  hands back every placement and lets go of the microphone. It is the escape
  hatch, and it is meant to be complete.
- A player the game leaves out is silent, and the member list and mixer grey
  them out while that is happening, so culling is visible rather than
  mysterious. Switching the integration off hands everything back at once.
- Updates are acted on at up to 50 a second and `hello` at one a second;
  anything faster is dropped rather than queued behind the audio mixer.
- The socket exposes positions and volumes. There is no access to chat, to
  keys, or to any channel other than the one in `hello`.
- Any local process can still connect, exactly as with a TeamSpeak plugin. If
  that matters to you, leave the integration off when you are not playing.

## Other games

FiveM is the worked example, but the protocol is not about FiveM.
[GAMES.md](GAMES.md) has a row per game: how a mod reaches loopback there (or
why it cannot), whether it can see the other players or only its own, and what
that costs. It also covers the two compatibility shims, the game natives no
shim can stand in for, and the one game deliberately not supported.

## Testing without a game

`sdk/test-mod.mjs` is the version you run rather than watch. It is a fake mod in
one file with no dependencies: it opens the socket as a native client, and
checks the whole pipeline against a VoIPC that is connected to a server —
`hello` joining the channel, an update placing two players with a radio and a
phone layer, a duplicate id being refused, `transmit` opening and closing the
microphone, and a second origin being refused the mix. It hands everything back
when it finishes.

```bash
node sdk/test-mod.mjs --server rp.example.com:9987 --channel Ingame --password s3cret
```

Every line it prints is a rule from this document, so a red one tells you which.
If your own mod misbehaves, run this first: it says whether the client, the
channel and the consent switches are in the state you think they are.

`sdk/test-page.html` is a single file with sliders for your own position, how
much space is around you and how submerged you are, and one other player, plus
the channel to join, every mode the build reports in `modes`, a layer you can
add with its own chain and ear, the build's `capabilities` and a live line of
who is speaking. Open it in a browser, add `null` to the allowed origins, put
the server you are connected to in its *VoIPC server* field, and drag: you
should hear the other voice move, and hear the layer sit in one ear while it
does.

## A ready-made FiveM resource

`sdk/fivem-voipc/` is a working resource: drop it in, set `server` and
`channel` in `config.lua`, put the channel's password in `server_config.lua`
(server-only, because `config.lua` is downloaded to every player), and
`ensure fivem-voipc`. It publishes each player's
VoIPC id through a state bag, sends head-bone positions and the camera heading
at 10 Hz, culls by distance, derives muffling from vehicles, interiors and line
of sight, cycles the voice range on a key, and drowns you while you are
underwater.

**Radio and phone are real in it**, and they are the reference for how layers
are meant to be used: a keyed radio partner is heard *over the radio* while
still being heard as themselves if they are standing next to you. Membership
and entitlement live on the game server (`server.lua`), because a FiveM player
state bag only replicates to clients that have that player in scope — the other
end of a radio never is. It exposes:

| side | export |
|---|---|
| client | `setRadioChannel(name)`, `setRadioTalking(bool)`, `setVoiceRange(m)`, `getVoipcId()` |
| server | `setPlayerRadioChannel(src, name)`, `setPlayerCall(src, partner)`, `addChannelCheck(name, fn)`, `getPlayersInRadioChannel(name)`, `getVoipcId(src)` |

`Config.canJoinRadio(src, channel)` and `addChannelCheck` are where a job check
goes — ESX, QBCore, whatever you already have. **That is the whole of radio
entitlement, and it is deliberately on your server rather than VoIPC's**, which
relays encrypted audio to a channel and never learns that radio channels exist.
An honest client renders only what it is entitled to; a patched one hears the
channel, exactly as with SaltyChat, YACA and TokoVOIP.

Still deliberately simple: the muffle heuristic knows nothing about doors or
windows, `self.reverb` is never set because the resource has no room data to
derive it from, and the talking state is published (`voipc:talking`, and a
replicated `voipc_talking` state bag) without an overlay to draw it. alt:V and
RAGE:MP work the same way with their own state syncing.

### Already running pma-voice or SaltyChat?

`sdk/fivem-voipc-pma/` and `sdk/fivem-voipc-salty/` answer the export names
those two answer, and forward them here. ESX, QBCore, Qbox and the ox resources
are not voice integrations of their own — they call one of those two — so the
pair covers all of them, and switching is: start `fivem-voipc`, start the shim,
stop the old resource. Where the models genuinely differ (SaltyChat's secondary
radio, per-resource volume, mic clicks, radio towers) the shim logs what it is
not doing, once, rather than failing quietly.

**One trust model comes with it.** pma-voice lets a *client* set its own call
channel, and a call id is a guessable string, so a cheat client that guesses one
is in that call — pma-voice's own behaviour, and the shim keeps it rather than
breaking phone resources that rely on it. `Config.canJoinCall(src, id)` in
`sdk/fivem-voipc/config.lua` is where you close it: return whether your phone
resource actually put that player in that call. Radio channels never took the
client's word for it — they go through `Config.canJoinRadio` and
`addChannelCheck` on both paths.

**Game natives cannot be shimmed.** A script calling `MumbleSetVolumeOverrideByServerId`
or `NetworkIsPlayerTalking` is talking to the game's own voice stack, which
VoIPC is not in. Find them before you switch:

```bash
grep -rnE 'Mumble[A-Za-z]*|NetworkIsPlayerTalking' resources/
```

[GAMES.md](GAMES.md) has the full list and what to do about each.

To check your headphones without any of this, use Settings → Spatial Audio →
*Test 2D* / *Test 3D*: a synthetic voice circles you through the same mixer.

## Protocol version

`sdk: 1`. New fields will be added to these messages; unknown fields are
ignored, and a mod that does not send a field gets the documented default. A
breaking change bumps the number, and VoIPC then answers a `hello` that names
a version it does not speak with `{"type":"error","reason":"unsupported SDK
version 2"}`. That check comes after the connection checks, so a mod talking
to a VoIPC that is not connected to a server sees `state: disconnected` first.
