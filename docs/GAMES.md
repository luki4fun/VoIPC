# Games

Which games VoIPC can do proximity chat for, how a mod reaches it in each, and
what that costs. The protocol itself is in [SDK.md](SDK.md); this is the map.

Everything turns on one question: **can code inside the game open a WebSocket to
`127.0.0.1`?** VoIPC's SDK is a loopback socket, so a game that can reach one
needs no plugin, no signed binary and no cooperation from the publisher. A game
that cannot needs something else, or nothing.

The second question is **what that code can see**. A mod that knows where every
player is can place them all, and VoIPC culls to what it lists. A mod that knows
only where *its own* player is uses **beacon mode**: VoIPC broadcasts that one
position to the channel, encrypted with the channel key like voice, and everyone
else's client does the same, so the mix assembles itself. Beacon mode needs the
player's consent (Settings → Game Integration) because it is the only thing here
that puts anything on the wire.

## Tier 1 — loopback, with everyone's positions

The full feature set: distance, direction, muffling, per-player volume, radio
and phone layers, distance culling.

| Game | Incumbent voice | How a mod reaches loopback | Effort |
|---|---|---|---|
| **FiveM** (GTA V) | pma-voice, SaltyChat, TokoVOIP, YACA | NUI page, origin `https://cfx-nui-<resource>` | **Done** — [`sdk/fivem-voipc/`](../sdk/fivem-voipc/), with radio and calls |
| **RedM** (RDR2) | SaltyChat, pma-voice forks | Same NUI, same origin shape | Copy the FiveM resource; the natives differ, the wiring does not |
| **alt:V** (GTA V) | SaltyChat, alt:V Voice | CEF view, origin `http://resource/<name>` | Small: `alt.emitServer` in place of state bags |
| **RAGE:MP** (GTA V) | SaltyChat, RAGE voice | CEF browser, origin `http://package/<name>` | Small: `mp.events.callRemote` in place of state bags |
| **MTA:SA** (GTA:SA) | MTA's own voice | CEF browser, origin `http://mta` | Small; Lua is close enough to FiveM's to port directly |
| **Garry's Mod** | Source voice_enable | An HTML panel (`vgui.Create("DHTML")`) can hold a WebSocket | Medium: no state bags, so the server broadcasts positions itself |
| **Minecraft** | Simple Voice Chat, Plasmo | A **client** mod, `java.net.http.WebSocket` (JDK 11+, masks correctly, no dependency) + a small server plugin | Medium. Both incumbents also need a client mod, so the ask is not new to that audience |
| **Unity / Unreal** (your own game) | — | Whatever WebSocket client you already have | Small: you own both ends |

The FiveM resource is the reference for everything above, including the part
that is easy to get wrong: **radio and phone partners are not in scope**. A
FiveM player state bag only replicates to clients that have that player
streamed in, and the other end of a radio never is — so membership and keying
live on the game server, and the client reads them from a replicated global.
Every engine here has the same shape of problem.

### Two shims, for servers that already have a voice resource

[`sdk/fivem-voipc-pma/`](../sdk/fivem-voipc-pma/) and
[`sdk/fivem-voipc-salty/`](../sdk/fivem-voipc-salty/) answer the export names
pma-voice and SaltyChat answer, and translate them to VoIPC's. ESX, QBCore, Qbox
and the ox resources are not integrations of their own — they call one of those
two — so the pair covers all of them at once.

They inherit pma-voice's trust model along with its export names: a client may
set its own call channel there, and call ids are guessable. `Config.canJoinCall`
in `sdk/fivem-voipc/config.lua` is the hook that closes that if you want it
closed; radio channels are gated on both paths already.

**Game natives cannot be shimmed.** A script that calls Mumble directly is
talking to the game's own voice stack, not to a resource, and no Lua can stand
in front of that. Find them before you switch:

```bash
grep -rnE 'Mumble[A-Za-z]*|NetworkIsPlayerTalking|MumbleSetVolumeOverrideByServerId' resources/
```

`MumbleSetVolumeOverrideByServerId`, `MumbleSetVoiceTarget`,
`NetworkIsPlayerTalking` and the rest have no VoIPC equivalent by design: VoIPC
is not in the game's voice stack. Whatever they were doing, the mod should be
asking VoIPC for it in the `update` instead.

## Tier 2 — loopback, but the mod sees only its own player

These need **beacon mode**: `hello` with `"mode":"beacon"`, `self.pos` every
tick, and the other members' positions arriving as encrypted position packets.
The ceilings are the same everywhere, and they come from the 12-byte payload:
one range for everybody, no per-player muffle, no whisper or shout, no radio
layers keyed to a person.

| Game | How | Effort |
|---|---|---|
| **Guild Wars 2** | **MumbleLink**, which ArenaNet writes natively at ~25 Hz and documents. No addon, no injection, no grey area — VoIPC reads the shared memory itself (Settings → Game Integration → *Follow MumbleLink*) | **Done**, no mod needed |
| **ETS2 / ATS + TruckersMP** | The telemetry SDK plugin already publishes the truck's position in shared memory | Small: another reader beside `mumblelink.rs` |
| **Arma 3** | A `callExtension` DLL in `sdk/arma3/`, which is exactly the shape TFAR and ACRE2 already ship, so the audience expects it | Medium, and a binary to build per platform |

**Arma 3 is worth the effort it costs.** ACRE2's `acre_api_fnc_setRadioSpatial`
returns literally `"LEFT"`, `"CENTER"` or `"RIGHT"` — which maps one-to-one onto
a layer's `pan`, so VoIPC can put one radio in each ear the way ACRE2 does,
without ACRE2.

## Tier 3 — no client-side code at all

Five games where nothing inside the client can open a socket: the scripting is
server-side only, or there is none.

| Game | Why not |
|---|---|
| **SA-MP / open.mp** | Pawn runs on the server; the client is closed |
| **Space Station 14** | Content is server-side; the client runs sandboxed C# with no socket API |
| **DayZ** | Enforce script is server-side for anything that matters; client mods are signed and Battleye-policed |
| **Arma Reforger** | Workbench scripting is server-authoritative; no client socket |
| **Minecraft, vanilla client** | Plugins are server-side only — the client will not be told where anybody is |

**That is five games where the only workable shape is the server driving the
mix.** VoIPC has that: a routed channel plus `POST /game/v1/routes` lets the
game server tell the relay who may hear whom, without a client mod and without
the relay learning a coordinate. See "Routed channels" in [SDK.md](SDK.md). The
players still hear each other positionally only if something places them, so
tier 3 gets **who hears whom** rather than **where from** — which for a game
with no client mod is the whole of what was available anyway.

## World of Warcraft — deliberately not shipped

The data is better than you would expect. `UnitPosition("player")` and
`GetPlayerFacing()` are unrestricted in the open world, and beacon mode needs
only your own position, so the restrictions on *other* units never bite.

The blocker is getting it out of the game. The Lua sandbox has no file and no
socket I/O; SavedVariables flush on logout or `/reload`, not live. The only
real-time channel is rendering the numbers into screen pixels and capturing them
back — which drags in a capture path, a windowed-fullscreen requirement, HDR and
scaling fragility, dead air when minimised, a visible strip in every screenshot,
and an EULA clause nobody can clear on the player's behalf. It is not memory
reading and it is not input automation, but it is unenumerated, Blizzard has
acted against pixel tooling before, and the risk lands on the player's account
rather than on ours.

**If you want proximity voice in an MMO, Guild Wars 2 gives strictly better data
through a channel its publisher documents, for a tenth of the work.** If a WoW
bridge gets built anyway, it belongs in a separate repository — self-position
only, no memory reads, no input — with a README that says plainly that Blizzard
has not sanctioned it. It will not be linked from here: an unsanctioned tool
does not belong next to this project's privacy claims.

## Adding a game

1. Can something in the client open a WebSocket to `127.0.0.1`? If not, look at
   routed channels instead.
2. Does it send an `Origin`? A browser-like view does; a native plugin does not,
   and VoIPC allows a missing one. If the origin is a shape not in
   `DEFAULT_ORIGIN_PREFIXES` / `DEFAULT_ORIGIN_HOSTS` (`client/src-tauri/src/sdk.rs`),
   the player can add it in Settings → Game Integration, and it is worth a pull
   request so the next person does not have to.
3. Can it see the other players? Yes → `players` with a full `update` each tick.
   No → beacon mode.
4. Start from [`sdk/fivem-voipc/`](../sdk/fivem-voipc/) and
   [`sdk/test-page.html`](../sdk/test-page.html), which drives the whole
   protocol from a browser with no game at all.
