# Fuzzing

cargo-fuzz targets for every parser that takes bytes from the relay, another
member, a game mod or the network. This is its own workspace, built on
nightly; the root workspace excludes it.

Each target is one line. It calls a `fuzz_<name>` function that lives next to
the code it tests, in that crate's `src/fuzz.rs` (or `src/lib.rs` for
voipc-opus-wasm), behind `cfg(any(test, fuzzing))`. That crate's own tests
replay `regressions/<name>/*` on stable, so `cargo test` keeps every input
that once crashed.

| Target | Crate | Input |
|---|---|---|
| `codec` | voipc-protocol | client and server messages, length-prefixed frames |
| `compat` | voipc-protocol | an older relay's messages, for each protocol the app still talks to |
| `media_packets` | voipc-protocol | voice, position, video and screen-audio packets |
| `video_assembly` | voipc-protocol | a viewer's record stream, frame grouping, reassembly |
| `ws` | voipc-protocol | the TCP fallback's WebSocket frames, decoder and upgrade |
| `envelope` | voipc-crypto | chat envelopes, history payloads, media keys |
| `keys` | voipc-crypto | log keys, pins, recovery keys |
| `log` | voipc-crypto | kept entries and epoch-key wraps |
| `file` | voipc-crypto | file blobs, claimed sizes, the capped inflate |
| `vault` | voipc-crypto | vault slots and items |
| `pair` | voipc-crypto | a pairing's commitment, reveal, answer key and wrapped vault key |
| `jitter` | voipc-audio | sequence numbers in any order |
| `opus` | voipc-audio | Opus packets into the native decoder |
| `game` | voipc-audio | SDK frames and messages, origins, MumbleLink |
| `web_media` | voipc-web | the browser's media parsers |
| `opus_decode` | voipc-opus-wasm | the browser's Opus decoder (rusty-opus) |
| `media` | voipc-media | pictures and packs nobody here made, through every decoder and the pack reader |
| `import` | voipc-import | Discord's JSON and a member's words, through the importer's rewrite |

Not covered yet:
- the stateful sign-in and sync machines (`SignIn::on_message`,
  `AccountSync::on_reply`);
- the relay's own parsers, in the server binary, which no target can depend on: the
  provider callback's `query_param` and `percent_decode` get many generated inputs in
  its tests instead;
- `solve_pow`, which costs up to 10 million hashes per input;
- the Android-only SPS parser.

## Running

```sh
rustup toolchain install nightly-2026-10-23   # the version CI pins (nightly.yml)
cargo install --locked cargo-fuzz@0.13.2
cd fuzz
cargo +nightly-2026-10-23 fuzz run codec -- -max_total_time=60
```

CI runs every target for ten minutes each night (`.github/workflows/nightly.yml`).

## When it finds something

1. Get the input:
   - from CI, it is the job's `fuzz-crash-<target>` artifact;
   - when run locally, it is under `artifacts/<target>/`.
2. Copy it to `regressions/<target>/<short-name>`. `cargo test` now fails on it.
3. Fix the code: that test then passes and stays.
4. Commit both.
