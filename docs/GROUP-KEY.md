# Group epoch key for text channels and voice rooms

Status: **built, in VoIPC 1.14 / protocol 26.** The primitives, the relay's validator and state, both
apps' state machines, kept history and voice are in the code (`voipc-crypto` `group_key` and
`group_state`, voipc-server `gk/` and `accounts/gk.rs`, the desktop's `gk_net.rs`, voipc-web
`gk.rs`). Where this text and the code disagree, the code is right and this text is a bug.
**No outside cryptographer has reviewed this design or its code** (owner, 2026-11-17: no external
review). Instead the built version gets an adversarial review of our own, which works through
section 7's questions against the code, and the owner's review once everything is done. Section 7
says which questions that review has answered; until it has run, none is answered. The release
notes say plainly that no outside cryptographer reviewed it.

It was first planned for 1.16 / protocol 27, after the media edge pool (1.15 / protocol 26). Neither
1.14 nor 1.15 shipped on its own, so the group key went into protocol 26 beside the edges, and the
release that carries both is 1.14 (owner, 2026-11-18).

On a relay at 26 with `group_key` on (the default, §9), every text channel and every voice room uses
the group key, small ones too. There is one state machine per channel and no size threshold. It
replaces the pairwise live path (protocol 21) in text channels and the 3N media-key join in voice
rooms. Direct messages, files and the vault do not change. The app keeps the old paths for older
relays and for relays with the switch off (§9).

## 1. Why

On the live path today, a writer hands its libsignal sender key to each reader through a pairwise
session (`channel_state.rs`, "The live path"). That cost grows with the readers:

- At 100,000 followers, one writer's first post costs it about 180 MB down and 17.6 MB up.
- Each exit batch then costs every writer the same again.
- The kept log has the same shape, one copy per writer (`log.rs` buckets, `sync/chains.rs`). That is
  why `kept_seats` defaults to 5000 and a writer takes at most 32,000 readers (`MOST_READERS`).

Goals:

1. A post costs a writer O(1), however many read it.
2. A newcomer costs the channel O(1). An exit costs the channel O(buckets), not O(members × writers).
3. Keep the properties the live path has:
   - end to end against the relay;
   - post-quantum protection of what is stored or recorded;
   - forward secrecy for leavers;
   - signed writers.
4. One Rust implementation in `voipc-crypto`, used by the desktop app and, through `voipc-web`, by
   the browser.

Not goals:

- MLS. With openmls, every member would hold the whole ratchet tree, about 30 MB classical at 100k
  leaves. Every guest join would be a commit every member applies. Its post-quantum suite is
  ML-KEM-768, not Kyber1024.
- Hiding who is in a channel from the relay. It routes the posts, so it knows.
- Protection against a member. Whoever reads a channel can copy it.
- A size threshold per channel. All channels move together; the relay switch is the way back.

## 2. Keys

| Key | What it is | Who holds it | How others trust it |
|---|---|---|---|
| Identity key `IK` | Curve25519 (libsignal) | The account's vault; a guest's is per connection | Pinned on first meeting (TOFU), or by safety numbers |
| Seat KEM key `SK` | Kyber1024 key pair | Accounts: the vault item `item.seat_kem`. Connections: a per-connection seat pair | One endorsement by `IK` over `SK` and `SX` together, with a counter (§11.8) |
| Seat DH key `SX` | X25519 key pair | As `SK` | As `SK` |
| Self key | 32 random bytes | Accounts only, in `item.seat_kem` | — |
| Keyholder keys `KK_K`, `KX_K` | Kyber1024 and X25519 key pairs of one keyholder device or connection; never the account's seat keys | That device only: a desktop app's local store, or a connection's seat pair | An endorsement by `IK` (§11.8), and named in the keyholder headers (§4) |
| Seed `seed_s` | 32 random bytes; `s` numbers the seeds of a generation from 1 | Keyholders (in the keyring) | — |
| Member secret `s_m` | `HKDF(seed_s, …)`, §3.1 | Keyholders (derived); member `m` (from a welcome) | — |
| Bucket key `BK(b,v)` | 32 random bytes, or a ratchet of the last version (§3.5) | Keyholders; the ≤ 62 seats of `(b,v)` | Its seat-list digest sits in the bucket root of every header (§4) |
| Epoch key `CK_e` | 32 random bytes, drawn again on every attempt at an opening commit | Keyholders; every seated member | `confirm` in every header |
| Keyring key `KRK` | 32 random bytes per change of the keyholder set | Keyholders | — |
| Writer sender key | libsignal sender key, one chain per writer per epoch | The writer; readers through the writer blob | Signed by the writer's `IK` |
| Media key | `HKDF(CK_e, …)` per sender seat and stream (§3.10) | Everyone in the voice room | — |

The log key `LK` plays no part. It keeps serving the per-writer kept log of protocol 21 (§5.10).

**Seat keys.**
- An account's seat keys are the vault item `item.seat_kem`, an item of its own. It holds the
  Kyber1024 pair `SK`, the X25519 pair `SX`, the self key, the time it was made, and its counter
  `n`, which every rotation raises by one (§5.11). Every device of the account has it. It is
  published through an `AccountRequest` only after the vault save has settled, as the log key is
  (`logkey_unsettled`). It rotates (§5.11).
- `item.seat_kem` takes about 4.9 KB (the Kyber1024 secret key alone is 3168 bytes), and about
  9.7 KB while the old keys are kept during a rotation (§5.11). The old pair keeps its Kyber1024
  public key (1569 bytes) beside its private parts, since a welcome still waiting for the old keys
  salts its KEK with `ser(SK.pub)` (§3.2). The whole vault goes to a signing-in device in one
  `AuthStep::Vault` frame of at most `VAULT_TOTAL_BYTES` (56 KiB, `accounts.rs`), so C1 checks this
  budget against the largest vault the app writes today: about 29 KB is left.
- A connection has a per-connection seat pair: Kyber1024 plus X25519. That covers a guest, every
  member on a relay without accounts, and every seat in a voice room. The connection's `IK` signs the
  pair; when signed in, that is the account's `IK`, and the endorsement carries the account's current
  counter `n`. The pair is made at the first `EpochFetch` while unseated, sent with that frame, never
  renewed while connected, and gone with the connection.
- The prekeys are not used. They keep being renewed every hour and deleted 60 s later (`prekey.rs`),
  as README promises.
- **Kyber1024 now** (default): round-3 Kyber1024 as libsignal ships it, the KEM PQXDH uses. The KEM
  type is inside `tag(SK)` and named in the welcome context, so a later move to ML-KEM-1024 is a
  seat-key rotation and nothing else.

**Keyholder keys.**
- A keyholder (§4, §5.6) opens the keyring through a key pair of its own: Kyber1024 `KK` and X25519
  `KX`. It is never the account's seat pair, so the other devices of a keyholder's account hold no
  keyring, no seed and no bucket key.
- A desktop app makes one keyholder pair per relay the first time it takes a text keyholder role
  there. It keeps the pair in its local store beside its local floor (§5.7), never in the vault, and
  endorses it with origin 0x03 and the account's counter `n` (§11.8).
- Every other keyholder uses its connection's seat pair: guests, browsers, and every keyholder of a
  voice room. That makes it a **connection keyholder**, which leaves the set when its connection
  ends, unless it is the last entry (§5.6). A browser keeps no local store this design relies on, so
  it is one too. A signed-in browser,
  whose text seat is the account's, makes a connection pair when it volunteers
  (`KeyholdVolunteer`, §9), endorsed with origin 0x02.
- A desktop's pair is replaced at every seat-key rotation of its account (§5.11).

**Names.**
- `m` is a member id: `Account(account id)` or `Conn(user id)` for a connection's own seat.
- A **seat** is `(m, tag(SK), tag(SX))`. New seat keys on an account make a new seat.
- `K` is a keyholder: one entry of the keyholder set, a member id with its keyholder keys. An
  account that holds keys on two desktops is two keyholders. In contexts, `K` is the entry's member
  id, and `tag(KX_K)` tells the entries of one account apart.
- `w = (m, u)` is a writer: its seat's member id and its connection's user id `u`. Two devices of
  one account are two writers on one seat.
- `group` is the group id (§11.1). `k` is the group kind, text `t` or voice `v`. Every context
  carries `k`, so a text group and a voice group never share a key, even under one id.
- `tag(x)` is the first 8 bytes of `SHA-256("voipc-gk/v1/tag|" ‖ ser(x))`. `ser` is libsignal's
  serialization with its type byte (§11.2).

## 3. Primitives

Notation:
- `‖` concatenates bytes.
- `ctx(name; …)` is the context string of §11.1: the label `voipc-gk/v1/<name>`, then the named fields,
  each after a `|`.
- `HKDF(ikm, info)` is HKDF-SHA256 with an empty salt. Where a salt is used, it is written out.
- Every HKDF output is 32 bytes: `s_m`, `RB`, the ratchet, `KEK`, every AEAD key, `confirm` and the
  media key.
- `AEAD(key, c, x)` is AES-256-GCM with a random 96-bit nonce and the bytes of the context `c` as AAD
  (`aead.rs`). It gives `iv(12) ‖ ct ‖ tag(16)`: 60 bytes for a 32-byte `x` (`ROW_BYTES`).
- Wherever a key is derived for an AEAD, the HKDF info and the AAD are the same context string.
- `XEdDSA(IK, msg)` is libsignal's variant: `calculate_signature` and `verify_signature` of its
  `curve25519` module. It does not negate the private key. It keeps the Edwards public key's sign
  bit in the top bit of the signature's last byte. A check reads `S` from the last 32 bytes with
  that bit cleared, little-endian, and refuses `S ≥ ℓ` (§3.12) before libsignal checks the rest.
- Every opener refuses an opened key, seed or `KRK` of 32 zero bytes. It refuses an X25519 public
  key of low order, as `log.rs` does. That covers identity keys too: an `IK` of low order signs and
  endorses nothing, since XEdDSA under it takes forgeries anyone can make.

### 3.1 Member secret

```
s_m = HKDF(seed_s, ctx(member; k, group, gen, s, m, tag(SK_m), tag(SX_m)))
```

### 3.2 Hybrid welcome, from keyholder `K` to recipient `R`, carrying `P`

The recipient is a seat `m`, with `RK = SK_m` and `RX = SX_m`, or, for a keyring welcome, a
keyholder `K'`, with `RK = KK_K'` and `RX = KX_K'`.

```
(ct_q, ss_q) = Kyber1024.Encaps(RK)
eph          = X25519 key pair made for this welcome
ss_x         = X25519(eph, RX)
ss_k         = X25519(KX_K, RX)
salt         = SHA-256(ser(ct_q) ‖ ser(eph.pub) ‖ ser(RK.pub) ‖ ser(RX.pub) ‖ ser(KX_K.pub))
KEK          = HKDF-SHA256(salt, ikm = ss_q ‖ ss_x ‖ ss_k, info = c)
welcome      = ser(ct_q) (1569) ‖ ser(eph.pub) (33) ‖ AEAD(KEK, c, P)
```

There are three kinds, told apart by the context:

| Kind | `P` | Context `c` | Bytes |
|---|---|---|---|
| Seat | `s_m ‖ BK(b,v)` | `ctx(welcome; k, group, gen, s, kyber1024, seat, b, v, m, tag(SK_m), tag(SX_m), K, tag(KX_K))` | 1694 |
| Seed | `s_m` | `ctx(welcome; k, group, gen, s, kyber1024, seed, m, tag(SK_m), tag(SX_m), K, tag(KX_K))` | 1662 |
| Keyring | `KRK` | `ctx(welcome; k, group, gen, s, kyber1024, keyring, e, KS, K', tag(KK_K'), tag(KX_K'), K, tag(KX_K))` | 1662 |

- A seat welcome seats `m` in bucket version `(b, v)`, the version the commit that carries it made.
- A seed welcome carries `s_m` under the new seed `s` of a seed roll and nothing else. It changes no
  bucket, so its context names none (§5.6).
- `KS` is the digest of the keyholder set this `KRK` is for (§11.6). `e` is the epoch whose opening
  header set it, and `s` the head's `seed`.
- It is the concatenation combiner, with the ciphertext and every public key in the salt: the shape
  X-Wing takes.
- An attacker must break both Kyber1024 and X25519 to open it.
- `ss_k` authenticates it. Only `K` or `m` can make a welcome that opens, so the relay can hand no
  member an `s_m` or `BK` of its choosing, and no keyholder a `KRK`. This rests on X25519 alone.

### 3.3 Row, which seats `m` in bucket version `(b,v)`, made by keyholder `K`

```
RB      = HKDF-SHA256(salt = ser(KX_K.pub) ‖ ser(SX_m.pub),
                      ikm  = X25519(KX_K, SX_m) ‖ s_m,
                      info = ctx(rowbase; k, group, gen, s, m, tag(SX_m), K, tag(KX_K)))
row     = AEAD(HKDF(RB, c), c, BK(b,v))        c = ctx(row; k, group, gen, s, b, v, m, K)   → 60 B
```

- `RB`, the row base, is the same for every row from `K` to `m` under seed `s`. Both ends compute it
  once and keep it, so a row after the first costs one HKDF and one AES-GCM.
- A member keys a kept `RB` by `(K, tag(KX_K), s)`, never by `K` and `s` alone (default,
  2026-11-17). After a KeyholdersReplace (§4.3) the same member id has a new `KX`, and an `RB` of the
  old pair must not stand in for the new one.
- Classical half: the static DH between this keyholder's `KX` and `m`'s `SX`.
- Post-quantum half: `s_m`, which reached `m` only in a welcome.
- A row uses the newest seed its seat was given a welcome under (§5.6). Its context names it.
- A removed keyholder still holds `seed_s`, so it can derive every `s_m` under `s`. It still cannot
  open rows another keyholder made, because those need that keyholder's DH. Opening them takes both,
  until the seed rolls (§5.6).
- A quantum attacker breaks the DH half. With `seed_s` too (from a removed keyholder, say), it opens
  every row under `s`, those made after the removal included, until `seed_floor` passes `s` (§5.6,
  §6).

### 3.4 Seal of `CK_e` for bucket version `(b,v)`

```
seal = AEAD(HKDF(BK(b,v), c), c, CK_e)          c = ctx(seal; k, group, gen, e, D_e, b, v)   → 60 B
```

`D_e` is the digest of epoch `e`'s opening header (§4.1), so a seal opens only with the header it
was made for.

### 3.5 Ratchet, used only at a promotion (KeyholdersAdd)

```
BK(b,v') = HKDF(BK(b,v), ctx(ratchet; k, group, gen, e, b, v, v'))
```

`v'` is the new version's random id and `e` the promoting epoch. It is one way: whoever holds
`BK(b,v')` cannot go back to `BK(b,v)`, so a new keyholder opens no seal from before its promotion.

- A ratchet version keeps the `made` time of the version it came from, so promotions never put off
  the hourly re-key by rows (§5.5).
- A ratchet binds its epoch, so a rebase never reuses one: it ratchets again under the new epoch, with
  a new `v'` (§5.6).

### 3.6 Key confirmation

```
confirm = HKDF(CK_e, ctx(confirm; k, group, gen, e, j))     → 32 B, in every header
```

It is a PRF output under `CK_e` and shows nothing of it. A member who opened `CK_e` from a seal checks
it against the signed header, so the relay cannot get a key it chose taken.

### 3.7 Keyring

The keyring holds what keyholders share (§11.6): the live seeds, `CK_e`, and per bucket version
`(b, v, BK, seats, list digest, made)`.

```
base_e    = AEAD(HKDF(KRK, c), c, keyring at (e, 0))      c = ctx(keyring; k, group, gen, e, 0, s, KS, base)
delta_e,j = AEAD(HKDF(KRK, c), c, buckets added at (e, j)) c = ctx(keyring; k, group, gen, e, j, s, KS, delta)
H_e,0     = SHA-256("voipc-gk/v1/keyring-hash|" ‖ 0³² ‖ SHA-256(base_e))
H_e,j     = SHA-256("voipc-gk/v1/keyring-hash|" ‖ H_e,j-1 ‖ SHA-256(delta_e,j))
```

- Every opening commit uploads a new base, and every Join commit a delta.
- Header `(e, j)` carries `keyring_hash = H_e,j`.
- A keyholder takes a keyring only if all of these hold:
  - the hash chain matches the head's `keyring_hash`;
  - the base and every delta open under contexts built from the head's `gen`, `e` and `seed` (as
    `s`) and the `KS` of the head's keyholder set, each delta with its own position `j`. The
    context binds these; nothing is taken from the plaintext for them;
  - the base's own fields `gen` and `epoch` are the head's, its `join` is 0, and its `seeds` hold
    exactly the numbers from the head's `seed_floor` to its `seed`. Each delta's `join` field is its
    position `j`;
  - its `ck` passes the head's `confirm`;
  - the bucket root recomputed from its entries is the head's `bucket_root`, and the seats of its
    connections pool add up to the head's `conn_seats`;
  - for a keyholder that held the parent's keyring: the seeds it carries over, and the `BK` of every
    version it keeps unchanged, equal the keyholder's own copy. So a KeyholdersReplace, or any other
    commit, cannot hand the other keyholders a seed or bucket key of its own choosing (§5.11).

### 3.8 Writer blob

```
sig  = XEdDSA(IK_w, ctx(writer-sig; k, group, gen, e, D_e, w) ‖ "|" ‖ SKDM)
blob = AEAD(HKDF(CK_e, c), c, len(SKDM) u16 BE ‖ SKDM ‖ ser(IK_w) (33) ‖ sig (64))
                                                         c = ctx(writer; k, group, gen, e, D_e, w)
```

The SKDM's distribution id is `dist(group, gen, e, D_e)` (§5.8), so libsignal files each epoch's
sender key on its own, and the two halves of a fork apart.

### 3.9 Chain seal (kept history)

```
chain_seal = AEAD(HKDF(CK_e, c), c, state)        c = ctx(chain; t, group, gen, e, D_e, owner, chain, index)
```

`owner` is the writing account, as in `log.rs` chains. `index` is 0, or 1 for a chain with a
sharer's back-link (§5.10).

### 3.10 Media key (voice)

```
MK = HKDF(CK_e, ctx(media; v, group, gen, e, D_e, m, tag(SX_m), stream))
```

- `(m, tag(SX_m))` is the sender's voice seat: its member id and its connection's seat pair. The
  sender derives its key from its own seat, which no relay chooses.
- A receiver learns each sender's seat from the room's roster, which the relay sends as
  `VoiceSeats` (protocol 26). A roster that lies makes that sender's packets fail to open, and does
  nothing else.
- `stream` is the sender's random 32-bit stream id, in the packet.
- The relay's session id `sid` stays in the AAD (`build_aad`) as today, but not in the key.
  `media_keys.rs` took it out of the nonce because a relay can give two members the same one, and
  the same holds for the key.
- Each sender seat and stream has its own key, so two senders whose stream ids collide never share a
  (key, nonce), whatever ids the relay hands out. That also fixes a weakness in today's
  one-key-per-room design.

### 3.11 Self-rows (accounts)

A self-row is what an account keeps of its own secrets, so its other devices and later sessions can
open them. It is sealed under the random self key from `item.seat_kem`, never under `self_key`, which
derives from an X25519 private key, and never under a key derived from KEM key bytes.

```
self_row    = AEAD(HKDF(self, c), c, s_m)          c = ctx(self; k, group, gen, s, m, tag(SK_m), tag(SX_m))
history_row = AEAD(HKDF(self, c), c, list of (K, tag(KX_K), RB))
                                                   c = ctx(self-history; k, group, gen, s, m, tag(SK_m), tag(SX_m))
```

- A member writes a self-row only after a row or seal under that `s_m` opened and `confirm` passed.
  The `s_m` must be the one a confirmed key came through: the keying's own `BK` opened the seal
  whose key `confirm` checked. Until then nothing of the keying is stored (`BK`, `s_m`, row base).
  A seed welcome's `s_m` waits until a row under it opens to a confirmed key: at most 4 for one seat
  and seed, and at most 8 seat-and-seed pairs in all, the lowest seed dropped first (`member.rs` `key_in`, `pend_s_m`; tests
  `no_self_row_is_written_for_an_s_m_no_confirmed_key_came_through`,
  `a_welcome_whose_seal_fails_confirm_leaves_the_seats_s_m_as_it_was`).
- History rows exist only in groups that keep history (§5.10, §5.11). They let the account open rows
  made to seat keys whose private parts it has deleted.
- A guest keeps nothing past its connection.

### 3.12 Header digest and signature

```
D   = SHA-256("voipc-gk/v1/digest|" ‖ body)      body = the postcard encoding of §11.3
sig = XEdDSA(IK_signer, "voipc-gk/v1/header-sig|" ‖ D)
```

- The signature is not part of `D`. libsignal's XEdDSA also accepts `(R, S + ℓ)` for nearly every
  signature, so a `D` over the signature would let anyone make a second valid header with another
  digest. Our wrapper also refuses any `S ≥ ℓ`.
- Evidence of a fork compares bodies, never `D` alone.

## 4. Epochs and headers

### 4.1 Generations, epochs, joins

- A group has a **generation** `gen`: 16 random bytes. A new generation starts:
  - when the group's first keyring is made;
  - for every group at a new database incarnation, after a restore (§5.7);
  - when a channel is purged, which drops its group rows;
  - in a memory-only group (§5.12), at each relay start;
  - in a voice room, when it empties, or when no keyholder is left in it (§5.9);
  - on a relay without accounts, when no keyholder is online;
  - for every group, when the relay starts with `group_key` on after a run with it off (§5.14).
- Within a generation, epochs `e = 1, 2, …` each have one `CK_e`.
  - An epoch begins with an **opening header** (`join = 0`). `D_e` is that header's `D`. Its epoch
    is its parent's plus one.
  - Join commits then follow, numbered `j = 1, 2, …`.
  - A Regenesis continues the count (`e + 1`) in the same generation.
  - The relay starts at most one opening commit per group every 2 s (`EPOCH_MIN_GAP`). That bounds
    how fast epochs can grow, which members check (§4.4 rule 3).
- Bucket ids `b` and version ids `v` are random u64.
  - A version id is drawn for each version a commit attempt makes. It never stands for another key
    or another seat set in the generation: a rebase may reuse a version from its stale attempt only
    with the same seats and the same `BK`, and never a ratchet version (§5.6).
  - A keyholder refuses to make an id its keyring already has.

### 4.2 Header

The exact encoding is in §11.3. Its fields:

| Field | Meaning |
|---|---|
| `group_kind`, `group`, `gen`, `epoch`, `join` | Where it stands |
| `kind` | Genesis, Regenesis, Fresh, Join, KeyholdersAdd, KeyholdersRemove or KeyholdersReplace (§4.3) |
| `time` | The signer's clock, unix seconds |
| `parent` | `D` of the header before it; zero for Genesis |
| `epoch_parent` | `D_e` of its epoch; zero on an opening header (its own `D` is `D_e`) |
| `kh_parent` | `D` of the last header that set the keyholders; zero for Genesis |
| `signer` | The signer's member id |
| `keyholders` | Only on headers that set them: up to 8 entries `(m, u, origin, n, IK, KX, tag(KK))`. `u` is the connection's user id, set for voice keyholders; `origin` says whether `KX` is a desktop's keyholder pair or a connection's seat pair; `n` is the endorsement's counter (§11.3) |
| `gated` | Whether the group is gated. It changes only at an opening header |
| `seed`, `seed_floor` | The newest seed number, and the oldest still in use (lower while a roll runs, §5.6) |
| `exits_upto` | The highest exit sequence number this header has dealt with (§5.4) |
| `seats`, `buckets` | How many seats and bucket versions the bucket root covers |
| `conn_seats` | How many of those seats sit in the connections pool. Always 0 in a gated group |
| `bucket_root` | Merkle root over every current bucket version `(b, v, pool, seats, list digest, via)`, §11.4 |
| `keyring_hash` | `H_e,j` of §3.7 |
| `names_hash` | Gated groups: a running hash over every `added` list, each bound to its header's `time`, `epoch` and `join`, since the generation's Genesis, or since the opening header that turned `gated` on (§4.4 rule 4, §11.3). Open groups: zero |
| `added` | Gated groups: `(m, IK, tag(SK), tag(SX), n, made)` per new seat, with its endorsement's counter and time. Open groups: a count |
| `removed` | Gated groups: `(m, tag(SK), tag(SX))` per seat removed, at most 768 (§5.4). Open groups: a count |
| `confirm` | §3.6 |

- The seat-list digests are in every header through `bucket_root`.
- A member gets only its own leaf with its inclusion path; keyholders get the whole list.

### 4.3 Header kinds

| Kind | New epoch? | New `CK` and confirm? | Seed | `KRK` | Buckets | Seals to | Who may sign |
|---|---|---|---|---|---|---|---|
| Genesis | Yes: new `gen`, `e = 1` | Yes | New, `s = 1` | New | The signer's own | The signer's bucket | The volunteer the relay asked; members apply the rules for a new generation (§5.7) |
| Regenesis | Yes: `e = parent.e + 1`, same `gen` | Yes | New, `s = parent.seed + 1`, `seed_floor = s`: a roll start, exempt from the 24 h rule, that clears a due roll (§5.6) | New | All new; members are re-seated by welcomes as they fetch | The new buckets as Join commits make them | A volunteer, in a stored group (a `c:` id on a relay with accounts), after the Regenesis wait with no keyholder online, and `time ≥ parent.time` + that wait: 2 min when every entry of the set in force is a connection entry (origin 0x02) and no Regenesis started that set in the last hour, else 1 h (§5.6, "fast new start"). The relay's validator refuses one dated more than `CLOCK_SLACK` before its own clock (§5.7) |
| Fresh | Yes | Yes | Same, or a due roll starts when the roll slot is open (`seed` rises, §5.6); a roll may finish (`seed_floor` rises) | Same | New versions for buckets with leavers, the refresh slice, merges, and every version over 1 h old (§5.5) | Every current version | A keyholder of the parent's set |
| Join | No: `j + 1` | `confirm` of the same `CK_e` | Same | Same | New buckets for joiners | The new versions only | A keyholder of the parent's set |
| KeyholdersAdd | Yes | Yes | Same, or a due roll starts when the slot is open; a roll may finish | New, welcomed to every keyholder | Every bucket ratchets in place (§3.5), except those re-versioned by rows for exits; a bucket its exits empty is dropped (§5.3) | Every current version | A keyholder of the parent's set |
| KeyholdersRemove | Yes | Yes | Text: a roll becomes due, and starts here if the slot is open; else a roll may finish. Voice: a roll starts here, always (§5.6). This commit's rows still use `s` | New, welcomed to every keyholder | Every bucket re-versioned with a fresh `BK` by rows | Every current version | A keyholder of the parent's set that stays in the new one |
| KeyholdersReplace | Yes | Yes | Same: it never starts or finishes a roll | New, welcomed to every keyholder from the old pair (§5.11) | As Fresh: new versions for buckets with leavers, the refresh slice, merges, and every version over 1 h old | Every current version | The keyholder whose entry it swaps (§5.11) |

**Seed rolls by kind** (§5.6, default, 2026-11-17). A roll may start at a Fresh, a KeyholdersAdd or a
KeyholdersRemove when the group's roll slot is open, and at a Regenesis always. It never starts at a
Join or a KeyholdersReplace. A roll may finish (`seed_floor` rises to `seed`) at any opening commit
except a KeyholdersReplace. In a voice group the slot does not apply: every KeyholdersRemove starts a
roll, and nothing else does.

- Any entry leaving the keyholder set makes a KeyholdersRemove: a removal, a resignation, a
  connection keyholder's disconnect, or a device removed from its account.
- A keyholder replacing its own pair at a seat-key rotation makes a KeyholdersReplace (§5.11). It is
  a Fresh commit plus the swapped entry and a new `KRK` (default, 2026-11-17).
  - It swaps exactly one entry, its signer's, named by that entry's old `tag(KX)`, for one with the
    same member id, user id, origin (0x03: connection keyholders never rotate) and `IK`, a higher
    counter `n` and a new pair. Nothing else in the set changes.
  - The header has no field for the old entry: a member reads the swap off the parent's keyholder set
    and the new one, which differ in that one entry. The old `tag(KX)` is in the contexts of the
    Replace's keyring welcomes, which the old pair makes (C1 builds it so).
  - It makes the rows a Fresh makes: for leavers, the refresh slice, merges, and the 1 h re-key of
    §5.5. It never changes the seed: the keyholder stays one, and already held the seed and the bucket
    keys.
  - The new `KRK` keeps the old pair, whose private parts go next, from opening any later keyring
    (owner, 2026-11-17).
  - **Authorising the swap** (default, 2026-11-17). Its keyring welcomes are made from the old pair,
    which proves to the other keyholders that the signer held it. Every other welcome, and every row,
    in and after the Replace comes from the new pair. A keyholder takes the new keyring only if those
    welcomes open as from the old pair, and only under §3.7's check of the seeds and bucket keys it
    carries over.
- A keyholder never signs a commit that removes its own entry without replacing it, because it would
  know the new seed and `KRK`. It resigns by asking the relay, and another keyholder commits.
- It does sign the KeyholdersReplace that swaps its own pair. It stays a keyholder, so it is meant
  to know the new `KRK`, and a group whose only keyholder rotates does not stall.

### 4.4 Taking a header

A member takes header `H` only when all of these hold. Rules 4, 6 and 8 also say what a writer checks
when it folds the names, and what a failed check does.

1. **Form.** The body re-encodes to the same bytes. Its lists are sorted and without duplicates. It is
   within its size cap, and its group kind and group are the expected ones. The signature has `S < ℓ`.
2. **Signer.**
   - Genesis and Regenesis: the rules of §5.7, and the signer's `IK` matches its pin, or is pinned
     now (TOFU, as everywhere else).
   - Any other kind: the signer is in the keyholder set of the header `H.kh_parent` names. A header
     that sets keyholders is signed by a member of the set before it, under §4.3's rule for its kind.
3. **Chain.**
   - An opening header has `epoch = parent.epoch + 1` and `join = 0`. A Join header has its parent's
     epoch and `join = parent.join + 1`. A member checks this for every header whose parent it holds,
     and the relay's validator checks it always.
   - Usually `H.parent` is the member's floor `D` (§5.7), and that is enough.
   - Otherwise, when the floor is outside the relay's window, the member walks the keyholder chain.
     From `H.kh_parent` it follows `kh_parent` links back to the keyholder header its floor names
     (the floor's `kh`). Each link must be signed as in rule 2, and the walk takes at most 4096 links.
     Then `(H.epoch, H.join) > (floor.epoch, floor.join)`. In the floor's own epoch, `H.epoch_parent`
     must also be the floor's `D_e`.
   - **Epoch bound.** A header taken by a walk has
     `H.epoch ≤ floor.epoch + ⌈(H.time − floor.time + CLOCK_SLACK) / EPOCH_MIN_GAP⌉`, with
     `EPOCH_MIN_GAP` 2 s (§4.1). With rule 7, a header signed with a made-up epoch can raise a floor by
     at most the epochs the elapsed time allows, never to the end of the u32 range.
   - A device with no floor for the group walks back to the newest Genesis or Regenesis on that chain
     and takes it under §5.7's rule for a device with no floor.
   - A walk takes the keyholder chain on its signers' word and skips the headers between. Rule 4 still
     makes a gated writer fold every name in them before it posts.
4. **Gated names (writers).** In a gated group the names protect writers: they show who will read
   what a writer posts (owner, 2026-11-17).
   - A member takes headers without the names. One that only reads fetches no names but the `added`
     list of the Join header that seated it. Its app can still show the list on demand, checked the
     same way.
   - A writer keeps a **names floor**: the header position and `names_hash` it last folded to. Before
     each post it **folds**: it takes every `added` list between its names floor and the head it posts
     under, each with its header's `time`, `epoch` and `join`, and checks that they fold from the names
     floor's `names_hash` to the head's `names_hash` (§11.3). It checks every entry under rules 6 and 8
     as they stood at that entry's header `time`. When all pass, its app shows the new readers and the
     names floor moves to the head; until then it holds the post.
   - It gets the lists as the Join headers themselves or as the bare lists (`EpochNamesIn`, §9), and
     skips none, whether it took the headers link by link or walked. Lists that do not fold are the
     relay's doing: the writer refuses them, asks again, and holds its posts meanwhile.
   - **A failed fold** (default, 2026-11-17) is an entry that fails rule 6 or rule 8.
     - The writer holds its posts in that group, and its app says why: a guest seat, a pin mismatch,
       or a flagged counter. Held posts drop at `HOLD_MS`, as always.
     - Its names floor stays before the list that failed until an opening header after that list names
       the seat in `removed`. Then the entry counts as named and gone, and the fold goes on.
     - The relay sends the `removed` lists between with the names, each in the signed opening header
       that carries it, and keeps them as it keeps the `added` lists. The writer takes each such header
       as any header (rules 1–3).
   - A writer whose names floor is in an older generation folds every list since the new generation's
     Genesis, or since the opening header that turned `gated` on. After a re-seat that is every seat,
     once, before its first post.
   - **Delivery** (default, 2026-11-17). The relay pushes each gated Join's `added` list to every
     writer with a chain in the current epoch, as it sends `EpochExit` (§5.4). So every new reader
     reaches the app of every writer seated before it:
     - under an honest relay, before that writer's next post;
     - under a hostile relay, at the latest before its first post in a later epoch, at most 70 min on
       (§5.5). A writer folds to the head it posts under, and a later epoch's opening header descends
       from every Join before it. Within one epoch, a relay that withholds the pushed lists and the Join
       headers can delay the names by up to that epoch.
   - **Gone.** The relay keeps the lists for 90 days, the seat-expiry time, and also the one step
     before the oldest of them (§11.3: the `names_hash` before it, its header's `time`, `epoch` and
     `join`, and its list's digest).
     - It may answer that the names since a names floor are gone only when that floor's `time` is more
       than 90 days old by the writer's own clock. It then sends its 90-day tail of lists and the step
       before it.
     - The writer takes the answer only if that step's `time` is more than 90 days old by its own clock,
       less `CLOCK_SLACK`, and the step and the tail fold to the head's `names_hash`. Since each step
       binds its header's `time`, that proves the tail covers the last 90 days.
     - It checks and shows the tail's names as in any fold, moves its names floor to the head, and its
       app says that people joined more than 90 days ago whose names it was not shown. Only seats
       older than that stay unnamed.
   - A device with no names floor starts at the first head it takes. Who was seated before it is the
     group as it found it, taken on trust as the keyholders are. If the generation began within the
     relay's 90 days, its app can ask for every name since then and check them the same way.
   - Readers in gated text groups, and every member of an open group, may skip Join headers, except a
     newcomer's own. In a gated voice room every member folds the names as they come (§5.9).
5. **Confirm.** Once the member holds `CK_e`, `confirm` checks out. A relay that mixes seals from two
   commits is caught here.
6. **Gated checks.**
   - `gated` changes only at an opening header. A device with a floor reports a change from gated to
     open.
   - In a gated group, `conn_seats` is 0 in every header.
   - Who checks the `added` entries: a writer at its fold, a keyholder in every header it takes, every
     member of a gated voice room as the Join headers come (§5.9), and an app that shows the list on
     demand. Readers of a text group check none.
   - In each such list no entry is a connection, and every `IK` the device has a pin for matches that
     pin. At a fold an entry is checked against the pin as it stood at its header's `time`, where the
     device knows it. An `IK` whose pin changed since, where the device does not know the old pin, is
     shown, not refused (default, 2026-11-17). Such an entry is named to the writer too, as a checked
     one is (`names.rs` `readers`).
   - What a failure does: at a writer's fold, it is a failed fold (rule 4). A keyholder refuses the
     header and says why, and takes the next opening header that names the refused seat in `removed`.
     In a voice room the app warns (§5.9). On demand, the app shows the entry as failed.
7. **Time.** `H.time` is at most 10 min (`CLOCK_SLACK`) ahead of the member's own clock.
8. **Counters.** Who checks them: a writer at its fold, for each `added` entry; a keyholder, for each
   `added` entry in a header it takes; every member, for each keyholder entry the parent's set did
   not hold.
   - An entry is checked against the counters known at its header's `time` (default, 2026-11-17). A
     counter `n` below the highest this device has seen for that account (§5.11) is flagged only if
     the header's `time` is after that newer endorsement's `made` plus `CLOCK_SLACK`. So a writer that
     folds names from before a rotation does not flag the old seat, its own account's included.
   - A flagged `added` entry fails a writer's fold (rule 4). A flagged entry makes a keyholder, or a
     member checking a keyholder entry, refuse the header.
   - A flagged entry for the device's own account makes the app warn: an old seat key of this account
     was seated. Readers of a text group fold nothing, so there the account's own app sees this only
     where it writes (§5.11).

The relay keeps these headers:

- every header that set keyholders, the Genesis, and each Regenesis with its parent, for the
  generation's life;
- the header that last raised `seed`, so a keyholder can tell when a roll is due (§5.6);
- every header of the current epoch, and the last 64 of any kind;
- each opening header while its epoch is current, and while a kept chain references it (§5.10);
- the last Join of each epoch a kept chain references, with that opening: a seat a Join added
  reads the epoch's kept posts there (§5.10);
- in gated groups, for 90 days: every `added` list with its header's `(time, epoch, join,
  names_hash)`, every opening header whose `removed` list is not empty, and the step before the
  oldest of those lists (rule 4).

It pushes every header that sets keyholders, and every Genesis and Regenesis, to every member online
that is seated in the group or was seated in its previous generation. So a removal reaches members
without their asking. In gated groups it also pushes each Join's `added` list to every writer with a
chain in the current epoch (rule 4), and in gated voice rooms each Join header to every member
(§5.9).

## 5. Flows

### 5.1 Genesis

When a member needs a key in a group with no keyring (a writer, or a reader whose `EpochFetch` finds
none), the relay sends `EpochDue{start: Genesis}` to a volunteer, chosen under §5.6's rules; in a
voice room that is the lowest user id. The volunteer makes:
- `seed_1`, `KRK` and `CK_1`;
- one bucket for itself, and a welcome to itself;
- a Genesis header, signed.

It becomes the first keyholder, and then seats the member that asked, by a Join commit. Members take
the new generation under the rules in §5.7.

### 5.2 Seating

Text groups seat lazily: following a channel costs nothing until someone writes, as today. A member
is seated the first time it needs `CK`:
- it has a post it cannot open;
- or it wants to write and holds no `CK` for the current epoch.

Two exceptions:
- An account that keeps the channel's history is seated eagerly at `LogJoin`, online or not. At most
  `kept_seats` per channel are seated that way; the rest are seated lazily.
- Voice seats are taken at room join (§5.9).

The member sends `EpochFetch{group, have}`. A connection attaches its seat pair the first time. With
no seat, the relay queues it for the next join batch (every 2 s; in a voice room every 250 ms, open
choice 7), and the member holds the post (`HOLD_MS`, 60 s, unchanged).

**Before it encapsulates or makes a row,** the keyholder checks each joiner:
- the endorsement of `SK` and `SX` verifies under the joiner's `IK`;
- for an account, the `IK` matches the keyholder's own pin for it, or is pinned now, and the
  endorsement's counter `n` is at least the highest it has seen for that account (§5.11);
- in a gated group (by the head's signed `gated`), the joiner is an account, not a connection;
- the seat is not already in its keyring.

A joiner that fails is left out, and the relay is told why. So a relay cannot get a guest into a
gated group's commit and make every member refuse the epoch.

**A join commit** on `(e, j)`:
- puts the batch into new buckets of at most 62 seats each, accounts and connections in separate
  pools;
- gives each joiner a seat welcome, or a row if the relay says it already holds `s_m` under the
  current seed (a returning account);
- in a stored group, also makes a 60-byte row to each new account seat beside its welcome (open
  choice 24, 2026-11-18). Every version a seat is in then has a row for it, or ratchets from one
  that has, so kept epochs stay readable from `s_m` (its self-row) after the welcome or the old
  KEM key is gone (§5.10). It costs one `RB` (about 29 µs) and 60 B per joiner;
- seals `CK_e` to each new version;
- uploads a keyring delta;
- signs a Join header with `join = j + 1` and the new `bucket_root`; in gated groups, `added` lists
  each joiner with its `IK` and counter, and `names_hash` takes in that list with the header's own
  `time`, `epoch` and `join` (§11.3).

**Seats a commit sealed but nobody named.**
- The keyholder keeps, on the device, every seat it sealed to in a Join commit `J` until it takes a
  later header that descends from `J`. "Named" means: inside `J`'s `bucket_root` (and in its `added`
  in gated groups), `J` taken by the relay, and `J` an ancestor of the heads the relay goes on to
  show. The relay saying it took `J` is not enough.
- Keyholders take every header link by link, since they commit on the head. So each later `EpochDue`
  or `EpochIn` shows whether `J` is still an ancestor.
- After `EpochStale`, its next commit on that group names those seats again (§5.6, rebase), or is an
  opening commit, which ends their `CK_e`.
- If the head moves on without `J` or without those seats, or no later header reaches the device
  within 70 min (the writers' epoch-age limit, §5.5), it warns its user: "This device gave #x's keys
  to N people the server then did not list."
- What remains is in §6: for at most that whole epoch (≤ 70 min), a seat the relay chose can hold
  `CK_e` with no taken header naming it. It reads the epoch from its start, through the earlier
  writers' blobs. The relay can repeat this in every epoch, with any keyholder, and each time one
  keyholder device sees it and warns.
- Writers and newcomers do nothing extra for this. Writers keep one chain per epoch, and a newcomer
  still reads its epoch from the start.
- Closing that fully would need a `CK` derived per join *and* every writer starting a new sender-key
  chain after each join that seats someone. A newcomer could then no longer open the post that made
  it ask, which breaks lazy seating. §7 Q4 asks about it.

**Newcomers read the current epoch from its start.**
- Under an honest relay, that start is at most 60 s back in a group of one bucket and 5 min back
  otherwise (§5.5), or the last exit.
- Under a hostile relay that withholds refreshes, it is at most 70 min back, the writers' epoch-age
  limit (§5.5).
- Today a newcomer reads at most about 60 s back (`ROUND_LIFE_MS`).
- The window is deliberate: a newcomer seated in a later epoch could never open the post that made it
  ask.

### 5.3 Buckets never grow

A bucket version's seats are fixed when it is made, so:
- someone new always gets a new bucket and never joins an existing version, which would let them
  open that version's earlier seals;
- someone gone gives their bucket a new version without them;
- a bucket with nobody left is dropped, which costs no row.

Join batches and exits therefore leave small buckets behind. At every opening commit the keyholder
merges and repacks them within each pool, by the rules `sync/chains.rs` uses today (`SMALL_SEATS` 16,
`SMALL_BUCKETS` 16, `BUCKET_SEATS` 62):
- **Merge.** A bucket under 16 seats is small. Once a pool has 16 or more small buckets, all of them
  merge: their members are re-seated together in new full buckets. With fewer, none merge.
- **Repack.** When the pool's bucket count `B` passes `1.5 × N/62 + 16`, the smallest other buckets
  whose seats fit one bucket are re-seated into one, if that takes at least two.
- Re-seating a member costs one 60-byte row: `s_m` is already theirs, so no welcome.
- Between two opening commits, at most 150 small buckets build up per pool (5 min of 2 s batches),
  on top of up to 15 left from the last merge. So a merge costs at most 165 × 15 = 2475 rows, about
  150 KB, and a repack at most 62 rows.
- So a pool's other buckets stay near `1.5 × N/62 + 16`, one repack per opening commit, and its
  small ones at 165 or fewer. §8 uses `B = ⌈N/62⌉` (1613 at 100k), the fully packed figure; C6
  measures the real one.

**Lists.**
- The keyring keeps a seat-list digest per version, computed like `list_digest` (§11.5), not the
  lists themselves. The relay keeps the lists.
- To re-version, merge or re-key a bucket, the keyholder takes the list from the relay. It takes a
  list only when its keyring names it, by digest and seat count, and refuses any other: the relay
  then gets a `NOT_READY` decline, not a signature.
- Every opening commit reads the lists of the buckets it drops, so the keyholder's own check sees
  every seat a drop removes. A drop may take only seats the exits name (validator rule 10), and a
  KeyholdersAdd that carries the exit emptying a bucket drops it (tests
  `an_opening_asks_the_list_of_each_bucket_it_drops_and_drops_no_seat_no_exit_names`,
  `a_promotion_carrying_the_exit_that_empties_a_bucket_drops_it_and_is_taken`).
- It refuses any new version whose seats are not a subset of the old one's. Only Join buckets hold
  new seats, and in gated groups those are named.

### 5.4 Exits

Going offline is not an exit for an account. These are exits:
- a leave: an account's seat ends when its last connection leaves the channel (or `LogLeave`); a
  connection's seat ends when it leaves;
- a kick, ban (`OUT_OF_LOGS`) or eject of the account or connection;
- a provider identity reset, a gate unseat, an evict;
- a connection's end, for a connection seat;
- a seat-key rotation, which ends the old seat (§5.11);
- seat expiry: a seat not used for 90 days, meaning no fetch and no post in that group;
- a purge of the channel (`purge_begin`), which drops the group's rows; the next keyring starts a
  new generation.

The relay numbers exits per group with a sequence number `seq` (u64):
- An exit enters the open batch, which closes `exit_gap(N)` after its first exit. `N` is the group's
  seat count. It is 20 ms per seat, at most 36 s (`EXIT_GAP_MAX_MS`).
- The relay sends `EpochExit{group, seq}` when the exit enters a batch: to every writer with a chain in
  the current epoch, and to each writer that starts one while the exit is pending.
- Once the batch closes, it asks a keyholder with a deadline of 4 s, and the next one after that, so
  both fit inside `CHECK_WAIT_MS` (10 s).
- **Large batches in gated groups.** A gated opening header lists each removed seat (33 bytes), and
  a header body is at most 32 KiB. So a gated batch closes at 768 exits (about 25 KB of `removed`),
  whatever its gap. Later exits wait for the next batch, which opens at once, and their writers are
  told as each enters it. A ban wave, a gate unseat or the 90-day expiry sweep of 5000 seats takes 7
  opening commits, one after another.
- Open groups carry `removed` as a count, so their batches have no such cap.

The **opening commit** that deals with a batch:
- makes a new `CK_{e+1}`, and gives each bucket a leaver sat in a new version without them (≤ 61
  rows each);
- seals `CK_{e+1}` to every current version, and merges small buckets;
- sets `exits_upto` to the batch's last `seq`. A batch is always a prefix of the exits not yet dealt
  with, so `exits_upto` covers every exit up to it.

The relay's validator refuses an opening commit whose `exits_upto` covers an exit whose seat is still
in a leaf.

**A gate going on.** When an open group becomes gated, every connection seat is an exit (a gate
unseat).
- The relay first deals with those exits in opening commits while the group is still open, where
  `removed` is a count and has no cap. Only then does it ask for the opening commit that sets
  `gated = true`, with `conn_seats = 0`.
- A keyholder refuses to sign a gated header while its keyring still holds a connections-pool bucket,
  and says so in its answer. The relay's validator checks the same.
- So a hostile relay that hides the guests' exits gets no gated header at all: the group stays open,
  and members see it as open. No guest stays seated in a group the header calls gated.

**Writers.**
- Each writer starts a new sender-key chain at its first post of a new epoch.
- A writer told of exit `seq` keeps posting in the current epoch. If no opening header with
  `exits_upto ≥ seq` has arrived within `EXIT_GAP_MAX_MS + CHECK_WAIT_MS` (46 s) of `EpochExit`, it
  holds its posts and says the channel's keys are late. Held posts drop at `HOLD_MS`. Using the cap
  spares the writer from taking `N` on anyone's word.
- So under an honest relay a leaver reads for at most `exit_gap(N) + CHECK_WAIT_MS` after its exit
  is named, plus the commits of any full gated batches queued before its own. Whatever the relay does
  with commits, it reads never more than 46 s after a writer was told. This is today's window, kept on
  purpose. It covers text posts; voice is in §5.9.

**A relay that hides an exit** keeps the leaver seated with no bound, as today: refreshes re-key the
leaver's bucket with whatever seats the relay names. A hidden exit is the relay's choice whatever the
timers say.

### 5.5 Refresh and age limits

- **Refresh.** Every 5 minutes, and every 60 s while the group has a single bucket, the relay asks for
  a Fresh epoch even with no exits.
- **Bucket age.** Each opening commit re-keys, by rows with a fresh `BK`, every version more than 1 h
  old by the keyring's `made` time. A ratchet version keeps the `made` of the version it came from
  (§3.5), so promotions do not reset it. A refresh commit also re-keys at least the oldest twelfth of
  the buckets, so their ages spread out. An honest keyholder does this whatever the relay asks for.
- **Writer epoch-age limit.** A writer starts no post under an epoch whose opening header's `time` is
  more than 70 min behind its own clock (`EPOCH_AGE_MAX` 60 min plus `CLOCK_SLACK` 10 min).
  - It holds its posts and says the keys are late, as for exits. Readers show the same warning.
  - It is 1 h, not 5 min, so a channel stays writable while its keyholders are briefly away.
  - It matches today's `CHAIN_AGE_MAX_MS`.
- **Chain age.** A writer's sender-key chain also ends after `CHAIN_AGE_MAX_MS` (1 h) within an
  epoch: a new blob of about 230 bytes. An epoch lasts at most 70 min for writers, so a writer has
  at most two chains in one epoch, and the relay keeps both blobs (§5.8).

Under an honest relay and keyholder:
- a stolen `CK` heals within 5 minutes (60 s in a one-bucket group);
- a stolen bucket key heals within an hour.

Under a hostile relay, only the 70-minute epoch limit holds, and only for epoch keys, in a group of
any size. Bucket keys heal at the next opening commit that an honest keyholder makes. Hidden exits
stay unbounded (§5.4).

### 5.6 Keyholders

**Who volunteers.** These rules are part of the design, as is the switch's default. Keyholders are
named to members, and their headers show when they were online. A keyholder is one device or
connection (§2), so every rule below is per keyholder entry, not per account.
- **Desktop app:** volunteers by default. A Settings switch, "Help hold keys for text channels", turns
  it off; off means never in text groups.
  - **Voice rooms are not covered by it.** There every app in the room may be among the 2 lowest user
    ids and hold the room's keys while it is in the room, as every app may be today's minter. That way
    voice never waits for a volunteer.
- **Phone:** only in voice rooms it is in. It resigns cleanly when it leaves the room, so a removal is
  never caused by Android killing it in the background.
- **Browser:** in voice rooms it is in. In text groups only as a last resort: no account desktop
  volunteer is online, and the group has at most 10,000 seats, counted by its own `seats`. A browser
  is a connection keyholder (§2). In a text group it resigns once a header after its own promotion
  adds a desktop keyholder (origin 0x03).
  - A browser tab that is hidden or in a call still offers, ranked below a visible one out of a
    call, so a channel held only by browsers keeps its text keys while they talk (open choice 31,
    owner, 2026-11-19). It builds in short steps (§8).
- **Guests (connections):**
  - always allowed in voice rooms, on any relay;
  - in open text groups, only while no account volunteer that these rules allow there is online. A
    guest keyholder resigns once a header after its own promotion adds an account keyholder;
  - at most 2 guest keyholders in a text group;
  - never in gated groups.
- On a relay without accounts every keyholder is a connection keyholder.
- The relay applies the conditions on who is online. The volunteer's app checks what it can see
  itself, the keyholder set in the header and the group's `seats`, and refuses or resigns a role
  those do not allow.

**How many.**
- The relay promotes while fewer than 2 keyholders are online, up to 8 in the set.
- **Hand-over.** In text groups volunteers have ranks: account desktops, then account browsers, then
  guest desktops, then guest browsers. At any count, while a keyholder of a lower rank holds the role
  and a volunteer of a higher rank is online, the relay promotes that volunteer, one at a time. The
  lower keyholder then resigns under the rules above, once the replacement's KeyholdersAdd is taken.
- At 8, a promotion first removes the keyholder that has been away longest (a KeyholdersRemove).
- In text groups the relay chooses among volunteers by rank.
- Voice rooms choose by roster instead (§5.9).

**Promotion** (KeyholdersAdd):
- The relay proposes a candidate: `EpochDue{promote}`, which is its word.
- An online keyholder checks that the candidate is seated; that its keyholder pair is endorsed by its
  `IK` with a counter at least the highest seen for its account, and with the origin its kind needs
  (0x03 for an account desktop, 0x02 for a connection keyholder); and, for an account, that the `IK`
  matches its pin (or pins it now). In gated groups the candidate must be an account, and in text
  groups at most 2 keyholders may be guests.
- It then commits a KeyholdersAdd: a new epoch with a new `CK` and a new `KRK`, welcomed to every
  keyholder's own pair. Every bucket ratchets in place (§3.5) at no row cost, plus one seal per
  version.
- The new keyholder gets no bucket key and no keyring from before its promotion. It does get the
  seed (see below).
- The app shows the set in the channel's details ("Keys held by …"), within §5.12's limits.

**The keyring:**
- It holds the live seeds, `CK_e`, and every `(b, v, BK, seats, list digest, made)` (§11.6).
- It opens only through a hybrid welcome of `KRK` to a keyholder's own pair, never through an
  X25519-only row, `self_key` or the account's seat keys. So the other devices of a keyholder's
  account, browsers with no floor among them, can open none of it.
- The relay stores the base and deltas (§3.7) and one `KRK` welcome per keyholder. Both are chunked
  under the 64 KiB frame, up and down.

**Duty.**
- The relay asks one keyholder per due commit (`EpochDue`), in turn, with a deadline (§9). Once it
  passes, it asks the next one.
- The relay takes `EpochCommit{parent}` only when `parent` is its head. It checks this at the first
  frame and again at the last, and takes it from any keyholder of the head's set. The loser gets
  `EpochStale{head, reason}`.
- **Rebase** onto the new head, after `EpochStale`:
  - It draws a new `CK` for every attempt at an opening commit, so a leaver given a stale seal reads
    nothing of the epoch that wins.
  - It makes the seals and the header again, and the rows of any bucket the winner touched.
  - It may reuse a version from the stale attempt only if the new head did not touch that bucket, the
    version is not a ratchet (a ratchet binds its epoch, §3.5), and its seats are still the ones it
    wants. Then its id, `BK` and rows are reused.
  - If the winner rolled the seed, it makes everything again.
  - It names again the seats it sealed that are still unnamed (§5.2).

**Stalls and removal:**
- Any keyholder entry that misses or declines 3 deadlines in an hour is proposed for removal, and so is
  a desktop entry away 7 days.
- A connection keyholder's entry is proposed for removal once its connection ends: a connection
  pair never comes back.
- The relay never proposes the last entry of a set, and proposes an entry only when another entry
  that is online can sign its removal (a KeyholdersRemove's signer stays in the set). So when the
  last entry is a connection entry and its connection ends (a sole browser keyholder's reload, or
  a relay restart of a browser- or guest-held channel), the entry stays, nobody online can sign,
  and the group waits for a Regenesis: the fast new start below (`holders.rs` `removal_where`).
- When an account removes a device, the relay proposes the removal of that device's entries. So it
  does for an entry whose counter has been below its account's newest for 7 days: a device that never
  replaced its pair (§5.11). And so it does at once for an entry that a device of its account reports
  swapped by a KeyholdersReplace it did not make (§5.11).
- Another keyholder commits a KeyholdersRemove. That is a full re-key: a new `CK`, a new version of
  every bucket by rows and a new `KRK`, at once. In a text group it also makes a seed roll due; in a
  voice group it starts one (below).

**Seed roll:**
- **When one is due** (text groups).
  - A removal makes a roll due. A removal while a roll is due adds nothing; one while a roll runs
    makes the next roll due.
  - **Seed maximum age: 30 days** (default, 2026-11-17). A roll also becomes due when the current
    seed's roll started 30 days ago, by header `time` (for seed 1, the Genesis).
  - A Regenesis is a roll start, and clears a due roll.
- **One a day.** In a text group a roll starts at most once per group per 24 h (owner, 2026-11-17),
  counted by header `time` from the last roll start. A due roll starts with the first opening commit
  that may start one (§4.3) once that slot is open: the KeyholdersRemove itself when the last start is
  long enough ago. A roll due by age starts in the same slot. A Regenesis is exempt from the 24 h rule
  (default, 2026-11-17).
- **Keyholders start it unasked** (default, 2026-11-17). The relay asks for a due roll in `EpochDue`,
  but a keyholder starts one at its first opening commit after the slot opens, whether the relay asks
  or not. It knows a roll is due from the headers: the removals since the last raise, and the `time`
  of the last raise, which is also the seed's age. The relay keeps that header (§4.4).
- The relay's validator refuses a commit that raises `seed` when no roll is due, or within 24 h of the
  last raise in a text group, except a Regenesis (§9).
- **Voice rooms are not batched** (default, 2026-11-17). In a voice group a removal rolls the seed in
  its own KeyholdersRemove, at once. A voice roll covers at most 250 seats at today's cap
  (`[media] voice_room`, §5.9): about 0.4 MB of seed welcomes. The 30-day age applies to text groups
  only.
- **Text rolls never overlap** (open choice 23, 2026-11-18). A roll starts in a text group only
  once the last one has finished (`seed_floor` = `seed`), a Regenesis aside; the validator refuses
  one that starts while a roll runs (rule 12). An overlapping roll would owe every seat still on the
  dropped seed a seed welcome inside the commit: up to N of them, about 166 MB at 100k, far past a
  commit's cap. A voice Remove may start a roll while one runs: the seats still on the seed it
  drops get their seed welcomes in that commit (at most 250), and with none behind it carries none.
- The commit that starts the roll draws `seed_{s+1}` and sets `seed = s + 1`, `seed_floor = s`. Its
  own rows still use `s`, since no seat has been given `s + 1` yet. Any older seed leaves the keyring
  there: a seat still on a seed the new floor drops (a roll that had not finished) gets its seed
  welcome under `s + 1` before any row is made to it.
- Keyholders then give every remaining seat a seed welcome (§3.2) under `s + 1` within 24 h: on the
  seat's next fetch, and by a background sweep. Seed welcomes change no bucket, so they travel outside
  commits (`EpochWelcomes`).
- A seat **holds** `s + 1` once the relay has stored a seed welcome for it. From then on rows to that
  seat use `s + 1`, and the row's context says which. A seat that is offline for weeks opens its
  welcome when it is back; it does not hold the roll open.
- When every seat holds `s + 1` or has gone, the next opening commit other than a KeyholdersReplace
  sets `seed_floor = s + 1`. The keyring then drops `seed_s`, and members drop `s_m` under `s`.
- Until then a removed keyholder still holds `seed_s`, where `s` is the head's seed at its removal.
  With that alone it opens no row another keyholder made, short of breaking X25519 (§3.3). A quantum
  attacker with `seed_s` does open them: the rows under `s` made after the removal, its own re-key
  rows among them, and through them the new bucket keys and epoch keys, until `seed_floor` passes `s`
  (§6).
- **What the age bounds.** Each keyholder holds the seed, and with it every `s_m`. Once any keyholder
  is compromised, or a replaced keyholder pair is stolen (§5.11), a quantum attacker with the relay's
  recordings opens every row under that seed: back to the seed's start, and forward until it rolls. In
  a text group the 30-day age bounds that to about 31 days: 30 days, plus a roll of up to 24 h. It
  costs one roll a month: about 166 MB of seed welcomes per 100k group (about 1.7 KB per member),
  delivered as members fetch and by the 24 h sweep (§8). §6 and §7 Q2 say so.

**Nobody holds the keys:**
- Joins wait. A held post past `HOLD_MS` drops, and the app says that nobody who holds this
  channel's keys is online.
- **On a relay without accounts, and in a voice room:** the relay asks a volunteer for a new Genesis
  at once, which is a new generation.
- **In a stored group** (a `c:` id on a relay with accounts): once no keyholder has been online for
  the Regenesis wait, the relay may ask a volunteer for a Regenesis. The wait is:
  - **2 min**, the fast new start (owner, 2026-11-19), when every entry of the keyholder set in
    force is a connection entry (origin 0x02: a browser's or a guest's pair) and no Regenesis
    started that set less than an hour before. Such an entry dies with its connection and can never
    come back online, so after the sole browser keyholder reloads, or after any relay restart, the
    hour would only stall the group's joins and exits;
  - **1 h** for any set with a desktop entry (origin 0x03), which comes back with its device, and
    for a set a Regenesis itself started less than an hour before (the churn bound: connections
    that drop again and again start anew at most once an hour that way).
  - Members enforce the wait themselves, from the signed headers alone (§5.7): `rules.rs`
    `regenesis_wait`, `REGENESIS_FAST_WAIT` and `REGENESIS_FAST_GAP` in `group_key.rs`. The relay
    counts it on its own clock too, from when no keyholder was online (`group.rs` `regenesis_at`),
    and its validator refuses a Regenesis that comes earlier.
  - The trade-off, stated in §6 and THREAT-MODEL.md: a hostile relay can drop every connection of
    such a set and have a new generation started every few minutes. It reads nothing and forges
    nothing by it; it costs a re-seat each time (§8). A channel with a desktop keyholder keeps the
    hour.
- Every member shows "keys for this channel were made anew by X", within §5.12's limits. The relay
  chose that seat, and it is named to everyone. That is the same power the relay has over who is
  seated at all.

### 5.7 Rollback floor and generations

A member keeps, per group, its **floor**: the newest header it took, as
`(gen, gen_time, epoch, join, D, D_e, kh, time)`.
- `gen_time` is the `time` of the generation's Genesis. It orders generations, whose ids are random.
- `D_e` is the floor epoch's `D_e`, and `kh` the `D` of the keyholder header the floor names (its own
  `D` if it sets keyholders, else its `kh_parent`). Rule 3 of §4.4 walks back to `kh` and compares
  `D_e`.
- `time` is the floor header's own signed `time`.
- In a gated group it also keeps its **names floor** (§4.4 rule 4), beside the floor and in the same
  places: the `(gen, epoch, join, names_hash, time)` of the header it last folded the names to. It is
  set to the first head the device takes in the group, without fetching any names before it, and
  moves only when the device folds: before a post, or when its app shows the list. A failed fold
  leaves it before the list that failed (§4.4 rule 4).
- It also keeps the last 8 generation ids it took for that group.

Where floors live:
- **Local floor:** the desktop and phone apps keep one per relay and group, whatever identity they
  connected with, so a guest on an app keeps one too. It is updated at every header. Beside it the app
  notes `taken`, its own clock when it last took a header of the group.
- **Vault floor (accounts):** `gk_floors`, kept beside the pins, outside the sign-in frame: its own
  namespace (`voipc.gkfloors`), in pages of at most `VAULT_MAX_BYTES` (48 KiB) like `pins.N`, read
  one at a time after sign-in. Keyed by group id.
  - A floor takes about 0.35 KB with its 8 generation ids (an estimate), so a page holds about 140
    groups. At most 16 pages, about 2200 groups. Past that, the group used least recently drops out,
    and on a fresh device it falls back to the rule for no floor.
  - A device takes no header of a stored group until the pages are in, as it decides on no pin
    before the pin pages are in.
  - It is saved on every generation change, and at most every 60 s otherwise.
  - It holds only stored groups (`c:` ids), never memory-only ones (§5.12), so an anonymous room
    never reaches the vault.
  - Two devices merge per group: the generation with the later `gen_time` wins; within one
    generation, the higher `(epoch, join)`; and the generation lists are joined, keeping the newest 8.
  - The floor in use is the higher of the local and the vault floor, by the same order.
- A browser keeps no local floor. Signed in, it has the vault floor, which the relay can roll back
  (THREAT-MODEL). As a guest it has a floor only for the page's life.

Rules:
- **Within a generation**, a header at or below the floor is refused.
- **A new generation** is a Genesis, or a head whose walk (§4.4 rule 3) ends at one. A device takes it
  only if its `gen` is none of the last 8 it took, its Genesis `time` is at most `CLOCK_SLACK` ahead
  of the device's clock (rule 7), and:
  - **With a floor in an older generation:** the Genesis `time` is later than the floor's `time`
    minus `CLOCK_SLACK`. So a device that was away (offline, out of the room, or behind a restore)
    takes a generation of any age that began after it last saw the group, and never one that began
    before.
  - **A change seen live:** if the device took a header of the group in the last 10 min by its own
    clock (`taken`, local floors only), the Genesis `time` must also be within 10 min of its clock,
    either way. A device that follows a group sees a new generation as it starts, so an older one
    shown to it is a replay.
  - **With no floor** (a fresh device, or one that never met this group): the device takes the head's
    generation on TOFU, through the walk of rule 3 back to its newest Genesis or Regenesis. No clock
    check applies beyond rule 7.
- **A Regenesis** is taken only if its `time ≥ parent.time` + the Regenesis wait (§5.6) and it passes
  rule 7, and:
  - the wait is read under the keyholder set in force before it, the header its `kh_parent` names:
    2 min when every entry there is a connection entry (origin 0x02) and no Regenesis started that
    set less than an hour before the new one's `time`, else 1 h (`rules.rs` `regenesis_wait`);
  - a member checks it under the keyholder header it holds beside its floor, and a member that holds
    only its floor (whose `kh` is only a digest) is handed that header: it must be the one `kh_parent`
    and the floor's `kh` name, else it is refused, so a relay cannot swap in another set
    (`check_link_under`, `check_on_floor_under`, `check_regenesis_under`). On a walk, every
    Regenesis is checked under the set before it, which the hash chain fixes;
  - with a floor in its generation, its `parent` is the floor or reachable from it (§4.4 rule 3), and
    the live rule above applies to it as to a Genesis;
  - with a floor in an older generation, the device takes the generation's Genesis first, under the
    rules for a new generation, and then the Regenesis on the walk;
  - with no floor, it takes the Regenesis on TOFU, as it would a Genesis. Such a device never saw
    the set before it, so it takes a Regenesis 2 min after its parent whatever that set was, as it
    takes any Genesis on trust.
  - The volunteer's app refuses to make one earlier: the builder holds to the 2 min, and the
    volunteer's own check of its commit under the set it holds holds to the hour for a set with a
    desktop entry. The relay keeps each Regenesis's parent, so this check can always be made
    (§4.4).
  - The relay's validator also refuses a Regenesis dated more than `CLOCK_SLACK` (10 min) before its
    own clock (rule 5, `BACKDATED`; test
    `a_regenesis_dated_further_back_than_the_clock_slack_is_refused`). A new set's churn hour counts
    from the Regenesis's own `time`, so a backdated one would let the next fast new start come
    minutes later (J9 review).
  - Signed header times may run up to `CLOCK_SLACK` ahead of a member's clock (rule 7), so a
    dishonest volunteer can skip the 2 min, and take 10 min off the hour, as before. An honest
    relay asks only once the wait is out on its own clock.
- Every header has to pass §4.4 rule 7. A keyholder whose clock is more than 5 min off the relay's
  clock (sent in the `GroupKeys` frame right after `Authenticated`) refuses to sign.
- So no clock ever raises a floor. A wrong clock on one phone makes that phone's headers refused, and
  nobody else's.
- A voice joiner who was in the room an hour earlier, in a generation since dropped, has a floor in an
  older generation and takes the current one, however long ago it began. A member back after a
  restore, a purge or the switch going back on does the same.

**Restore (incarnation):**
- The database holds a random incarnation id (`voipc_meta`, key `gk_incarnation`). A restore
  replaces it: the operator runs `voipc-server --config … db new-incarnation`, listed in OPERATING
  §7's restore steps.
- At start, every stored group from an older incarnation loses its keyring, `KRK` welcomes, seeds and
  pending joins. Its next fetch starts a new generation, and members take it under the rules for a
  new generation.
- What kept chains reference (headers, seals, rows, chain seals, self-rows) stays readable until
  `kept_window` or `retention_days` sweeps it.
- If the step is forgotten, a member whose floor is above the relay's head sends `EpochFloorAhead`
  with that signed header. The relay checks the signature against a keyholder `IK` it stored for
  that generation, and that `(epoch, join)` is above its head. Only then does it start a new
  generation for that group, at most once per group per hour. Without the proof, any member could
  force a full re-seat.
  - It ignores a floor header signed by a keyholder it removed in that generation. That is a removed
    keyholder's fork (§6), and honouring it would let that keyholder force a re-seat every hour.
  - If the backup predates the member's generation, the relay holds no keyholder `IK` for it and
    cannot check the proof. It then changes nothing and warns its admins (§5.13), and only the
    operator command brings the group back. The member's app says the server's keys for the channel
    are older than what it saw.
- On a relay with accounts, a new generation, whatever the relay says caused it, is shown to every
  member with its signer. A relay that claims restores often is seen doing so.

### 5.8 Posts and writers

A writer's first post in an epoch carries its writer blob (§3.8):
- `w = (m, u)`. The relay keeps every blob per `w` per epoch, at most two (a chain ends after 1 h,
  and an epoch lasts at most 70 min for writers, §5.5), and hands them to whoever sends
  `EpochBlobWanted`. It refuses a third. The writer opens no session and makes no round trip.
- Blobs live in the relay's memory only (open choice 5): a relay restart loses them, and each writer
  starts a new chain, with a new blob, after it reconnects.
- The SKDM's distribution id is `dist(group, gen, e, D_e)`: UUID v5, namespace OID, of
  `ctx(dist; k, group, gen, e, D_e)`. libsignal files the sender key under it, so a post decrypts
  only with the key installed for its epoch and that epoch's opening header, and the epoch check is
  structural.

The post itself is a libsignal sender-key message. `group_encrypt` takes no associated data
(`group.rs`), so the binding goes inside the plaintext, as `gen(16) ‖ epoch(4, BE) ‖ D_e(32) ‖ body`.

A reader takes a post only if all of these hold:
- the blob opened under `CK_e` for that `D_e`;
- the writer's signature verifies under `IK_w`, and `IK_w` matches the pin of the account `m`, or the
  connection's own key for a guest;
- the blob's `u` is the post's sender;
- the post decrypts under `dist(group, gen, e, D_e)`;
- the prefix is that `(gen, e, D_e)`.

Consequences:
- libsignal signs the sender-key message with the writer's signing key, which the blob bound to
  `IK_w`. So the binding is the writer's word too.
- A fork with two headers on one parent shows as posts their readers refuse, never as text the wrong
  half reads.
- Two devices of one account are two writers, each with its own blob.

**Size.** One channel message holds at most 16 KiB (owner, 2026-11-19). The relay refuses a larger
post on every channel path, key on or off, text channels and voice rooms alike, in its own words
("post too large: one message holds at most 16 KiB", `session.rs` `POST_TOO_LARGE`): under the key
as `EpochRefused{POST, TOO_LARGE}` when the post carries a blob, else as a `ChannelError`. Both apps
check it first: the writer bounds the sealed size of what it would send (`writer.rs` `post_fits`,
with the 52-byte prefix under the key) and refuses a post that does not fit before it goes, so the
row is marked "Not sent: one message holds at most 16 KiB." and nothing reaches anyone. Direct
messages keep their own limit. Tests: `a_post_past_the_cap_is_refused_before_it_goes_and_told_as_the_relay_tells_it`,
`a_key_post_past_16_kib_is_refused_as_a_post_with_or_without_a_blob`,
`a_voice_rooms_post_is_held_to_16_kib_like_a_text_channels`, test-ui "a message past 16 KiB is
stopped before it goes, and the composer says why".

**Taken.** The relay answers each post it takes with `EpochPostTaken{group, post}` to the writer's
own connection, where `post` is the first 16 bytes of SHA-256 over the post's ciphertext
(`group_key::wire::post_digest`). A post it refuses gets no such answer. The writer files the
post's kept copy the moment that answer comes (§5.10).

**Push or pull.**
- Text is pull: a member that cannot open a post sends `EpochFetch`. To save that round trip, the
  relay may attach the epoch to the first `EpochPostIn` it sends each seated member in an epoch,
  within a byte budget per second. It does not yet (open choice 6): nothing measured so far needs
  it.
- Voice is push (§5.9).

### 5.9 Voice rooms

A voice room is a group of its own, kind `v`. Seats are taken at room join, not lazily. Every seat
uses the connection's seat pair; a signed-in member's seat id is still its account, so the guest
check of gated rooms works.

**Anonymous rooms seat by connection** (open choice 11, 2026-11-18). In an anonymous room that is
not gated, every seat is `Conn(u)`, a signed-in member's too: the seats the relay sends
(`VoiceSeats`), a post's writer and the writer blobs carry no account id, and a writer's key is
taken on trust per connection, as a guest's is. The relay never puts an account behind a
pseudonym, and the check of a voice keyholder reads `u` from its entry, so the room needs no
mapping from accounts to user ids. A gated anonymous room keeps account seats, since its gate is
about accounts, and keyholder entries still name the keyholder's account, as every header's do
(§5.12). A keyholder takes either name of its own connection pair as its own seat
(`own_seats`; tests `e2e_an_anonymous_rooms_signed_in_members_sit_by_connection_and_hear`,
`a_signed_in_device_starts_an_anonymous_voice_room_seated_by_its_connection`).

**Keyholders.**
- They are the 2 lowest user ids in the room's roster: the rule today's minter uses, with no
  promotion step. Every app in the room may be one, phones and browsers included, whatever its
  Settings switch says (§5.6).
- Each is a connection keyholder: its keyholder keys are its connection's seat pair, and its entry
  carries its user id `u` (§11.3).
- A member refuses a voice KeyholdersAdd, or a Genesis, whose new keyholder's `u` is not among the 4
  lowest user ids in its own roster. The slack is for rosters that lag. The check reads `u` from the
  entry, so it needs no mapping from accounts to user ids, which an anonymous room must not give.
- A keyholder that leaves the room is removed at once (KeyholdersRemove), and that commit rolls the
  seed at once: voice rolls are not batched (§5.6). When none is left, the lowest user id makes a new
  Genesis.

**Joins and leaves.**
- A join is a join commit: one welcome for the joiner, nothing for the others. Today it is 3N
  pairwise messages.
- A joiner whose floor for the room is in an older generation, from an earlier visit in this relay
  run, takes the current one under §5.7's rule for a floor in an older generation, however long ago
  it began.
- A leave is an opening commit within 2 s: at most about 5 KB in a room of 62. Today the minter
  sends N keys.
- Refresh runs as in §5.5. Voice senders never stop on epoch age; the app only shows the keys as
  late. Voice must not break.
- **After an exit, voice keeps going too.** If no opening header covering an `EpochExit` arrives
  within 46 s, the app keeps sending voice, video and screen share, and shows that someone who left
  may still hear the room. So in voice the leaver's window rests on a timely commit: about 2 s plus a
  keyholder's turn under an honest relay, and no bound if the relay withholds the commit, as if it hid
  the exit (§6).

**Chat in a voice room.**
- A voice room's chat is written under the room's `CK_e`, with writer blobs and posts as in §5.8,
  `k = v`. It needs no seat beyond the room seat, and no pairwise sender key.
- Chat posts follow §5.4 and §5.5 as text posts do: a writer holds its posts when the keys are late.
  Voice itself does not.
- At 26 with the switch on, the relay refuses `DistributeSenderKey` and `SendEncryptedChannelMessage`
  in voice rooms, as it refuses `DistributeMediaKey` (§9). A voice join is then one welcome in all.
- **A voice room's kept log stays as it was** (open choice 26, 2026-11-18): per-reader wraps on the
  0010 path, which the relay still takes there with the switch on. The chain seal of §3.9 is for text
  only, and the voice group lives in memory. So a voice room keeps chat for its members as before,
  and the group key adds nothing to what it keeps.

**Delivery and storage.**
- Opening headers and seals are pushed to everyone in the room. Join headers go to the joiner, and
  to every member in gated rooms.
- **Names in gated rooms.** Every member takes the pushed Join headers and folds their names as they
  come (§4.4 rule 4), whether it writes or not. Voice never holds: a failed fold warns, and voice,
  video and screen share go on. Chat posts in the room hold on a failed fold, as a text writer's do.
- Headers and keyrings live in memory only. The keyring goes when the room empties, and the next
  joiner starts a new generation.

**Media keys.**
- Media keys are per sender seat and stream (§3.10), with `key_id = e mod 2¹⁶` and `minter = 0`.
  `MediaKey::supersedes` already compares ids with wrap-around.
- The receiver keeps `CK` of the current and the previous epoch, and derives a sender's key at that
  sender's first packet, from the seat the roster gives for it.
- `MediaKeyRing` is cleared on a generation change, since `e` starts again at 1.
- A sender moves to a new epoch's key 300 ms after it takes it (open choice 8), so a receiver a
  moment behind loses no packet.

Routed (proximity) rooms use the same group, with no cap of their own. The 3N join is why rooms are
capped at 250 today (`[media] voice_room`). That cap stays as the admin set it, but nothing in this
design needs it.

### 5.10 Kept history

Kept history keeps its chains and step rows per writer (`log.rs`). What changes:
- **Chains end at every opening epoch.** A writer's chain lives within one epoch, so a leaver opens
  none of its later steps.
- **Chain starts** are sealed once under `CK_e` (§3.9), in `voipc_gk_chains(group, owner, chain,
  gen, epoch, sealed)`, instead of once per bucket the writer holds. A reader opens it from its seat
  at epoch `e`, guests included: at the epoch's opening header when the opening seated it, and for a
  seat a later Join of that epoch added, at the epoch's last Join, which comes with the opening
  (`past.rs` `take_past_at`; tests
  `e2e_j8k_seats_a_join_added_and_seats_at_the_opening_read_their_epochs_kept_posts`,
  `e2e_t1_kept_posts_of_the_epoch_a_member_was_joined_in_open_on_its_new_device`). A Join taken that
  way must come with an opening of its own epoch and generation: its `epoch_parent` is the
  opening's `D`, its `kh_parent` the opening's keyholder header, and `gated`, `seed` and
  `seed_floor` are the opening's. Its signer is checked against the set the device's anchor
  reaches, or, on the binding alone, against the opening's own keyholder set; the leaf must be in
  the Join's bucket root, and `confirm` must hold for both headers
  (`e2e_j8k_a_relay_that_hands_a_forged_or_out_of_epoch_join_gets_no_post_read`).
- **Which epoch a copy goes under.** A writer files a post's kept copy under the epoch the post went
  out under, once the relay took it: the moment `EpochPostTaken` names the post (§5.8). A post the
  relay refuses for good is never kept, and one sent again after an `OLD_EPOCH` or `RATE` refusal
  is kept once, under the epoch it went again under. The relay starts a kept chain only under the
  head, or the one before for `HOLD_MS` after the head opened; a copy that comes too late for that
  ("That epoch's key is gone here") is filed again under the head the app holds then, so whoever is
  seated in that later epoch can read it in kept history, someone who joined after the post
  included (`group_state/copies.rs`; tests
  `a_taken_post_is_filed_at_once_under_the_epoch_it_went_under`,
  `a_post_refused_for_good_is_never_kept`, `a_post_never_taken_is_never_filed_and_is_given_up`).
  A page that closes within about one round trip after posting can still lose the kept copy; its
  live readers got the post.
- **Back-links.** For a chain with a sharer's back-link (`log.rs` `link`), the seal holds the state
  at index 1. Index 0, which opens the older chain, still goes only to who is proven to hold that
  older start, by today's proof path.
- **Chain ids** (open choice 12). A small group whose epochs open every 2 s would use up the 2²⁰
  chain ids of `log.rs` (`MAX_CHAIN`) in about 24 days of continuous posting. So a chain under the
  group key packs `chain << 1 | index` above the writer's last 0010 chain (`sync/chains.rs`), which
  leaves about 2³¹ chains: over 100 years at 1800 an hour.

**Reading old epochs.**
- A device needs `CK_e`: from its seal, from its row then, and from `s_m` (its self-row) or, after a
  rotation, its history row (§3.11).
- No inclusion path is needed: the seal's and the row's contexts bind `D_e` and `(b, v)`.
- **Anchored or on the binding alone** (open choice 22). A past header is taken when the keyholder
  headers sent with it lead back by `kh_parent` digests, at most 4096 links, from the keyholder header
  the device holds beside its floor to the signer's set. With no such anchor (a fresh device, a
  browser, an older generation), it is taken on the binding alone: the seal opens under a `BK` that is
  the device's own, and `confirm` passes. Only the device's own `BK` counts there: one from a row
  under its self-row's `s_m`, from its history row's `RB`, or from a welcome whose `s_m` is the
  self-row's. A welcome or a seed welcome alone counts only when anchored, since the relay may have
  chosen who made it (tests `a_fresh_device_takes_no_past_epoch_on_a_welcome_from_a_keyholder_the_relay_made`,
  `e2e_j8k_a_relay_that_seats_a_new_device_from_a_keyholder_pair_of_its_own_gets_no_key_taken`). A
  hostile relay can force the binding alone, by not answering the live fetch. A past header never
  moves the floor.
- A kept ask names the device's floor (`have`) only when the device holds the keyholder header that
  floor names. A floor read from the vault alone, as a reloaded page has before its live answer, is
  no anchor (`kept.rs` `send`; tests `a_kept_ask_names_the_floor_only_with_its_keyholder_header_held`,
  `e2e_j9m_a_reloaded_browser_page_reads_its_kept_posts_before_its_live_answer`).

**At the switch to 26:**
- Each writer closes its per-writer chain at its first post after the switch.
- The 0010 rows (`voipc_seats`, `voipc_seals`, `voipc_bucket_lists`, `voipc_chain_wraps`) stay. The
  existing opener reads them (their labels are frozen, COMPATIBILITY §4, and the 1.11.0 fixture
  covers them) until `kept_window` or `retention_days` sweeps them.
- History from before the switch reaches newcomers only through sharers' links, as today.
- **Sharing with newcomers stays** (open choice 25, 2026-11-18), bounded to writers who share: for
  them the relay still files `voipc_pending` and `LogPending`, and the index-0 wrap of the writer's
  current chain when it has a back-link, one wrap per newcomer. Through that link the newcomer reads
  the writer's older chains, 0010 ones included, as README and ACCOUNTS.md promise.
- No longer written at 26 with the switch on: those 0010 tables for text channels, `voipc_pending`
  for writers who do not share, `ChainRekey`, and the `MOST_READERS` cap. The relay drops nothing it
  holds. A voice room's kept log keeps the 0010 path (§5.9).
- `kept_seats` keeps its meaning and its default of 5000: an account that keeps a channel's history
  is seated eagerly, online or not, up to that many a channel. OPERATING §10a says it is now cheap
  to raise.
- **The switch gap.** An account is seated eagerly at its first `SeatKeysPublish`: the first time one
  of its devices signs in with a 1.14 app. Kept posts written under the group key before then are
  not readable to it. COMPATIBILITY §3 and the CHANGELOG say so.
- Group state is charged to the relay, not to any account's `quota_mb`, and shown in `AdminLoad`.

**How long the relay keeps an epoch's header, seals and rows:**
- **as long as** a kept chain starting in that epoch is kept, with the epoch's last Join (§4.4);
- **or** until `HOLD_MS` after the next opening commit, when no kept chain references it.

Kept chains are bounded by `kept_window` entries per channel, so at most `kept_window` epochs stay per
channel. Per kept epoch at 100k members that is `B` seals, about 97 KB, plus the rows of the versions
current then. For a ratcheted version, those are the rows of the version it came from. A self-row
(60 B) stays per account, seed and seat-key generation for as long as rows of that seed are kept.

Estimates at 100k members:
- refresh alone keeps about 1.2 MB of seals an hour (12 × 97 KB), if every epoch has a kept post;
- exit batches every 36 s with posts in each keep up to about 9.7 MB an hour;
- seals are bounded by `kept_window` × 97 KB, about 1 GB per channel at the default 10,000;
- rows add about 6 MB for every hour the kept epochs span, since every version is re-keyed by rows
  within the hour (100k rows of 60 B), plus about 3.7 KB per exit. With an exit batch every 36 s,
  10,000 kept epochs span about 100 h: about 0.6 GB of rows, 1.6 GB in all. With refresh alone they
  span up to about 35 days: about 5 GB of rows, unless `retention_days` ends them sooner. Not
  measured yet; OPERATING §10a says `kept_window` is what bounds it.

Today the same channel keeps one seal set per writer per chain, so the group key keeps less as soon
as more than one person writes.

**Gated channels past 32,000 members.** In a gated group, an `added` seat is checked against the
pins of writers at their fold, and of keyholders, only where they hold one, and a device pins at most
32,000.
- Past that, a newcomer in a gated channel is named in the header but checked by nobody who has not
  met them.
- In a channel that size the names are no check anyway: at 17 joins a second, nobody reads them.
- The other check, that no seat is a guest, holds at any size. Every member checks the signed
  `conn_seats`. Writers at their fold, and keyholders, check every `added` entry. Keyholders and the
  relay's validator check the pools themselves, and a keyholder signs no gated header while its
  keyring holds a connections-pool bucket (§5.4).

### 5.11 Seat keys: rotation and devices

**When.** An account rotates `item.seat_kem` (new `SK`, `SX` and self key) on:
- a password change;
- use of the recovery key;
- removal of a device;
- every 30 days. An app signing in with keys older than that rotates before anything else.

**How:**
1. Make the new item with counter `n + 1`, save the vault, publish the new keys.
2. In every group that keeps history where the old seat is seated:
   - open any welcome still waiting for the old keys;
   - write a history row (§3.11) holding the row bases of every keyholder that made rows to the old
     seat, per seed;
   - seal every live self-row and history row again under the new self key.
3. The relay names an exit for the old seat in each of its groups, and queues the new seat for the
   next join batch there. This re-seat is eager, one welcome per group (§8), so the old keys are not
   needed for long.
4. Delete the old private parts after the re-seat (owner decision 4): once the relay reports the new
   seat seated, or the old seat gone with no welcome waiting for it, in every group where the old
   seat was seated.
   - **At most 7 days after the rotation** (owner, 2026-11-17). A group with no keyholder online for
     that long would otherwise keep the old keys alive until the 90-day expiry. The account is then
     re-seated there lazily, as any newcomer.
   - The relay's report is its word. A relay that reports too early only costs the account a welcome
     still waiting for the old keys; one that never reports meets the cap.

Rotating `SK` alone would be enough for the rows, since `tag(SK)` feeds `s_m`. `SX` and the self key
rotate with it so that a stolen old vault opens nothing new.

**A keyholder's rotation.** A desktop keyholder replaces its keyholder pair at every seat-key rotation
of its account: a new pair, endorsed with the new counter.
- In each group where it holds keys, it asks the relay (`KeyholdReplace`, §9) and commits, itself, a
  KeyholdersReplace that swaps its own entry, named by its old `tag(KX)`, for the new one (§4.3). That
  is a Fresh commit plus the swapped entry and a new `KRK`: a new `CK` sealed to every current version,
  the rows a Fresh would make (leavers, the refresh slice, merges, the 1 h re-key of §5.5), a new
  `KRK` welcomed to every keyholder from the old pair, and no seed change.
- Every other welcome and every row, in that commit and after it, comes from the new pair. Members
  key the row bases they keep by `tag(KX)` (§3.3).
- A device that sees its own entry swapped by a KeyholdersReplace it did not make warns its user and
  asks the relay to remove that entry (`KeyholdResign`, §9). The relay proposes the removal at once
  (§5.6). The header is pushed to it, as every header that sets keyholders is (§4.4).
- A copy of the old pair stolen before its private parts go opens the keyrings up to the swap, the
  current seed and bucket keys among them. It opens no later keyring, and no row the new pair makes,
  short of breaking X25519. Classically, it reads what those bucket keys seal for up to about 1 h
  after the swap under an honest relay, until rows re-key every version it held (§5.5). With a
  quantum computer and the recordings, it opens the rows under that seed until the next roll: at most
  about 31 days, by the 30-day seed age (§5.6, §6, §7 Q2).
- It keeps the old pair's private parts until that commit is taken in every such group, and at most
  7 days. In a group still not done by then, it resigns.
- So a group whose only keyholder rotates does not stall: no other keyholder has to sign.
- A device removed from its account replaces nothing. The relay proposes the removal of its entries,
  and another keyholder commits it (§5.6).
- Connection keyholders do not rotate: their keys end with their connection.

**What it heals.**
- Rotation heals a theft that happened once, such as a lost device or a leaked backup. Live text
  recorded before the rotation stays closed to that thief.
- **Old keys stay old.** Every endorsement carries the account's counter `n` and the time it was
  made (§11.8), and so does every `added` entry. Keyholders, and writers at their fold, keep the
  highest counter seen per account, with its endorsement's `made`, beside the pins. They refuse a lower
  one in a header made after that `made` plus `CLOCK_SLACK` (§4.4 rule 8). So a relay holding an old
  seat pair, from a lost device or a leaked backup, cannot seat it again under the account's name once
  a keyholder has seen the newer counter. A keyholder that has not seen it can be fooled once.
  Connection pairs of a signed-in connection carry the account's counter too.
- **What readers no longer check** (owner, 2026-11-17: only writers take the names). In a gated group
  the account's own app sees itself named with an old counter, and warns, only if it writes there: the
  warning comes at a fold. Readers' pins no longer check new entries. And a reader promoted to
  keyholder has seen few counters, so it is the keyholder most easily fooled once.
- It does not stop a relay that keeps the old seat seated, which is a hidden exit (§5.4).
- It does not stop a relay that has cracked the password: that relay opens the next vault copy too.
  Only a password change helps there.
- Groups that keep history stay as weak as kept copies are today (ACCOUNTS.md): the history rows let
  the vault open their old epochs.

**Seats unused for 90 days** are exits (§5.4).

**Offline accounts.** Going offline is no exit (§5.4), and a rotation runs only on a device: an app
signing in with keys older than 30 days rotates first. So the seat of an account that stays offline
lives until it exits or expires after 90 days, and every re-key reaches it by rows. §6 claim 6 says
what that changes.

**Devices.** All of an account's devices share its seat in a text group, and each is its own writer
`(m, u)`. Keyholder roles are per device (§2). The seat ends on a kick, ban or eject of the account,
or when its last connection leaves the channel. A connection's seat pair has the same
forward-secrecy limit for the connection's life.

### 5.12 Private rooms and memory-only groups

**Group ids.**
- A text channel whose offered log is not empty uses it: `c:…`, as `ChannelEntry::log_conv` makes it.
  The offered log is `info.log`, which `refresh_log` (`state.rs`) leaves empty in anonymous and
  `hide_members` channels, although every persistent channel has a `log_conv`.
- Every other group uses `r:<run>:<channel id>`. `<run>` is 16 random bytes the relay draws at each
  start. That covers temporary channels, channels on a relay without storage, anonymous and
  `hide_members` channels, and every voice room.
- **A change of `anonymous` or `hide_members`** at runtime (which calls `refresh_log`) moves the
  channel to its other id. The group under the new id starts with no keyring, so its next fetch makes
  a Genesis, and members take it under §5.7's rules.
  - Leaving a `c:` id: the stored group takes no more commits. What kept chains reference stays
    readable until `kept_window` or `retention_days` sweeps it, as the kept log of a channel that
    turns anonymous does.
  - Leaving an `r:` id: the memory-only group is dropped.
  - Coming back to a `c:` id that still has a stored group: the relay starts a new generation there,
    since exits in the meantime reached no keyholder of it (as in §5.14).

**Memory only.** Groups with `r:` ids live in memory only: no header, keyring, seat or welcome reaches
the database. That keeps account ids from anonymous rooms out of the database, as the kept log does
(`refresh_log`).

**Anonymous and `hide_members` rooms.**
- Their headers keep the full lists: the pin and guest checks need them.
- What the app shows is a rule. In an anonymous room it shows no keyholder name, no "made anew by"
  name and no new-reader (`added`) name; it still runs every check on them. In a `hide_members` room
  it shows keyholders and new readers only to admins, as the roster is shown.
- Their headers and keyrings, like those of every voice room, live in memory only (`r:` ids).
- A modified app can still map an `IK` to an account, which THREAT-MODEL.md already admits.

### 5.13 What admins see

`AdminLoad` gains a row (`GroupLoad`) for each group of at least 1000 seats and each group with
something amiss or a warning, those first, at most 50 rows (`load.rs` `groups_shown`):
- seats, and keyholders online and in all;
- the age of the last commit;
- joins and exits waiting;
- missed deadlines;
- about how many bytes of group state it holds in memory and in the database.

"Amiss" is seats with no keyholder online, a head older than writers wait for (70 min), or a
missed deadline. `LoadReport.warnings` carries, each naming its channel as `#<channel id>:`, "no
keyholder online for N min", "keys late", "missed N deadlines" and "a member reports it ahead of
this database" (§5.7), at most 50 of them, the largest groups' first, and then "N more group key
warnings: the server's log has each". Each is logged at warn when raised, at most once per 10 min per
kind and group.

The timers are fixed, because clients enforce several of them (§5.4, §5.5, §5.7). There is no
"re-key now" button for now. Admins choose no keyholders, which keeps moderators away from keys.

### 5.14 The relay switch

`group_key` (§9) is read at start, for the whole relay.
- **Off to on** (the update to 1.14, or an admin turning it on): every group starts with no keyring,
  so its first fetch makes a Genesis. Writers close their per-writer kept chains at their first post
  (§5.10). An account is seated eagerly only from its first `SeatKeysPublish` (the switch gap,
  §5.10).
- **On to off:** the relay goes back to the old paths (the live path and the 3N join) at its next
  start. It keeps the group tables and serves what kept chains reference, read-only, so history kept
  under the group key stays readable: an account reads it with the seat keys in its vault, and
  publishes nothing (test
  `e2e_t1_an_account_on_a_relay_with_the_key_off_reads_kept_history_with_its_vaults_seat_keys`). Apps
  see the change in the `GroupKeys` frame after `Authenticated` and use the live path and the 3N
  join.
- **Back on:** a start with the switch on after a run with it off begins a new generation for every
  group, as a new incarnation does (§5.7), since exits during the off run reached no keyholder.
  Members take it under §5.7's rule for a floor in an older generation, however long the off run
  lasted. That costs a full re-seat of every group (§8), so the switch is a way back from a fault,
  not a setting to flip often.

## 6. What changes for each party

These rows are in THREAT-MODEL.md since 1.14, each with the tests that hold it.

| Who | Can | Cannot | Compared with today |
|---|---|---|---|
| **The relay, honest or curious** | See who is seated and in which bucket, when epochs change, each commit's size, who holds keys and when they are online, when each member fetches, and when an account rotates its seat keys | Read `CK`, a bucket key, a seed, a keyring, a writer blob, a post or media | Same, plus keyholders |
| **The relay, hostile** | <ul><li>Seat a ghost, by asking a keyholder to. In a gated group the header names it to every writer seated before it: before that writer's next post under an honest relay, and whatever the relay does, before its first post in a later epoch (≤ 70 min) (§4.4 rule 4). Keyholders, and writers at their fold, refuse guests and old seat keys; a writer whose fold fails holds its posts until the seat is removed.</li><li>Give a seat it chose (an account that passes the keyholder's checks) the current `CK_e` with no taken header naming it, by leaving the Join commit that seated it out of the heads it shows. The seat reads that whole epoch (≤ 70 min) from its start. The relay can repeat it in every epoch, with any keyholder, and each time one keyholder device sees it and warns.</li><li>Withhold commits: newcomers wait, and writers stop 46 s after a named exit, and 70 min into an epoch. In a voice room a leaver keeps hearing, and the app warns after 46 s.</li><li>Delay the names of new readers to a writer by up to one epoch (≤ 70 min), by withholding the pushed lists and the Join headers. Past 90 days away, the writer's app says that people joined more than 90 days ago whose names it was not shown. A member that only reads is not shown them unless it asks.</li><li>Hide an exit, with no bound, as today.</li><li>Keep an offline account's seat fed with every epoch until it exits, rotates or expires (90 days).</li><li>Choose which volunteer becomes a keyholder in a text group, within §5.6's rules.</li><li>Start a new generation: at will on a relay without accounts; on a relay with accounts by claiming a restore, or by a Regenesis once no keyholder has been online for the wait (§5.6). In a channel whose keyholders are all connection entries (browsers and guests), that wait is 2 min, so by dropping their connections it can force a new start every few minutes (the fast new start, owner 2026-11-19); a channel with a desktop keyholder keeps the hour. Members are told each time.</li><li>With a removed keyholder, fork members who have not yet seen the removal (below).</li><li>Split members onto two branches, which shows as posts they cannot open.</li><li>Roll a browser back within its vault floor's lag, or further by rolling back the vault item.</li><li>Make newcomers read up to 70 min back, by withholding refreshes.</li></ul> | <ul><li>Forge a header, a welcome, a row, a keyring or a writer blob.</li><li>Choose `CK` (confirm is in every header), a `BK` or an `s_m` (welcomes are authenticated), or a keyring (its hash is in the header).</li><li>Roll a desktop or phone app below its local floor, or back into one of the last 8 generations it took, or into a generation that began before its floor.</li><li>Seat an account's old seat keys again once a keyholder has seen its newer counter, or past a writer that has seen it: that writer's fold fails, and it holds its posts.</li><li>Skip a name in a writer's fold, move a list to another header, or pass off a shorter tail as the last 90 days: each step of `names_hash` binds its header's `time`, `epoch` and `join`.</li><li>Make two voice senders share a media key.</li><li>Make a writer open sessions with members.</li></ul> | Ghosts and hidden exits as today. New: withholding commits, keyholders, the stale-join residue, new generations shown to members, offline accounts staying seated. Gone: the 180 MB first post and the forced session-start uploads. |
| **A keyholder, hostile** | Seat ghosts. With the relay's help they need not be named: seats in merge or re-version buckets, which members cannot see, and which an honest relay's validator refuses. It can also hand `CK` to anyone, which no design stops. Skip a leaver, only with the relay hiding the exit; stall commits until it is replaced; read everything the group carries while it holds keys; give away the seed | Open rows other keyholders made without breaking X25519; read bucket keys or keyrings from before its promotion | New role |
| **A removed keyholder that also left the group** | Keep `seed_s`, the head's seed at its removal, until every seat is given `s + 1`: in a text group up to about 48 h, since the roll starts within 24 h of the removal and finishes within 24 h; in a voice room the roll starts at the removal itself (§5.6). With the relay, fork members who have not yet seen its removal: sign headers on the keyholder set from before it, which they take, and read what they write until they see the removal and need a new generation (§5.7). With a quantum computer and the recordings, open the rows under `s` made after its removal, its own removal's re-key rows among them, and through them the new bucket keys and epoch keys, until `seed_floor` passes `s` | Classically, open anything sealed from the KeyholdersRemove epoch on outside such a fork, or rows other keyholders made | New |
| **A removed keyholder still seated** (a resignation, a stall or away removal) | Read everything the group carries, as any member. The seed and fork items of the row above | Open the bucket keys or the keyring made after its removal, or rows to other seats, except as above | New |
| **A thief of a replaced keyholder pair** (a copy stolen before its private parts went, §5.11) | Open the keyrings up to the swap, the current seed and bucket keys among them. Classically, read what those bucket keys seal for up to about 1 h after the swap under an honest relay, until rows re-key every version it held (§5.5). With a quantum computer and the recordings, open the rows under that seed until the next roll: at most about 31 days, by the 30-day seed age (§5.6) | Open a keyring after the swap, or a row the new pair makes, short of breaking X25519. Swap the entry again: the pair is no longer in the set | New |
| **A quantum attacker with the database and recordings** | Recover every X25519 secret. With a seed some keyholder gave away or lost, open every row under it: back to the seed's start, forward until it rolls, and the rows made under it after a removal until `seed_floor` passes it. In a text group a seed is in use for at most about 31 days (§5.6) | Open a welcome, a row, the keyring or a self-row without Kyber1024, `s_m` or the self key | Better: kept copies are X25519-only today (ACCOUNTS.md) |
| **A thief of an account's vault or device** | Read what was recorded for its seats since the last seat-key rotation, and new epochs until the next rotation (≤ 30 days) or password change, if the relay names the rotation's exit. In groups that keep history, read that history, as today. A thief of a keyholder desktop also gets that device's keyring, until the account removes the device and another keyholder commits the removal; a vault alone opens no keyring. Sign headers as any keyholder entry of the account, since a header's signer is checked by its `IK` (§4.4 rule 2). Without the entry's keyholder pair it makes no welcome, row or keyring the other keyholders take, so alone it can at most stall the group. With the relay it can sign a KeyholdersReplace that swaps one of the account's entries for a pair of its own: the other keyholders refuse its keyring, since its keyring welcomes do not come from the old pair, and the device whose entry it swapped warns and asks for that entry's removal. Members cannot check keyring welcomes, so on that branch it can re-seat them by welcomes from its own pair and act as a hostile keyholder (row above) until its entry is removed (§7 Q11) | Read live text recorded before the last rotation. Seat the old keys again where the newer counter has been seen | Worse for live text in groups without kept history: today a stolen device reads back only to its last renewal (hourly) |
| **An account that only went offline** | Stay seated until it exits, rotates at its next sign-in, or expires (90 days). With a relay that keeps and feeds it the epochs, read them all when back | Read anything after its seat ends | Worse: today an offline device's chain covers at most an hour |
| **A newcomer** | Read the current epoch from its start: ≤ 60 s in a one-bucket group and ≤ 5 min otherwise under an honest relay; ≤ 70 min under a hostile one | Read earlier epochs, except through kept-history sharing | About 60 s back today |
| **A leaver** | Text: read for up to `exit_gap(N) + CHECK_WAIT_MS` after the exit is named under an honest relay, and at most 46 s once writers are told; with no bound if the relay hides the exit. Voice: hear until the opening commit that removes them, about 2 s under an honest relay; with no bound if the relay withholds that commit or hides the exit, and the app warns after 46 s | Open any epoch after the opening header that removed them | Same for text. Voice: today the minter re-keys as soon as it sees the leave |

**Claims that change.** README.md and THREAT-MODEL.md change with these. The weakened ones (W) go
into one GitHub security advisory and a CHANGELOG "Security" entry with 1.14 (COMPATIBILITY §5).

1. **(W) Session keys after each round** (README, *Perfect Forward Secrecy*): in text groups, keys no
   longer reach readers through per-round sessions. Seat keys rotate every 30 days and on events, so
   a stolen device reads recorded live text back to the last rotation, not the last hour.
2. **(W) Chains end by age** (README, *Perfect Forward Secrecy*: "every chain ends by age"; README
   line 398, *Text channels*: "Someone who only goes offline is covered within a minute on a small
   channel and within an hour with 2000 online"). Today a writer ends its own chain by age, 2 s per
   reader it named and at least 60 s (`CHAIN_AGE_PER_NAMED_MS`, `channel_state.rs`), and no relay can
   stretch that. Under the group key a held `CK` lasts until the next opening header: at most 5 min
   (60 s in a one-bucket group) under an honest relay, and up to 70 min under a hostile one, in a
   group of any size. Chains also end at every opening epoch and after 1 h. Small channels lose most.
3. **Kept copies use X25519 only** (README): copies kept under the group key gain Kyber1024. The 0010
   rows written before the switch do not.
4. **Media keys** (README, voice): "handed to each joiner over the pairwise Signal session" becomes
   "derived from the room's epoch key, which reaches each joiner in a hybrid welcome". "Nobody
   elected by the server" stays true: the keyholders are the lowest user ids. Keys are now per
   sender seat, which closes the stream-id collision whatever session ids the relay hands out.
5. **(W) Writers name new readers** (THREAT-MODEL, hostile relay; README, *What the server can still
   do*). A writer's app no longer names each reader as it hands its key over: the key reaches readers
   through the epoch. Instead, in gated groups, the signed headers name every new reader to the app of
   every writer seated before it: under an honest relay before that writer's next post, since the
   relay pushes each Join's list to the writers of the epoch; under a hostile relay at the latest
   before its first post in a later epoch (≤ 70 min). No name can be skipped, and each list is bound to
   its header's time and position (§4.4 rule 4, §11.3). A writer whose fold fails holds its posts
   until the seat is removed.
   - A member that only reads is not shown them unless its app asks (owner, 2026-11-17). So an
     impersonated account's own app sees itself named only if it writes there, readers' pins no
     longer check new entries, and a reader promoted to keyholder has seen few counters (§5.11).
   - The gaps: a writer away more than 90 days (its app says that people joined more than 90 days ago
     whose names it was not shown), a fresh device (which starts from what it finds), and the
     stale-join residue above.
   - Past 32,000 pins, newcomers are checked only by those who pinned them. In `hide_members` rooms
     names show only to admins; in anonymous rooms the app shows none.
6. **(W) What the age of a chain covers** (THREAT-MODEL, hostile relay: "what the age of a chain
   covers, an hour at most, is someone gone offline", and the member row: "at most an hour, and reads
   it only if a relay feeds them"; README line 398). An account that only goes offline stays seated,
   and every re-key reaches it by rows. With a relay that keeps and feeds it the epochs, it reads
   them all until it exits, rotates at its next sign-in, or its seat expires after 90 days. Only
   guests (connection seats) are covered at disconnect. A chain key stolen alone is covered by the
   70-minute epoch-age limit, and a bucket key by the hourly re-key under an honest keyholder. A
   hidden exit stays unbounded. A shorter expiry for offline accounts in groups without kept history
   would narrow this; owner decision 4 sets 90 days.
7. **(W) A new party, the keyholder.** Its role, its rules and the seed's post-quantum reach (at most
   about 31 days of rows in a text group, by the 30-day seed age) are above. Its online times show to
   members.
8. **Forced session-start uploads** (THREAT-MODEL): gone in text groups.
9. **(W) Newcomers** (README, *People who join a channel later*): they read up to 60 s or 5 min back,
   and up to 70 min under a hostile relay.
10. **Rollback** applies only to devices that keep a local floor: the desktop and phone apps.
11. **Rotated when somebody leaves** (README, voice): the room's keyholders, the lowest user ids,
    commit a new epoch within about 2 s. A relay that withholds the commit keeps a leaver hearing, as
    one that hides the leave can today; the app warns after 46 s.

## 7. Open questions

The adversarial review of the built version (§10) answers each of these against the code, and states
what it could not settle. It runs after this text was brought up to date with the code; until its
answers are written here, every question below is open.

1. **Welcome** (§3.2): is the concatenation KDF enough, with `ct_q`, `eph.pub` and every public key in
   the salt and `ss_k` in the input? We want IND-CCA security if either Kyber1024 or X25519 holds, and
   authentication to `K` while X25519 holds. A quantum attacker can forge welcomes. The member then
   opens a seal under the forged `BK` only to a `CK` that fails `confirm` in the signed header, and it
   writes no self-row, so we count this as denial of service. Is that right, or should a welcome also
   carry a signature?
2. **Rows and the shared seed** (§3.3, §5.6): `RB` mixes a static X25519 secret with `s_m`, and every
   keyholder holds the seed that makes `s_m`. Does §6's claim for a removed keyholder hold?
   - In text groups seed rolls start at most once per group per 24 h and finish within 24 h (§5.6), so
     a removed keyholder's seed stays useful to a quantum attacker for up to about 48 h: is that
     acceptable? Voice rooms roll at the removal itself.
   - A text seed has a maximum age of 30 days (default, 2026-11-17), so a seed any keyholder leaks
     reaches at most about 31 days of rows, at the cost of one roll a month (about 166 MB at 100k). Is
     that the right trade?
   - The rows of a removal's own re-key still use the old seed, so a quantum attacker holding it opens
     them (§6).
   - A desktop keyholder that replaces its own pair at a seat-key rotation commits a
     KeyholdersReplace: a Fresh commit with a new `CK` and `KRK`, the rows a Fresh would make, and no
     seed change (§4.3, §5.11). A copy of the old pair stolen before its deletion therefore opens the
     keyrings up to the swap, the current seed and bucket keys among them. Classically it reads for up
     to about 1 h after the swap, until rows re-key every bucket key it held; post-quantum, until the
     next roll, at most about 31 days. Is that acceptable?
3. **Binding** (§3.4–§3.8, §3.12, §4): `D` leaves out the signature, `D_e` names the opening header,
   `confirm` is in every header, the bucket root carries the seat-list digests, and the keyring is a
   hash chain. `D_e` sits in seals, blobs, the writer's signature, the distribution id
   (`dist(group, gen, e, D_e)`) and the post prefix. Does that stop the relay mixing two commits,
   moving a blob, or getting a keyring taken that no header commits to?
4. **Stale joins** (§5.2): we did not take a `CK` derived per join. A ghost on a stale branch would
   still get the writers' sender keys unless every writer restarts its chain after every join, which
   breaks lazy seating. Is the remaining exposure acceptable: one account the relay chose, unnamed, for
   one whole epoch, repeatable every epoch, each time seen by one keyholder device that checks the
   ancestry of its own Join commits? Is there a cheap construction that closes it?
5. **Promotion** (§3.5): does a KeyholdersAdd (an opening epoch) with every `BK` ratcheted by HKDF
   give a new keyholder nothing from before its promotion, apart from the seed?
6. **Rollback and generations** (§5.7): the floor is `(gen, gen_time, epoch, join, D, D_e, kh, time)`.
   A walk is bounded in epochs by elapsed time (one per 2 s). A new generation is taken only if it
   began after the floor's `time` (and within ±10 min of the device's clock when the
   device followed the group in the last 10 min), the last 8 generation ids are refused, a device
   with no floor takes the head on TOFU, and members enforce the Regenesis wait: 2 min under a set
   of connection entries alone that no Regenesis started in the last hour, else 1 h (§5.6, §5.7). Is
   that safe for what it buys? Is "the relay can claim a restore, and members are told" an
   acceptable bound?
7. **Windows**: a text leaver reads up to `exit_gap(N) + CHECK_WAIT_MS` under an honest relay, and at
   most 46 s once writers are told. A voice leaver hears until the next commit, which voice never
   waits for. A hidden exit is unbounded, as today. Newcomers read 60 s or 5 min back, 70 min under a
   hostile relay. Writers stop at an epoch age of 70 min. Are these acceptable as stated?
8. **Seat keys** (§2, §5.11): round-3 Kyber1024 now, with ML-KEM-1024 later by rotation. Rotation
   every 30 days and on events, with history rows keeping kept history readable once the old private
   parts are gone, and a monotonic counter in every endorsement so old keys cannot be seated again.
   Does this keep "rotation heals a theft that happened once" for live text? Is a counter checked
   only by those who have seen the newer one enough? Since only writers fold the names, an
   impersonated account's own app sees itself named only if it writes there, readers' pins no longer
   check new entries, and a reader promoted to keyholder has seen few counters (§5.11). A lower counter
   is flagged only in a header made after the newer endorsement (§4.4 rule 8): does that time rule
   leave a gap?
9. **Voice** (§3.10): is a media key per sender seat and stream from `HKDF(CK_e, …)`, under today's
   GCM nonce layout (`stream ‖ sequence ‖ type ‖ fragment`), sound?
10. **Names** (§4.4 rule 4): is a signed running hash over the `added` lists, each step bound to its
    header's `time`, `epoch` and `join`, which a writer folds from its names floor to the head before
    each post, enough to make every gated newcomer reach every writer seated before it: before its
    next post under an honest relay, which pushes the lists, and within one epoch (≤ 70 min) against a
    relay that withholds headers or forks? Does the step before the 90-day tail prove that the tail
    covers 90 days? Is holding a writer's posts on a failed fold, until an opening header removes the
    seat, the right answer, and are those `removed` lists, taken from signed headers, enough? Readers
    of text groups do not fold.
11. **Keyholder keys** (§2): a keyholder opens the keyring through a pair of its own, never the
    account's seat keys, so the account's other devices hold no keyring. Is a self-signed replacement
    of that pair (a KeyholdersReplace, §4.3, §5.11) sound, given that the replaced pair may be the one a
    thief holds?
    - The Replace names the entry it swaps by its old `tag(KX)`. Its keyring welcomes are made from
      the old pair, which proves possession to the other keyholders; every other welcome and row, in
      and after it, comes from the new pair, and members key kept row bases by `tag(KX)`. A device that
      sees its own entry swapped by a commit it did not make warns and asks for that entry's removal.
      Keyholders refuse a keyring whose carried-over seeds or unchanged bucket keys differ from their
      own copy (§3.7).
    - A holder of the account's `IK` (any device of the account, a vault thief) can still sign
      headers as any of the account's keyholder entries: rule 2 checks the signer by its `IK`. Without
      the entry's pair it makes no welcome, row or keyring welcome as that entry, and without the
      keyring no seal to an existing version, so alone it can at most stall the group. With the relay
      it can sign a KeyholdersReplace naming a pair of its own. The other keyholders refuse that
      keyring, but members cannot check keyring welcomes, so on that branch it can re-seat members by
      welcomes from its own pair and act as a hostile keyholder until its entry is removed. The
      device whose entry it swapped sees the pushed header and warns. Is that bound acceptable?
12. **Fast new start** (§5.6, §5.7, owner 2026-11-19): a Regenesis 2 min after its parent when every
    entry of the set in force is a connection entry, checked by members from the signed headers, with
    the churn bound (a set a Regenesis started keeps the hour for an hour) and the relay refusing a
    Regenesis dated more than `CLOCK_SLACK` back. Known gaps: a hostile relay can have an online
    connection keyholder promote another connection, then drop both, and so start anew every few
    minutes, and it can have such a keyholder remove a desktop entry first (misses and time away are
    the relay's word), which leaves a set of connection entries alone; header times may run 10 min
    ahead, so a dishonest volunteer skips the 2 min. Each costs a re-seat and reads nothing. Does the rule hold anything else open, and is the churn bound worth
    keeping as it is, against counting any change of the set in the last hour?

## 8. Costs at 100,000 members

The figures in the tables are **estimates** from this design, with `B = 1613` buckets. What was
measured since is at the end of this section, under *Measured*. Sizes used:

| Thing | Bytes |
|---|---|
| Row, seal | 60 |
| Seat welcome / seed welcome / keyring welcome | 1694 / 1662 / 1662 |
| Header in an open group, with signature | about 450 (about 1.2 KB on headers that set keyholders) |
| `added` entry in a gated group | about 72 (`m` 17, `IK` 32, two tags 16, counter and time about 7) |
| `removed` entry in a gated group | 33 |
| Leaf plus inclusion path at `B = 1613` (11 levels) | about 420 |
| What a member fetches per epoch read: header, leaf and path, seal | about 0.9 KB, plus 60 B if its bucket was re-keyed |
| Keyring base (about 100 B per version) / delta per new bucket | about 160 KB / about 100 B |
| Writer blob | about 230 |

| Event | Keyholder | Each member | Writer |
|---|---|---|---|
| A post | — | The post + 52 B; 0.23 KB once per writer chain per epoch | Post + 0.23 KB once per epoch (today: 180 MB down, 17.6 MB up) |
| First seat | ↑ 1.7 KB + 60 B + 0.1 KB | ↓ about 2.6 KB once; gated: up to about 18 KB more, the `added` list of the Join header that seated it | — |
| Join commit of `n` joiners | ↑ `n` × 1.7 KB + 0.45 KB (gated: + 72 B × `n`) | Nothing, but for the joiners (First seat) | Gated: ↓ 72 B × `n` of names, pushed to each writer of the epoch, or 0.45 KB more as the whole header |
| Exit batch of `E` | ↑ 97 KB seals + 160 KB keyring + `E` × 61 rows × 60 B + merges ≤ 150 KB: about 0.27 MB + 3.7 KB × `E`, up to 0.42 MB + 3.7 KB × `E` with a full merge | ↓ about 0.9 KB when it next reads (gated: + 33 B × `E`) | New chain, + 0.23 KB |
| Refresh (every 5 min) | ↑ about 0.27 MB + one twelfth re-keyed (about 8.4k rows, 0.5 MB): about 0.8 MB, up to 0.95 MB with a full merge, so about 9–11 MB/h | ↓ about 0.9 KB per 5 min read; one 60 B row an hour | New chain |
| Promotion | ↑ 97 KB + 160 KB + ≤ 8 × 1.66 KB: about 0.27 MB; no rows | ↓ about 0.9 KB; derives its ratchet | New chain |
| Removal, resignation, a connection keyholder's disconnect | ↑ full re-key: 100k rows (6 MB) + 0.27 MB, at once; the seed roll it makes due starts at most once per group per 24 h, however many removals: 100k seed welcomes (about 166 MB) and 100k Kyber1024 encapsulations within 24 h of its start. A voice room rolls at once, at most 250 seed welcomes (about 0.4 MB) | ↓ 60 B + 0.9 KB, then 1.7 KB per roll | New chain |
| A keyholder replacing its pair (KeyholdersReplace) | ↑ as a Fresh, plus one keyring welcome per keyholder (≤ 8 × 1.7 KB): about 0.27 MB without rows, about 0.77 MB with a refresh slice (8.4k rows, 0.5 MB) | ↓ about 0.9 KB, as any opening header; 60 B if its bucket was re-keyed | New chain |
| Seed age: a roll every 30 days, text groups | ↑ 100k seed welcomes (about 166 MB) and 100k Kyber1024 encapsulations within 24 h of the roll's start: about 5.5 MB a day averaged | ↓ 1.7 KB once a month, as it fetches or by the 24 h sweep | — |
| One account rotates its seat keys | Its exit in a batch, and one 1.7 KB welcome per group it is seated in (the eager re-seat, §5.11) | Gated: 33 B for its old seat in `removed` | Gated: 72 B for its name |
| 100k guests reconnecting, all reading | ↑ about 170 MB in all, split among the keyholders, in 391 Join commits of 256, one after another | ↓ about 2.6 KB | — |
| A new generation (a restore, the switch back on, the last keyholder gone on a relay without accounts), or a Regenesis | As the reconnect: about 170 MB per 100k group, in 391 Join commits | ↓ about 2.6 KB; gated: up to about 18 KB more, the Join header that seated it | Gated: before its posts, every name since the Genesis (a new generation) or since its names floor (a Regenesis), about 7.2 MB at 100k in all (§4.4 rule 4) |

**Gated groups.** Only accounts sit in them, and an account's seat survives its disconnects, so
their joins are new accounts and seat-key rotations:
- Steady joins: at 100k with every account rotating every 30 days, about 140 names an hour, about
  10 KB an hour per writer. A growth spurt of 17 new accounts a second costs each writer about
  4.4 MB an hour.
- A full re-seat after a new generation or a Regenesis: each member that posts afterwards folds,
  before its posts, every name since the Genesis (a new generation) or since its names floor (a
  Regenesis), about `N` × 72 B in all: 7.2 MB at 100k, 720 KB at 10k. With 1000 writers the relay
  sends about 7.2 GB of names, where every reader taking them would have cost about 720 GB.

**Re-seat time.** Join commits on one group go one after another, at most 256 joiners each. So
re-seating 100k seats, after a new generation or in a guest reconnect storm, takes 391 commits
one after another: 117 s measured at 100k (§8, Measured). A member whose seat comes later than
`HOLD_MS` (60 s) after its post loses that held post, and its app says the post was not sent because
the channel's keys are late.

Per hour, at 100k:
- A member that reads every epoch through exit batches every 36 s fetches about 90 KB an hour. With
  refresh alone it fetches about 11 KB. In a gated group, add 33 B per exit; a writer also takes 72 B
  per new name.
- The relay sends about 90 MB per epoch if all 100k read it: about 2.5 MB/s at one epoch every 36 s.
- Keyholders together upload about 33 MB an hour with continuous exits (100 opening commits of about
  0.27 MB, plus 12 refresh slices of 0.5 MB), plus up to 150 KB per opening commit for merges, and
  3.7 KB per exit. Much of it is the keyring base at every opening commit. If C6 shows that it
  dominates, the base can become deltas too.
- All accounts rotating every 30 days cost the keyholders about 5.7 MB a day of welcomes.
- Keyholders replacing their pairs: a KeyholdersReplace each, a Fresh commit with one keyring welcome
  per keyholder: about 0.27 MB without rows and about 0.77 MB with a refresh slice, and never a seed
  change (owner, 2026-11-17). 8 desktop keyholders rotating every 30 days cost about 2–6 MB a month
  at 100k, where a full re-key and seed roll each would have cost about 1.4 GB.
- **Guest keyholder churn:** every departure of a connection keyholder costs a full re-key, about
  6.3 MB at 100k, and makes a seed roll due. Rolls start at most once a day (§5.6), about 166 MB each.
  On a relay without accounts at 100k, one keyholder disconnect an hour costs about 150 MB a day of
  re-keys plus at most 166 MB a day of seed welcomes, where a roll per departure would have cost about
  4 GB a day. That is why guests are a last resort on relays with accounts, and at most 2 per text
  group.

CPU:
- One X25519 per member per keyholder per seed, for `RB`. After that, a row costs one HKDF and one
  AES-GCM. A keyholder keeps the row bases in memory, per seat and seed, so only its first opening
  after it took the group (a promotion, a hand-over, a browser's reload or reconnect) pays the
  X25519s: that build is **cold**, the ones after are warm.
- 100k X25519 take about 3 s on a fast desktop core, up to about 9 s on a low-power core. In wasm an
  X25519 costs about 2.6 times native.
- One Kyber1024 encapsulation per welcome: about 22 µs natively, 0.6 ms in Chromium at `opt-level =
  "s"` and about 0.1 ms with libcrux at opt-level 3, which the browser build uses (open choice 28).
  A welcome's cost is mostly its X25519s, not Kyber.
- At the 10,000-seat browser limit a cold re-key is about 0.8–0.9 s of page time in wasm.
- **Builds run in steps** in the browser: after each unit of work (a row with its base, a welcome, a
  seal, a list check, the keyring seal, the bucket root, the signature) a build stops once its
  budget is spent (2 ms in a call or with the page hidden, 8 ms otherwise), so a step runs at most
  one unit past its budget. The keyholder's own check of its commit with the relay's validator is one uncut step:
  about 5.5 ms for an exits opening at 10k. A Genesis and a Regenesis build in one step.

**Measured** (2026-11-18 to 2026-11-21, one i9-13900K, Linux; the relay's side is in OPERATING
§10a):
- **Sizes** (C1 `group_cost`): an open-group header 383 B (about 413 with a 64-character id), a header
  that sets keyholders 1119 B, a keyring base 146.8 KB (91 B a version), a delta 119 B, an `added`
  entry 71 B, a `removed` one 33 B; an exit batch 0.244 MB + 3.66 KB × `E`, a refresh 0.75 MB. A
  member's epoch read is 854 B (914 with a re-keyed bucket) and 34 µs.
- **Native, one fast core:** X25519 26.2 µs, Kyber1024 encapsulation 22.2 µs and decapsulation
  25.8 µs, a seat welcome 94.2 µs, a Join of 256 24.6 ms (434 KB), a refresh 23 ms, a full re-key by
  rows 0.23 s warm and 3.1 s cold (9.0 s on a low-power core), a 100k re-seat 9.6 s of keyholder CPU
  in 391 Joins (169.5 MB), a 100k seed roll 9.6 s (166 MB), a voice room's roll at 250 seats 24 ms
  (415 KB), the names fold after a 100k re-seat 19 ms (7.1 MB).
- **In the app's own duty** (`group_load`): a Join of 256 builds in 27–33 ms, plus about 10 ms for
  its due's frames (mostly the 256 joiners' endorsement checks). A cold Remove at 100k builds in
  3.6 s. A 100k re-seat is bound by its 391 commits one after another, not by the CPU.
- **In the browser** (voipc-web, Chromium 156 and Firefox 159; opt-level 3 for libcrux):
  - a Join of 256 81–86 ms in Chromium (212–217 at "s"), 73–78 in Firefox;
  - a seed page of 256 75–76 ms in Chromium;
  - an exits opening of 720 at 10k: 133–151 ms warm, 0.82–0.87 s cold;
  - a refresh at 10k: 14–15 ms warm, 78–84 ms cold;
  - a voice Remove at 250 with every seat behind the last roll: 98.5 ms (224 at "s"); with none
    behind, 7.5–9.9 ms warm, 23–26 ms cold, and no seed welcome in the commit;
  - against native: X25519 2.6 times, row builds 2.5–3.5 times, builds that make welcomes 2.6–3.2
    times (4.0–8.7 at "s"), Kyber1024 2.4–4.7 times (8.9–28 at "s").
  - In steps of 2 ms, a cold re-key of 10k runs as about 400 steps, the longest 5.3 ms (the own
    check), and takes 0–5% longer in all than one block.
- Not measured: a text Remove by a promoted second keyholder in the browser, phones, a page doing
  anything else meanwhile, and the stepped builds' wall time on a busy page against the 4 s exits
  deadline.

## 9. Wire and storage (protocol 26)

This section was the sketch C1 and the review worked from. The messages as built, with every field,
direction, frame limit and the order relative to posts, are in `crates/voipc-protocol/src/gk.rs`
and the `Epoch*`, `Keyring*`, `Keyhold*`, `GroupKeys` and `VoiceSeats` variants of `messages.rs`;
the golden file is `tests/golden/v26.json`. Where the sketch below differs, those are right.

**Names.** Wire variants are `Epoch*`, `Keyring*` and `Keyhold*`; tables are `voipc_gk_*`. Nothing
then clashes with the user groups of 1.7 (`GroupSave`, `voipc_group_style`). Every `Epoch*` message
names its `group`, never a channel, since a channel's id can stand for groups of two kinds; one that
names an epoch also names its `gen`. The crypto module is `voipc-crypto/src/group_key.rs` (and
`group_state/` for the members' and keyholders' state), and the relay's is `gk/` with its store in
`accounts/gk.rs`. The tables come in migration `0013_group_keys.sql`.

**The relay switch.** A new top-level key in `server.toml`: `group_key = true`.
- With it on, a relay at 26 uses the group key everywhere. It refuses `KeyCheck`, `OpenSessions` and
  `DistributeSenderKeys` in text channels, and `SendEncryptedChannelMessage` there too (open choice
  13), and in voice rooms `DistributeMediaKey`, `DistributeSenderKey` and
  `SendEncryptedChannelMessage`, the 3N join and the pairwise chat key (§5.9). It answers the first
  such frame of a session with one `EpochRefused{LEGACY}`, and drops the rest.
- With it off, the relay keeps the old paths and refuses `Epoch*` and `Keyring*`. Group tables
  stay, and what kept chains reference is served read-only.
- It is read at start, so a channel never switches mid-life.
- The `GroupKeys{on, run, clock}` frame, right after `Authenticated`, tells the app which paths the
  relay uses (open choice 1), the run id of its `r:` groups and its clock.
- It is in COMPATIBILITY §3 "What changed in 1.14". It is an exception, as `[files]` was in 1.3:
  its default changes behaviour, and `false` keeps the old. An older relay refuses the key.

**The app.**
- An app at 26 keeps the live path and the 3N voice join, for relays at 21–24 (and the unreleased
  25) and for relays at 26 with the switch off: a relay that sends no `GroupKeys` frame, or one with
  `on: false`. It also keeps the paths from before 21, down to `OLDEST_RELAY_PROTOCOL`.
- It keeps both until `OLDEST_RELAY_PROTOCOL` reaches 26 and the switch is gone.
- The browser build keeps the old path too, for its own relay with the switch off.

**Client → relay (sketch):**
- `EpochFetch{group, have, seat_pair?}`. A connection's seat pair goes with its first fetch.
- `EpochCommit{group, parent, part, last, header?, welcomes, rows, seals, keyring}`. A commit spanning
  several frames is applied at its last.
- `EpochWelcomes{group, seed, welcomes}`, for a seed roll: seed welcomes (§3.2), one per seat.
- `EpochPost{group, gen, epoch, blob?, ciphertext}` and `EpochBlobWanted{group, gen, epoch, writer}`.
- `EpochNames{group, from, to}`: the `added` lists between two headers, for §4.4 rule 4: a writer's
  fold, or a member's app showing the list on demand. After a failed fold it also asks for the opening
  headers between that carry `removed` lists.
- `KeyholdVolunteer{platform, on, pair?, endorsement?}` (a desktop's keyholder pair, or a signed-in
  browser's connection pair), `KeyholdResign{group, entry?}`, and `KeyholdReplace{old, pair,
  endorsement}` for a desktop keyholder's new pair, `old` being its old pair's `tag(KX)` (§5.11).
  `entry` names an entry of the device's own account that a KeyholdersReplace it did not make swapped
  in; the relay proposes its removal at once (§5.6).
- `EpochFloorAhead{group, header}`.
- `AccountRequest::SeatKeysPublish{kem, dh, n, made, sig}`, after the vault save settles, beside the
  log key's. `AccountRequest::SelfRowPut{group, gen, seed, tags, kind, sealed}`.

**Relay → client (sketch):**
- `EpochDue{group, parent, joins, exits, lists, refresh, promote, remove, replace, start, deadline}`.
  - Each joiner comes with its `IK`, seat keys and endorsement.
  - Each exit comes with its `seq`, seat and bucket.
  - `lists` carries the seat lists of the buckets to re-version or merge.
  - `start` is `Genesis` or `Regenesis`, when the relay asks for a new generation (§5.1) or a
    Regenesis (§5.6).
  - `replace` asks a keyholder to swap its own entry for its new pair (§5.11).
- `EpochIn{group, headers, leaf, path, seal, welcome?, row?}`: the headers since the member's floor
  that §4.4 needs. The relay also pushes it unasked with every header that sets keyholders, and every
  Genesis and Regenesis (§4.4).
- `EpochNamesIn{group, lists, removals, step?}`: each `added` list with its header's `(time, epoch,
  join, names_hash)`; after a failed fold, `removals` holds the signed opening headers between that
  carry `removed` lists. Or "gone" when the floor is past the 90 days, with the 90-day tail in `lists`
  and `step` the one step before it (§4.4 rule 4). The relay also pushes it unasked with each gated
  Join's `added` list, to every writer with a chain in the current epoch.
- `EpochStale{group, head, reason}`.
- `EpochExit{group, seq}`.
- `EpochPostIn`, with `TextPost`'s fields plus `group`, `gen`, `epoch`, `blob?` and `ciphertext`.
- `EpochPostTaken{group, post}`, to the writer's own connection for each post the relay took, never
  for one it refused: `post` is the first 16 bytes of SHA-256 over the post's ciphertext, and the
  app files that post's kept copy then (§5.8, §5.10).
- `EpochBlob{group, gen, epoch, writer, blob}`.
- `KeyringIn{group, part, last, krk_welcome?, sealed}`, chunked like the commit.
- The voice seats come as `VoiceSeats` (open choice 2): each member's voice seat `(m, tag(SX))`,
  for the media keys (§3.10), beside the roster rather than in it.

**Relay timers and validator:**

| What | Value |
|---|---|
| Join batch | every 2 s; at most 256 joiners a commit |
| Exit batch | closes `exit_gap(N)` after its first exit (20 ms per seat, ≤ 36 s); voice: 2 s; in gated groups also at 768 exits |
| Opening commits | at most one per group every 2 s (`EPOCH_MIN_GAP`) |
| Deadline per keyholder | joins 5 s; exits 4 s (two fit in `CHECK_WAIT_MS`); refresh, promotion, removal, replacement 60 s; Genesis and Regenesis 30 s |
| Refresh | every 5 min; every 60 s with a single bucket |
| No keyholder online | a new Genesis at once on a relay without accounts and in voice rooms; in a stored group a Regenesis after 2 min when every entry of the set in force is a connection entry and no Regenesis started that set in the last hour, else after 1 h (§5.6) |
| Removal proposed | 3 missed or declined deadlines in an hour (any entry), or 7 days away (desktop entries); at disconnect (connection keyholders); at once for a device removed from its account; at once for an entry its account's own device reports swapped by a commit it did not make; 7 days after its account's counter passed the entry's. Never the last entry, and only one another online entry can sign |
| Hand-over | a higher-ranked volunteer promoted while a lower-ranked keyholder holds the role (§5.6) |
| Seed roll | every seat given a seed welcome within 24 h |
| Roll starts | text groups: at most one per group per 24 h, by header `time`, a Regenesis exempt; voice: at every keyholder removal, at once |
| Seed age | 30 days in text groups; then a roll is due |
| Seat expiry | 90 days unused |
| Names kept (gated) | 90 days: the `added` lists, the opening headers with `removed` lists, and the step before the oldest list |
| Names pushed (gated) | each Join's `added` list, as the Join is taken, to every writer with a chain in the current epoch |
| Old private parts kept | seat keys until the re-seat, at most 7 days; a keyholder's old pair until its replacement is taken, at most 7 days |
| Writer blobs | at most 2 per writer per epoch |
| Floor-ahead proofs | at most one new generation per group per hour; none for a removed keyholder's header |
| Open commit | one per keyholder per group; dropped 30 s after its first frame, or when the head moves; at most 56 KiB a frame and 12 MB in all (a full re-key at 100k is about 6.3 MB) |

The validator, modelled on `well_formed` and `chain_put`, takes a commit only if all of these hold:
- the signer is in the head's keyholder set, under §4.3's rule for the kind;
- the kind is the one it asked for;
- `gen`, `epoch`, `join`, `parent`, `epoch_parent` and `kh_parent` follow from the head: an opening
  header's epoch is the head's plus one, a Join header's join the head's plus one;
- the header's form passes §4.4 rule 1;
- the leaves rebuild `bucket_root`, and each list digest matches the relay's own list;
- no version adds a seat except a new Join bucket, and no bucket holds more than 62 seats;
- accounts and connections sit in separate pools, and `conn_seats` is the seat count of the
  connections pool: 0 when `gated`;
- in gated groups, `added` lists exactly the new seats, with the counters of their endorsements, and
  `names_hash` folds it onto the head's with the header's own `time`, `epoch` and `join` (§11.3);
  `removed` holds at most 768 entries;
- the seeds follow §4.3 and §5.6. A Regenesis always raises `seed`. Any other kind raises it only at
  a due roll (a removal since the last raise, or a text seed 30 days old), and in a text group never
  within 24 h of the last raise, nor while a roll runs. In a voice group every KeyholdersRemove
  raises it. A KeyholdersReplace changes neither `seed` nor `seed_floor`;
- a Regenesis comes no sooner than its wait after its parent and after no keyholder was online, by
  the set in force (§5.6), and is dated no more than `CLOCK_SLACK` before the relay's clock;
- a KeyholdersReplace swaps exactly one entry, named by its old `tag(KX)`, for one with the same `m`,
  `u` and origin and a higher `n`; it leaves the seed unchanged; and its keyring welcomes name the old
  pair as their maker (the other keyholders check that they open as from it, §4.3);
- every due joiner is seated, and every exit up to `exits_upto` is in no leaf;
- there is one welcome or row per new seat, and one seal per version the commit made, or per current
  version on an opening commit;
- the keyring hash chain matches what was uploaded;
- the counts agree, and the byte caps hold.

`EpochStale` reasons: not the head; not a keyholder; kind not due; a check above failed (which one);
timed out; the head moved.

**Relay state** per group: the head, the headers it keeps (§4.4), each seat's bucket, version, seed
and last use, the seat lists, the current seals, joins and exits due with the exit `seq`, the
keyholders with who is online and missed deadlines, the open commit, writer blobs per `w` and epoch,
the keyring pieces and `KRK` welcomes, and pending seed-roll welcomes. That is about 15 MB for a
100k group (an estimate). A gated group also keeps 90 days of `added` lists, and of the opening
headers that carry `removed` lists (§4.4): about 7 MB after a full re-seat at 100k, plus up to about
1 MB a day with every account rotating every 30 days (0.24 MB of names, 0.11 MB of `removed` entries,
and about 0.6 MB of headers at one per exit batch). That is about 90 MB over the 90 days.

**Database** (stored groups only; sqlite and postgres):
- `voipc_gk_groups`, `voipc_gk_gens`, `voipc_gk_headers`, `voipc_gk_seats`, `voipc_gk_lists`,
  `voipc_gk_vids` (version ids, kept for the generation's life, open choice 30), `voipc_gk_names`,
  `voipc_gk_welcomes`, `voipc_gk_rows`, `voipc_gk_seals`, `voipc_gk_keyring`, `voipc_gk_krk`,
  `voipc_gk_pending`, `voipc_gk_exits` (open exit batches outlive a restart), `voipc_gk_holders`
  (misses and away times outlive one), `voipc_gk_chains`, `voipc_gk_self` (keyed by group, account,
  generation, seed and seat tags), and `voipc_gk_seatkeys` beside `voipc_logkeys`, with each
  account's counter, all in migration `0013_group_keys.sql`;
- `voipc_meta` gets `gk_incarnation`;
- a relay without accounts keeps it all in memory, and so does every `r:` group (§5.12).

## 10. Tests and gates

- **Unit**, in `voipc-crypto/src/group_key.rs` (C1):
  - Every value opens only in its own context, in the style of
    `a_wrap_opens_for_its_recipient_and_its_context_only`. That covers the three welcome kinds, rows,
    seals, the keyring, blobs, chain seals, self-rows and media keys.
  - The welcome fails if Kyber, `eph` or `K`'s DH is wrong. A welcome made without `K`'s `KX` does not
    open. No welcome kind opens as another. A keyring welcome to a keyholder's pair does not open with
    its account's seat keys.
  - A leaver opens no later epoch, and a newcomer no earlier one. After a ratchet, the new keyholder's
    `BK` opens no seal of an earlier version, and the ratchet version keeps its source's `made`.
  - A mixed `CK` fails `confirm`, in a Join header too. A fresh device given a genuine Join header with
    a forged welcome and seal refuses it.
  - A header re-signed with `S + ℓ` keeps its `D`, and our wrapper refuses it.
  - Each of these is refused: a header with unsorted or duplicate lists, or non-canonical bytes; a
    forged header or blob; a guest in a gated header, or a gated header with `conn_seats` above 0; a
    header below the floor; an opening header whose epoch is not its parent's plus one; a walked
    header past the epoch bound; a generation among the last 8, or one whose Genesis is older than
    the floor's `time`; a Regenesis before its wait after its parent (2 min under a set of
    connection entries alone, the hour under one with a desktop entry, and the hour for a set a
    Regenesis started less than an hour before, on every member path, a floor-only member's
    included); a header 10 min ahead; an `added`
    entry or new keyholder with a counter below the highest seen for its account, in a header made
    after that endorsement's `made` plus `CLOCK_SLACK`.
  - **Names:** a gated writer's post is held until every `added` list since its names floor folds to
    the head's `names_hash`; a list left out, changed or reordered fails the fold. So does a list given
    another header's `time`, `epoch` or `join`: the hash binds them. A writer that folds its own
    account's old seat from a header made before its rotation does not flag it; from a header made
    after, it does. A gated reader takes headers without the lists, except the Join header that seated
    it.
  - A KeyholdersReplace is refused if it swaps more than one entry, or an entry other than the one
    named by the `tag(KX)` its keyring welcomes come from; keeps the entry's counter; changes its
    member id, user id or origin; changes `seed` or `seed_floor`; or makes rows other than a Fresh
    would make them (leavers, the refresh slice, merges, versions over 1 h old).
  - **Swap from a sibling device:** a KeyholdersReplace signed with the account's `IK` by a device
    that lacks the old pair, so its keyring welcomes do not open as from it, is refused by the other
    keyholders. So is a keyring whose carried-over seeds or unchanged `BK`s differ from their own copy.
    After a swap, a member's kept `RB` of the old pair opens no row of the new one.
  - A post with the wrong `(gen, e, D_e)` prefix under a valid chain is refused. So is a blob moved to
    another header.
  - A re-version with an extra seat is refused, by the list digest.
  - A keyring whose hash, root, `conn_seats`, `(gen, e, j, s)`, seed list or `confirm` does not match
    the head is refused, and so is an all-zero key.
  - A row or welcome under the wrong seed number does not open.
  - Two senders with equal stream ids, and equal session ids, get different media keys.
  - **Contexts:** a collision test like `the_labels_never_collide`. Every label is unique, every
    context carries `|k|group|` right after its label, and no two field tuples give one string.
  - **Known answers** (§11.9).
- **Client** (`channel_state` style, C3):
  - A writer holds 46 s (`EXIT_GAP_MAX_MS + CHECK_WAIT_MS`) after `EpochExit` without a covering
    opening header, and at an epoch age of 70 min. Readers warn. In a voice room the app keeps voice,
    video and screen share going and warns.
  - A keyholder keeps the seats it sealed, names them after `EpochStale`, and warns when the head no
    longer descends from its Join commit, or when no header reaches it within 70 min.
  - A phone refuses a text promotion, and a browser one above 10,000 seats.
  - A guest keyholder resigns when a later header adds an account keyholder; a browser keyholder when
    a later header adds a desktop keyholder.
  - **Generations:** a voice joiner whose floor for the room is from 30 min earlier, in a generation
    since dropped, takes the room's current one. A member back online 2 h after a restore takes the
    new generation. A fresh device takes a generation begun 3 days ago. A member back after a 2 h
    absence takes a Regenesis. A device that took a header 5 min ago refuses a Genesis 20 min old.
  - Two devices' vault floors merge to the generation with the later `gen_time`. No header of a stored
    group is taken before the floor pages are in.
  - A gated writer back after a day folds every name since its names floor before its first post, and
    a reader back after a day takes the head without them.
  - **Tail proof:** a writer away 91 days takes "gone" only with a step before the tail that is more
    than 90 days old and folds, with the tail, to the head's `names_hash`; it shows the tail's names
    and says that people joined more than 90 days ago whose names it was not shown. A step younger
    than 90 days, or one that does not fold, is refused. One away 89 days does not accept "gone".
  - **Failed fold:** a writer whose fold meets a guest seat, a pin mismatch or a flagged counter holds
    its posts and says why, keeps its names floor before that list, and posts again once an opening
    header names the seat in `removed`. A writer whose fold meets its own account named with an old
    counter, in a header made after its rotation, holds its posts and warns; its own old seat from
    before the rotation is not flagged.
  - In a gated voice room every member folds the Join headers as they come; a failed fold warns, and
    voice keeps going.
  - A keyholder starts a due roll at its first opening commit after the slot opens, with no
    `EpochDue` asking for it. A seat still on a dropped seed gets its seed welcome before any row.
  - A device that sees its own entry swapped by a KeyholdersReplace it did not make warns and asks for
    that entry's removal.
  - The app shows no keyholder, "made anew by" or new-reader names in anonymous rooms, and in
    `hide_members` rooms only to admins.
- **Relay** (`session_tests`, C2):
  - Of two commits on one parent, exactly one wins. A multi-frame commit is atomic.
  - Exits batch. An opening commit that leaves an exited seat in a leaf is refused. The exit deadlines
    leave each of two keyholders 4 s within `CHECK_WAIT_MS`. A gated batch of 2000 exits spans 3
    opening commits, each `exits_upto` a prefix, and writers are told of each exit as it enters a
    batch. Opening commits come at most one per 2 s.
  - A gate going on: the relay exits every connection seat while the group is open, and a keyholder
    refuses a gated header while a connections-pool bucket is left.
  - An account's seat survives a disconnect, and a guest's does not. A connection keyholder's
    disconnect is a removal.
  - **Guest keyholder hand-over:** with 2 guest keyholders online, an account volunteer coming online
    is promoted, and a guest resigns once that KeyholdersAdd is taken. The same for a browser keyholder
    when a desktop volunteer comes online. At most 2 guest keyholders per text group, and none in
    gated groups.
  - A stalled keyholder is passed over.
  - With no keyholder online: voice rooms and relays without accounts start a new Genesis at once; a
    relay with accounts offers a Regenesis after 2 min when the set in force is all connection
    entries, after 1 h when it holds a desktop entry, and after 1 h again within an hour of a
    Regenesis; it refuses a Regenesis dated more than `CLOCK_SLACK` back. A newcomer is seated soon
    after the sole browser keyholder reloads, or after a relay restart of a browser-held channel
    (`e2e_j8h_*`, `e2e_j9n_*`).
  - **Restore:** after `db new-incarnation` the relay starts a new generation, and members follow it.
    `EpochFloorAhead` without a valid header changes nothing, nor does one signed by a removed
    keyholder, nor one for a generation the relay does not know (that raises the admin warning).
  - **Rotation:** an account's rotation exits the old seat and seats the new one in each of its
    groups; the old private parts go once that is done, or after 7 days. The old seat keys offered
    again later are refused. A keyholder's rotation is a self-signed KeyholdersReplace that swaps its
    entry with rows only as a Fresh would make them and no seed change, and **a group whose single
    keyholder rotates** keeps going.
  - **Seed rolls:** two removals while a roll is due share it; a removal while a roll runs makes the
    next one due. The validator refuses a commit that raises `seed` when no roll is due, or within 24 h
    of the last raise in a text group, and a KeyholdersRemove made 25 h after the last roll starts the
    next one itself.
    - **Monthly roll:** a text seed whose roll started 30 days ago makes a roll due, and the next
      opening commit starts it.
    - A Regenesis within 24 h of a roll is taken, and clears a due roll.
    - In a voice room a KeyholdersRemove rolls the seed at once, within 24 h of the last roll too.
  - A device removed from its account loses its keyholder entries.
  - A seat unused for 90 days exits.
  - Every header that sets keyholders reaches the seated members online without their asking.
  - **Pushed Join lists:** each gated Join's `added` list reaches every writer with a chain in the
    current epoch without its asking. After a failed fold the relay sends the opening headers that
    carry `removed` lists, and it answers "gone" with the step before its 90-day tail.
  - At most 2 writer blobs per writer per epoch are kept; both serve a reader seated late.
  - A change of `anonymous` moves the channel to its other group id, and back again starts a new
    generation.
  - With the switch off, the relay keeps the old paths, and still serves what the key kept.
  - `r:` groups write nothing to the database.
- **Voice** (C5): a join is one welcome. Chat in a voice room goes under the voice group, and the
  relay refuses `DistributeSenderKey`, `DistributeMediaKey` and `SendEncryptedChannelMessage` there.
- **Compatibility:**
  - The apps choose the path by the `GroupKeys` frame: none, or `on: false`, means the live path and
    the 3N voice join (`the_frame_after_authenticated_chooses_the_path_once` in `gk_net.rs`,
    `live-gk.test.ts`, `voice-gk.test.ts`), and the `GK=0` lane of `test-web.sh` runs a relay with
    the switch off.
  - The nightly old-relays job covers text channels on released relays, 1.12.0 the newest; 1.13.0
    joins once it is tagged.
  - Golden `v26.json`, re-recorded with the group key in it, and compat rows as usual.
- **Fuzz:** `fuzz/fuzz_targets/group.rs` covers every opener, the header decoder, the Merkle path check
  and the relay's commit validator.
- **Mutation:** `cargo mutants` over voipc-crypto's `group_key` module in C1 (1087 mutants): every
  survivor was killed by a test or shown equivalent. It was not run again on the code that came after.
- **Load:** `examples/group_load.rs` (C6): `seats N` (offline accounts seated eagerly, SQLite or
  Postgres), `storm N` (guests connecting, then a reconnect storm), `exits R` (continuous exits with posts
  and a keyholder's Remove in flight) and `--check` (the smoke run). It reports the re-seat time, posts
  held and dropped, bytes per member per hour and keyholder CPU, natively. The browser's numbers come
  from `tools/gk-wasm-bench.mjs` (`gk_bench.rs`). A storm of 100k guests was not run (it needs about
  38 GiB). The results are in OPERATING §10a and §8 above.
- **Reviews:** no external review (owner, 2026-11-17). Before release, an adversarial review of our
  own of the whole built state machine: independent reviewers, each told to refute a §7 answer or a
  §6 claim against the code, with every finding verified before it counts. Then the owner's review.

## 11. Encodings

**Choices pinned after C1.** Where the text left two readings, C1's code chose one, and Python
vectors written from this text alone match it (§11.9). Each is now stated where it belongs:
- `names_hash` hashes `postcard(added)` with the variant index of `List`, not the bare list (§11.3).
- The keyring hash chain hashes each sealed part whole, nonce included (§11.6).
- Bucket leaves and keyring buckets go by `b` as a u64 number, `seeds` by seed number, and every
  other list by its encoded bytes (§11.2).
- Every HKDF output is 32 bytes (§3).
- `KS` hashes postcard's length prefix of the list too (§11.6).
- A `[u8; N]` field is its N bytes, with no length (§11.2).
- XEdDSA is libsignal's variant, and `S` is read with the sign bit cleared (§3).
- The SKDM is libsignal's own serialization (§11.7). A Kyber1024 public key and a ciphertext start
  with the type byte 0x08 (§11.2).
- The chain and media contexts carry the group's own kind, and the other kind is refused (§11.1).
- The Merkle root of no leaves is `SHA-256("")` (§11.4).
- The low-order refusal covers identity keys (§3).
- An origin 0x02 endorsement names the connection's own seat id, for a signed-in member too (§11.8).
  This one was decided after C1, not read from its code.

### 11.1 Contexts

One encoder makes every context: the label, then each field after a `|`, in the order below. Fields
never contain `|`. The string's UTF-8 bytes are the HKDF info and the AAD.

| Name | Fields after the label `voipc-gk/v1/<name>` |
|---|---|
| `member` | `k`, `group`, `gen`, `s`, `m`, `tag_sk`, `tag_sx` |
| `welcome` (seat) | `k`, `group`, `gen`, `s`, `kyber1024`, `seat`, `b`, `v`, `m`, `tag_sk`, `tag_sx`, `K`, `tag_kx` |
| `welcome` (seed) | `k`, `group`, `gen`, `s`, `kyber1024`, `seed`, `m`, `tag_sk`, `tag_sx`, `K`, `tag_kx` |
| `welcome` (keyring) | `k`, `group`, `gen`, `s`, `kyber1024`, `keyring`, `e`, `KS`, `K'`, `tag_kk'`, `tag_kx'`, `K`, `tag_kx` |
| `rowbase` | `k`, `group`, `gen`, `s`, `m`, `tag_sx`, `K`, `tag_kx` |
| `row` | `k`, `group`, `gen`, `s`, `b`, `v`, `m`, `K` |
| `seal` | `k`, `group`, `gen`, `e`, `D_e`, `b`, `v` |
| `ratchet` | `k`, `group`, `gen`, `e`, `b`, `v`, `v'` |
| `confirm` | `k`, `group`, `gen`, `e`, `j` |
| `list` | `k`, `group`, `gen`, `b`, `v` |
| `keyring` | `k`, `group`, `gen`, `e`, `j`, `s`, `KS`, `base` or `delta` |
| `writer` | `k`, `group`, `gen`, `e`, `D_e`, `w` |
| `writer-sig` | `k`, `group`, `gen`, `e`, `D_e`, `w`; the signed message is this string, one more `\|`, and the SKDM's raw bytes |
| `dist` | `k`, `group`, `gen`, `e`, `D_e` |
| `chain` | `k`, `group`, `gen`, `e`, `D_e`, `owner`, `chain`, `index` |
| `media` | `k`, `group`, `gen`, `e`, `D_e`, `m`, `tag_sx`, `stream` |
| `self` | `k`, `group`, `gen`, `s`, `m`, `tag_sk`, `tag_sx` |
| `self-history` | `k`, `group`, `gen`, `s`, `m`, `tag_sk`, `tag_sx` |

For example, a seal context reads
`voipc-gk/v1/seal|t|c:lounge-1|000102…0f|7|<64 hex>|81985529216486895|3`.

Field formats:
- `k`: `t` or `v`, always the group's own kind. A chain seal is made and opened only in a text
  group, so its `k` is `t`. A media key is derived only in a voice group, so its `k` is `v`. Each
  refuses a group of the other kind.
- `group`: `c:<…>` as `log_conv` makes it, or `r:<32 hex>:<decimal channel id>`. ASCII, no `|`, at
  most 128 bytes; any other is refused. A channel `uid` is 1–64 letters, digits, `-` or `_`, so every
  valid log conv fits.
- `gen`: 32 hex digits. `D_e`, `KS`: 64 hex digits. `tag_*`: 16 hex digits. Hex is lowercase, as
  `voipc_protocol::conv::hex` writes it.
- `e`, `j`, `s`, `chain`, `index`, `stream`: decimal u32, no sign, no leading zeros. `b`, `v`,
  `v'`: decimal u64.
- `m`, `K`, `K'`, `owner`: `a:<32 hex>` for an account, `g:<decimal user id>` for a connection's own
  seat.
- `tag_kk'`, `tag_kx'`: the tags of the receiving keyholder's own pair; `tag_kx`: of the sending
  keyholder's `KX`.
- `w`: `<m>/<u>`, for example `a:0101…01/42`.
- `kyber1024`, `seat`, `seed`, `keyring`, `base`, `delta`: those literal words. A later KEM gets its
  own word.

Labels that are not contexts. Each is a byte prefix followed by binary data:
`voipc-gk/v1/tag|`, `voipc-gk/v1/digest|`, `voipc-gk/v1/header-sig|`, `voipc-gk/v1/seat|`,
`voipc-gk/v1/leaf|`, `voipc-gk/v1/node|`, `voipc-gk/v1/keyring-hash|`, `voipc-gk/v1/keyholders|`,
`voipc-gk/v1/names|`.

Every label differs from every other, from today's (`voipc-seat/v1`, `voipc-chain/v1`, …), and none
is a prefix of another followed by `|`.

### 11.2 Keys, integers and lists

- `ser(X25519 public)` is 33 bytes (`0x05 ‖ 32`). `ser(Kyber1024 public)` and `ser(ct_q)` are 1569
  bytes (`0x08 ‖ 1568`): 0x08 is libsignal's type byte for Kyber1024. Tags, salts, endorsements and
  the welcome on the wire use `ser`.
- Headers carry Curve25519 keys (`IK`, `KX`) as their 32 raw bytes.
- Integers outside postcard are big-endian: the post prefix's epoch, length prefixes, the
  endorsement's `n` and `made` (§11.8), and the `time`, `epoch` and `join` of each `names_hash` step
  (§11.3). Every integer inside a postcard struct, `KeyringBucket.made` among them, is postcard's
  varint.
- X25519 shared secrets are the 32 raw bytes libsignal's `calculate_agreement` returns. `ss_q` is the
  32-byte Kyber shared secret.
- In postcard, a `[u8; N]` field is its N bytes with no length (a postcard array). A `Vec` starts
  with its length as a varint.
- Order of lists:
  - bucket leaves (§11.4) and keyring buckets (§11.6) go in ascending order of `b` as a u64 number,
    each `b` once. A u64's varint bytes do not sort as the number does, so they are not used here;
  - a keyring base's `seeds` go in ascending order of seed number (§11.6);
  - every other list goes in ascending order of its entries' encoded bytes, each once: the header's
    lists (§11.3), and so `KS`; the seat records of a list digest (§11.5); the history row (§11.7).

### 11.3 Header

The body is the postcard encoding of:

```rust
enum Header { V1(HeaderV1) }                  // postcard: variant index, then the struct
struct HeaderV1 {
    group_kind: GroupKind,                    // Text = 0, Voice = 1
    group: String,
    gen: [u8; 16],
    epoch: u32,
    join: u32,
    kind: Kind,                               // Genesis 0, Regenesis 1, Fresh 2, Join 3,
                                              // KeyholdersAdd 4, KeyholdersRemove 5,
                                              // KeyholdersReplace 6
    time: u64,
    parent: [u8; 32],
    epoch_parent: [u8; 32],
    kh_parent: [u8; 32],
    signer: MemberId,                         // Account([u8; 16]) = 0, Conn(u32) = 1
    keyholders: Vec<Keyholder>,               // empty unless the kind sets keyholders; ≤ 8
    gated: bool,
    seed: u32,
    seed_floor: u32,
    exits_upto: u64,
    seats: u32,
    buckets: u32,
    conn_seats: u32,                          // seats in the Conns pool; 0 when gated
    bucket_root: [u8; 32],
    keyring_hash: [u8; 32],
    names_hash: [u8; 32],                     // zero in open groups
    added: Added,                             // Count(u32) = 0 in open groups, List(Vec<AddedSeat>) = 1 in gated
    removed: Removed,                         // Count(u32) = 0, List(Vec<SeatRef>) = 1, likewise
    confirm: [u8; 32],
}
struct Keyholder {
    m: MemberId,
    u: Option<u32>,                           // the connection's user id: Some for voice keyholders, else None
    origin: u8,                               // 0x02 a connection's seat pair, 0x03 a desktop's keyholder pair
    n: u32,                                   // the endorsement's counter (§11.8)
    ik: [u8; 32],
    kx: [u8; 32],
    tag_kk: [u8; 8],
}
struct AddedSeat { m: MemberId, ik: [u8; 32], tag_sk: [u8; 8], tag_sx: [u8; 8], n: u32, made: u64 }
struct SeatRef   { m: MemberId, tag_sk: [u8; 8], tag_sx: [u8; 8] }
```

- Lists are sorted by their encoded bytes, ascending, with no duplicates.
- A body that does not re-encode to the same bytes is refused, which also refuses overlong varints.
- A header body is at most 32 KiB. A Join commit seats at most 256 joiners (about 18 KB of `added`
  entries in a gated group), and a gated opening header removes at most 768 seats (about 25 KB).
- The signature (64 bytes) travels beside the body, never inside it.
- **`names_hash`.** In a gated group each step binds the list to its header's own `time`, `epoch`
  and `join` (default, 2026-11-17):
  ```
  names_hash = SHA-256("voipc-gk/v1/names|" ‖ P ‖ time (u64 BE, 8) ‖ epoch (u32 BE, 4)
                       ‖ join (u32 BE, 4) ‖ SHA-256(postcard(added)))
  ```
  - `time`, `epoch` and `join` are this header's own fields, as fixed-width big-endian integers, not
    postcard varints.
  - `postcard(added)` is this header's `added` field exactly as the body encodes it, the enum and
    not the bare list: the variant index of `List` as a varint (`01`), the list's length as a
    varint, then the entries sorted by their encoded bytes. An empty list is the two bytes `01 00`.
  - The preimage is 98 bytes: the 18-byte label, `P` (32), `time` (8), `epoch` (4), `join` (4) and
    the list digest (32).
  - At a Genesis, and at the opening header that turns `gated` on, `P` is 0³² (32 zero bytes). That
    first step is taken even when the list is empty.
  - At any other header with a non-empty `added` list, `P` is `parent.names_hash`.
  - At a header with an empty list, `names_hash = parent.names_hash`: no step.
  - It runs on through a Regenesis. In an open group it is all zero.
  - "Fold" in §4.4 rule 4 means taking the steps, list by list, from the names floor's value, each
    with its own header's `time`, `epoch` and `join`. A "gone" answer's step before the tail is the
    same step, with `P` and the list digest given as bytes, since the relay no longer holds that list.

### 11.4 Bucket root

- One leaf per current bucket version, in ascending order of `b` as a u64 number, each `b` once
  (§11.2). The leaf is the postcard encoding of
  `Leaf { b: u64, v: u64, pool: Pool (Accounts 0, Conns 1), seats: u16, list: [u8; 32], via: Via }`,
  with `Via = Row (0) | Ratchet { from: u64 } (1)`.
- `leaf_hash = SHA-256("voipc-gk/v1/leaf|" ‖ leaf)`. `node = SHA-256("voipc-gk/v1/node|" ‖ left ‖ right)`.
- The tree takes the shape of RFC 6962 §2.1: it splits at the largest power of two below `n`.
- With no leaves, the root is `SHA-256("")`, RFC 6962's root of the empty tree, with no label. A
  group whose last seat left has none.
- A path is the sibling hashes from the bottom up, with the leaf's index and `n`.

### 11.5 Seat records and list digest

- A seat record is 33 bytes: `kind (1: 0x01 account, 0x02 connection) ‖ id (16: the account id, or
  12 zero bytes ‖ user id u32 BE) ‖ tag_sk (8) ‖ tag_sx (8)`.
- Its first 17 bytes are the seat id of the seat's member id `m`. A signed-in member's voice seat
  has the account's (§5.9), except in an anonymous room that is not gated, where every seat is the
  connection's (`Conn(u)`, open choice 11). An endorsement signs a seat id too, chosen by its origin
  (§11.8).
- `list(b,v) = SHA-256(len(c) u32 BE ‖ c ‖ records)`, with `c = ctx(list; k, group, gen, b, v)` and the
  records sorted ascending and deduplicated, as `log.rs` `list_digest` does.

### 11.6 Keyring and keyholder set

- `KS = SHA-256("voipc-gk/v1/keyholders|" ‖ postcard(keyholders))`, over the sorted list of §11.3.
  `postcard(keyholders)` is the `Vec<Keyholder>` as the header body encodes it: its length as a
  varint, then the entries sorted by their encoded bytes. The length is part of what is hashed.
- The base is `postcard(KeyringBase { gen, epoch, join: 0, seeds: Vec<(u32, [u8; 32])>, ck: [u8; 32],
  exits_upto: u64, buckets: Vec<KeyringBucket> })`. `seeds` is in ascending order of seed number,
  from `seed_floor` to `seed`, each once.
- A delta is `postcard(KeyringDelta { join: u32, buckets: Vec<KeyringBucket> })`.
- `KeyringBucket { b: u64, v: u64, pool: Pool, seats: u16, list: [u8; 32], via: Via, bk: [u8; 32],
  made: u64 }`, in ascending order of `b` as a u64 number (§11.2). A keyholder that takes a keyring
  puts the base's and the deltas' buckets together in that order before it builds the root, and
  refuses a `b` that comes twice. `made` is unix seconds; a ratchet version copies its source's.
- The hash chain of §3.7 hashes each sealed part whole, as it is stored: `SHA-256(iv ‖ ct ‖ tag)`,
  nonce included. It never hashes a plaintext.
- Which values a keyholder checks where (§3.7): `gen`, `e`, `j`, `s` and `KS` come from the AEAD
  context, built from the head. The base's `gen`, `epoch` and `join`, each delta's `join`, and the
  seed numbers in `seeds` are struct fields, checked against the head after opening.

### 11.7 Blob, post, welcome

- The blob plaintext is `len u16 BE ‖ SKDM ‖ ser(IK_w) (33) ‖ sig (64)`.
- `SKDM` is libsignal's `SenderKeyDistributionMessage` in its own serialization (a version byte,
  then its protobuf), taken whole. The writer's signature (§3.8) covers these same bytes.
- The post plaintext is `gen (16) ‖ epoch (u32 BE) ‖ D_e (32) ‖ body`.
- A welcome is `ser(ct_q) (1569) ‖ ser(eph.pub) (33) ‖ iv (12) ‖ ct ‖ tag (16)`.
- The history row's plaintext is `postcard(Vec<(MemberId, [u8; 8], [u8; 32])>)`, in ascending order
  of each entry's encoded bytes, each once.

### 11.8 Seat endorsement

```
sig = XEdDSA(IK, "voipc-gk/v1/seat|" ‖ origin (0x01 vault seat, 0x02 connection pair,
                 0x03 desktop keyholder pair) ‖ seat id (17, as §11.5) ‖ n (u32 BE) ‖ made (u64 BE)
                 ‖ ser(KEM.pub) (1569) ‖ ser(DH.pub) (33))
```

- `KEM` and `DH` are `SK` and `SX` for a seat, `KK` and `KX` for a desktop keyholder pair.
- The seat id says whose pair it is (decided after C1):
  - origins 0x01 and 0x03: the account's, `0x01 ‖ account id (16)`;
  - origin 0x02: always the connection's own, `0x02 ‖ 12 zero bytes ‖ u (u32 BE)`, with `u` the user
    id of the connection that made the pair. That holds for a signed-in member too. A signed-in
    browser's keyholder pair and a signed-in member's voice seat are endorsed by the account's `IK`
    with the account's counter (§2), and still name the connection, so the endorsement says which
    connection the pair is for.
- For a signed-in member, only the endorsement names the connection. The seat stays the account's:
  its seat record (§11.5), the `m` of every context, and a keyholder entry's `m`. A checker needs
  `u` to rebuild the signed bytes. A voice keyholder entry carries it (§11.3); elsewhere it comes
  with the endorsement.
- `n` is the account's seat-key counter: the vault item's own for origin 0x01, and the account's
  current one when the pair was made for 0x02 and 0x03. A guest's is 0, and its `IK` is per
  connection anyway. `made` is unix seconds.
- An 0x02 endorsement by an account's pinned `IK` counts toward that account's highest `n` (below).
  A guest's counts toward none.
- Keyholders, and writers at their fold, keep the highest `n` they have seen per account, with that
  endorsement's `made`, beside the pins. They refuse an endorsement, or an `added` entry, below it in
  a header (or for a join) made after that `made` plus `CLOCK_SLACK` (§4.4 rule 8, §5.11). The
  own-account warning comes at a fold, so an account's own app sees it only where it writes.
- A separate label for guests replaces today's prekey signatures over the bare key bytes
  (`prekey.rs`).

### 11.9 Known-answer vectors

C1 generates the vectors and keeps them as tests in `group_key.rs`, as `log.rs` does, with fixed
inputs (`run(n)` byte runs, the group `c:kat`).

| Vector | Computed by |
|---|---|
| Every context string, from fixed fields | String equality |
| `tag`, `D`, `KS`, `list`, `names_hash` (a first step and a later one, each with its `time`, `epoch` and `join`), the keyring hash chain, the Merkle root and a path | Python `hashlib`, outside this code |
| `s_m`, `RB`, the row and seal keys, the ratchet, `confirm`, the media key, the blob and chain keys | Python `hmac`/HKDF, outside this code |
| Rows, seals, blobs and self-rows, made with fixed nonces; the code must open them | Python `cryptography` |
| A seat, a seed and a keyring welcome, each whole: the recipient's and `K`'s key pairs from `KeyPair::generate` and the welcome's `eph` and `ct_q` from `Kyber1024.Encaps`, all under one seeded `CryptoRng`, with a fixed AES-GCM nonce; and the opened `P` | libsignal, from the seeded RNG. In the libsignal that `Cargo.lock` pins (v0.105.4), `kem::Key<Public>::encapsulate` and `KeyPair::generate` draw every random byte from the RNG passed in, so the whole welcome is fixed, both sides |
| An endorsement for each origin, with its `n` and `made` | This code, cross-checked against Python for the signed bytes |
| A header body, its `D`, and a recorded signature that verifies, and that `S + ℓ` keeps `D` | This code, cross-checked against Python for `D` |
