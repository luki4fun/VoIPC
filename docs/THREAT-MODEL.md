# What each party can do (1.4)

Who can do what to a VoIPC user, as of 1.4, and what in the code holds each
"cannot". Tests are named so they can be found with a search; `test-ui` checks
run in the browser lanes of `test-web.sh`.

| Who | Can | Cannot | Held by |
|---|---|---|---|
| **The relay, honest or only curious** | See metadata: who is connected and from which address, which channel, when, and how big each packet is. With accounts, also what [ACCOUNTS.md](ACCOUNTS.md) lists for kept messages: who wrote where, when, how long, and each copy's timer. For files posted in chat: each blob's size, when it is uploaded and fetched and by which connection, and which conversations it was posted or forwarded in (which links them); a re-upload shows which members still hold it. | Read messages, voice, video, screen audio, positions, kept copies or vault items. Read a file, or learn its name or type: each is sealed under its own key, which only the end-to-end message carries. | libsignal sessions; `media_keys` (AES-256-GCM); `log::seal_entry`; the vault (`account::Vault`); `voipc_crypto::file` (`known_answers`). |
| **The relay, actively hostile, for desktop users** | Meet guests in the middle: a guest's identity is per connection and not verified, by design. Seat a listener in a channel (the member list shows it). With accounts: meet you before the person you meant to meet; hide, drop or roll back vault items, the pins included; withhold kept copies or hand them out again; guess a password offline, at 600,000 PBKDF2-SHA256 rounds a guess; keep a writer on an old key of their own, which helps it only together with a member who left. | Read kept copies or vault items without the password. Forge or alter a member's kept entry (each is signed). Add a reader without the writer's device naming them. Replace a pinned key unnoticed, unless it removes the pins first, and then a device that saw them warns. Hand out a name no account could have (a letter from another script that looks like a Latin one, an invisible character) without a warning: it is treated as a name taken over. Make one member's voice play as another's. Bring back entries already read, or a cleared conversation. Claim another relay's id to get a password stretched for that one. Hand over another file under a file's id, or one that opens differently for two members (the key is committed). It can withhold a file, or say nobody has it. | `a_rewritten_sender_fails`; `a_replayed_session_start_on_the_last_resort_key_is_refused`; `vault_pins_it_cannot_trust_are_reported_and_never_saved_over`; `a_merged_pin_that_disagrees_is_reported`; `a_look_alike_name_from_the_relay_is_a_warning`; `a_server_claiming_another_servers_relay_id_gets_nothing_of_the_password`; `AccountSync::drain` drops entries at or below the read cursor; `the_recovery_key_sets_a_new_password_and_signs_every_device_out` (the relay checks the identity's signature); `another_blob_is_not_this_file`; `another_key_is_refused_by_the_commitment`. |
| **The relay, actively hostile, for browser users** | Everything above, and serve a page that reads what you type (your password included) and takes the remembered device keys and vault keys this page keeps, for every server opened in it. | Nothing the page itself cannot do. | Only the desktop app; the connect dialog warns when an account is on another server than the page's own. test-ui: "a server claiming another's relay id is refused". |
| **A member of a channel** | Read what is said there while a member, and keep copies. Hand over history, which is shown as second-hand. Prove that you wrote a kept message (they are signed). Keep a message you deleted: every VoIPC app removes it, but a modified one need not, and anyone may have copied it first. Put any name and time on a forward: *Forwarded from* is the forwarder's word. In a direct conversation, with a modified app, notice when you open a file they sent you after the relay's copy has gone: the relay asks their app for it again. Only the conversation it is opened in is asked, so where else it was forwarded learns nothing. With a modified app, also ask whether your device still holds a file whose id they know from any conversation they are or were in, and make it upload the file again: they post a message naming the file in a conversation with you and fetch it there, and your app, which holds the file and now has a message about it, uploads it with nothing on screen. In a direct conversation the answer is about you; in a channel, about someone there. Each time the relay has let the file go, it costs your upload budget again. | Forge another member's message or kept entry. Fetch a file posted in a conversation they are not in, unless they hold its id, which only its messages carry (then they can file it under a conversation of their own; without the key the blob says nothing). Read what is written after they left a text channel (the relay takes them out of its log, and the next message is under a new key) or after the next media key once they left a voice channel. Offer a media key for a room they are not in. Speak as another member. Edit or delete your messages: each app checks the writer, and takes a guest's change only for what it received on that guest's connection. Pin a message where the member list does not show them as a manager of the channel. | `leaving_a_text_channel_ends_its_readership`; the media-key rules in `channel_state` and `media_keys`; `a_rewritten_sender_fails`; `only_its_conversations_may_fetch_and_an_unknown_hash_looks_the_same`; `a_blob_that_has_gone_is_asked_for_and_the_waiter_is_served`; `chat-rules.test.ts`: "an edit applies only from the message's writer, and marks it edited", "a guest changes only what this connection received from them (R3-11)", "a pin counts only from a manager, and the latest pin event wins". |
| **A member with privileges** (a group's, 1.7) | What their privileges say and no more: kick, ban, the ban list, channels, emotes, the account list and history (no addresses), giving groups, editing groups. A ban covers an address, and ends every session there that holds no privilege, so whoever bans learns which other people were connected from the banned person's address: they leave at the same moment. That is by design: a ban is meant to cover the household or office. | Kick or ban an admin or anyone else with a privilege. Hand out a privilege they lack, or act on an account holding one they lack. Give or take a group with privileges, or edit a group, without a fresh two-factor code. See behind an anonymous channel, or the roster of a channel that hides its members (admins only). See, join or change a gated channel they are not let into, or shut themselves out of one. See an address. | `each_privilege_grants_its_own_step_only`; `a_moderator_cannot_touch_admins_or_see_addresses`; `admin_steps_that_hand_out_power_ask_for_a_fresh_code`; `a_channel_editor_reaches_only_channels_it_may_see`; `a_channel_editor_cannot_switch_anonymity_off`; `account_bans_follow_the_account_and_roles_pass_address_bans`; l4f `roles_change_only_on_accounts_the_actor_covers`. |
| **Someone holding your Discord, Google or Facebook account** (1.8) | Sign in as far as the relay's question of what opens the account. Ask your other device for its vault key, three times and then once per ten minutes: you see the ask, and it needs you to compare a code and say yes. Claim an account linked to that provider that nobody has opened yet, which is then theirs. | Join a channel, read anything, or take your connection over without the vault: `AuthStep::ProviderSigned` never carries `slot.pass`, and only an identity signature gets past it. Replace an identity, even with your code. Unlink the last way in. | `a_hijacked_provider_account_gets_no_admission_and_takes_nothing_over`; `the_password_slot_never_goes_out_to_a_provider_sign_in`; `a_provider_and_a_code_cannot_replace_an_identity`; `asking_the_other_device_is_rate_limited`. |
| **The provider itself** (1.8) | Everything above, for anyone using it, and see when they sign in here. | Read or open anything of VoIPC's: it gets no token or key from it, and is never told your account name. | The relay is the OAuth client; `voipc_crypto::account` derives nothing from a provider. |
| **A relay, about provider sign-in** (1.8) | Say an account was never opened, to hide its vault and the pins in it, then seat substituted keys as new: a device that remembers the account refuses, a new device only warns. Use the provider's id for you, which it stores. Swap the key in a pairing: it has one guess at a six-digit code for each time you compare. | Send your app to a copy of the provider's page: only the providers' own addresses are opened (`provider_page_ok`). Learn the vault key from a pairing: it is wrapped to a key committed to before the other device's nonce. | `a_remembered_account_is_not_believed_unopened`; `only_a_providers_own_page_is_opened`; `a_swapped_key_is_caught`; `the_vault_key_goes_only_to_the_committed_key_and_only_on_a_yes`. |
| **A member outside a gate** | Learn a gated channel's name by trying to make one with the same name ("name taken"). | See it in the list or a count, join, preview or be invited to it; keep its kept messages after losing the group; be heard, post or share where they may only listen (the relay drops it, and their app says so). | `a_gate_hides_its_channel_and_lets_only_its_speakers_speak`; `a_gated_channels_log_keeps_only_who_passes`; `a_listen_only_member_is_not_heard`. |
| **Someone with the device's disk** | Read the desktop's `settings.json` (servers, names, relay ids) and `tofu_pins.json` (which servers were used), if they can read your user's files. Guess the history password offline (600,000 PBKDF2-SHA256 rounds a guess). In the browser, read localStorage (read positions, relay ids); with the browser profile and its live session, use the remembered device keys. | Open the history file without its password. Read the desktop's files as another user on the machine (folder 0700, files 0600 on Linux and Android). Copy the browser's wrapping key to another profile. | `crypto.rs` (archive v5); `config::write_atomic` (0600); `data_dir` (0700); `devices.ts` (non-extractable AES key). |
| **A hostile page from another site** | Nothing of VoIPC's storage. Open a session to a relay, as any client can: the TCP tunnel and WebTransport check no Origin, because opening one relay from another relay's page is a feature. It has none of your keys or passwords, so it is a session of its own, not yours. | Read the relay origin's IndexedDB or localStorage. | The browser's same-origin rule. |

What changed for 1.0: post-quantum sessions, the sender in the media AAD, pre-key
refill, rolled-back or missing vault items reported instead of reset, a known
account shown as a guest reported, cleared direct conversations kept cleared,
the relay-id check in the browser, and readership ending when you leave a text
channel.

What changed for 1.3: files. A message's destruction timer, or a cleared
conversation, does not reach the relay's copy of a file it carried. That copy
is ciphertext, and goes within `max_age_hours` (24 h by default) of its latest
upload (a member's app uploads it again when someone asks after it has gone),
or with the next restart. The blob's exact size shows; it is not padded (readers
accept padding inside the sealed body, so a later version can add it). A guest's
side of a direct conversation is that guest's connection: another guest who takes
the same name later is not in it, and is not asked for its files.

What changed for 1.4: pictures, and emotes. **No picture somebody else made reaches
the app's or the browser's own image decoder** (a crafted one there, as libwebp's
CVE-2023-4863 was, would run code in the app). Every chat picture, emote and sticker
is decoded by memory-safe Rust (`crates/voipc-media`: pure-Rust decoders that forbid
`unsafe`, under fixed budgets), and only a PNG it wrote is shown; a picture it will not
read is offered to save, never shown (`what_is_too_big_is_refused_before_anything_is_allocated_for_it`,
`a_damaged_picture_is_refused_at_every_length_and_never_panics`, the `media` fuzz target,
`image-sinks.test.ts`); an animation that runs past a budget after its first frame is read no
further and shown as that frame, with a note saying why
(`an_animation_over_a_budget_stands_as_its_first_frame_and_says_why`). A relay sets how much
of a moving picture its members' apps keep
(`[files] animation_side`, `animation_mb`), within bounds each app holds it to
(`FileLimits::animation`), so a relay cannot make one picture take more than 512 MiB. Video
and sound still play through the system's decoders, after
a click, where the person allows it: on by default except in the Linux desktop app, whose
web view runs outside any sandbox. Emotes are the server's own, kept readable on the
relay like its channel names; the relay never decodes them, and an admin or a hostile
relay can show members a picture, never make one run. A message binds the hash of the
emote its sender saw (128 bits of it since 1.5; 1.4's 80 left room for a planned
collision), so an emote changed later shows as its name, not as another picture
(`emote-rules.test.ts`). Every member's app fetches every emote, so fetches say
nothing about who used which.

The desktop keeps a one-time copy of a 1.0 history beside the new one
(`chat_history.bin.v5`, under the same password), so that 1.0 can be gone back to.
Destruction timers and a purge do not reach that copy; clearing or deleting the history
removes it (`the_copies_kept_for_an_older_voipc_go_with_the_history`).

Edits, deletes, reactions and pins (1.3) are end-to-end encrypted messages like any
other: the relay sees one more message in that conversation, and counts it as a post in
an announcement channel or under slow mode. Someone who joins a channel later and is
handed its history gets edits applied and deleted messages left out, but no reactions
and no pins.

Also in 1.3: a password reset proves the recovery key itself, through a reset key it
derives (`slot.reset`, kept by the relay). Before, the vault key that every remembered
device keeps was enough, so a remembered device, or one forgotten at a password change,
could set a new password on an account without two-factor codes and sign everyone else
out. An account made before 1.3 keeps that gap until its owner makes a new recovery key
([ACCOUNTS.md](ACCOUNTS.md)).

