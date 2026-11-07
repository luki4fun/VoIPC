//! A real `AccountSync` against the relay's real `log` functions: every device's frames go
//! where `accounts.rs` sends them, with nothing but the session in between, so what the two
//! ends agree on is what is tested. A hostile relay is a change to an answer on its way back.

use std::collections::{BTreeSet, VecDeque};

use l4f_accounts::model::NewUser;
use voipc_crypto::account::{SignedIn, Vault};
use voipc_crypto::envelope::{envelope, open_envelope};
use voipc_crypto::generate_identity_key_pair;
use voipc_crypto::log::{
    chain_epoch, epoch_parts, open_chain_entry, Bucket, Chain, LogKey, StaticKey,
};
use voipc_crypto::sync::{AccountSync, Event, LogMemory, Prefs, ITEM_LOGKEY};
use voipc_protocol::codec::{decode_client_msg, encode_client_msg, PROTOCOL_VERSION};
use voipc_protocol::messages::{
    AccountReply, AccountRequest, ChainAsk, ChainKeys, ClientMessage, LogEntry, LogKeyInfo,
};
use voipc_protocol::types::VaultBlob;

use super::*;

const RELAY: [u8; 16] = [7; 16];
const CONV: &str = "c:lounge";
const OTHER: &str = "c:other";

type Id = [u8; 16];
/// Sees every answer on its way to a device, may change it, and says whether it arrives.
type Tamper = Box<dyn FnMut(usize, &AccountRequest, &mut AccountReply) -> bool + Send>;

fn name_of(r: &AccountRequest) -> String {
    let s = format!("{r:?}");
    s.split([' ', '{', '(']).next().unwrap_or("").to_string()
}

fn id_of(n: u64) -> Id {
    let mut id = [0xAA; 16];
    id[8..].copy_from_slice(&n.to_be_bytes());
    id
}

/// One device of an account.
struct Device {
    id: Id,
    sync: AccountSync,
    out: VecDeque<ClientMessage>,
    online: bool,
    shares: bool,
    may: bool,
    texts: Vec<String>,
    seqs: Vec<i64>,
}

/// What happened, in order, across all the devices.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Line {
    Named {
        device: usize,
        accounts: Vec<Id>,
        history: bool,
    },
    Sent {
        device: usize,
        what: String,
    },
    Stored {
        device: usize,
        behind: bool,
    },
    NotKept {
        device: usize,
        reason: String,
    },
    Unopened {
        device: usize,
    },
    Clamped {
        device: usize,
        window: u32,
    },
    Warned {
        device: usize,
        account: Id,
    },
    Problem {
        device: usize,
        problem: &'static str,
    },
}

struct World {
    relay: Relay,
    file: std::path::PathBuf,
    next_id: u64,
    next_at: u64,
    devices: Vec<Device>,
    accounts: Vec<SignedIn>,
    log: Vec<Line>,
    puts: Vec<(usize, AccountRequest)>,
    appends: Vec<(usize, u32)>,
    tamper: Option<Tamper>,
    /// This device reads after every frame a writer puts, and goes first.
    reader: Option<usize>,
    /// With a `reader`: joiners still waiting after each frame.
    waiting_after: Vec<i64>,
}

impl Drop for World {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm", ".lock"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.file.display()));
        }
    }
}

impl World {
    async fn new() -> World {
        World::with(|_| {}).await
    }

    async fn with(change: impl FnOnce(&mut AccountsConfig)) -> World {
        let file =
            std::env::temp_dir().join(format!("voipc-kept-{:016x}.db", rand::random::<u64>()));
        let store = Store::connect(&format!("sqlite://{}?mode=rwc", file.display()))
            .await
            .unwrap();
        let mut cfg = AccountsConfig {
            mode: AccountsMode::Optional,
            kept_seats: 0,
            ..Default::default()
        };
        change(&mut cfg);
        let relay = Relay::open_with(&cfg, store, &[9u8; 32]).await.unwrap();
        World {
            relay,
            file,
            next_id: 1,
            next_at: 1_700_000_000_000,
            devices: Vec::new(),
            accounts: Vec::new(),
            log: Vec::new(),
            puts: Vec::new(),
            appends: Vec::new(),
            tamper: None,
            reader: None,
            waiting_after: Vec::new(),
        }
    }

    /// An account with its keys published, on one device with copies on. No seat yet.
    async fn person(&mut self) -> usize {
        let id = id_of(self.next_id);
        self.next_id += 1;
        let name = format!("person{}", self.next_id);
        let signed = self.account(id, &name).await;
        self.accounts.push(signed);
        self.device_of(self.accounts.len() - 1, LogMemory::default())
    }

    async fn account(&mut self, id: Id, name: &str) -> SignedIn {
        self.relay
            .store()
            .create_user(
                &NewUser {
                    id: AccountId(id),
                    username: name.to_string(),
                    display_name: name.to_string(),
                    email_pending: None,
                    password_hash: None,
                    created_at: 1,
                },
                None,
            )
            .await
            .unwrap();
        let identity = generate_identity_key_pair();
        let key = identity.public_key().serialize().to_vec();
        self.relay.set_identity(AccountId(id), &key).await.unwrap();
        let logkey = LogKey::generate();
        let out = log::publish(
            &self.relay,
            AccountId(id),
            &logkey.public(),
            &logkey.endorse(&identity),
        )
        .await
        .unwrap();
        assert!(matches!(out, AccountReply::LogKeyStored), "{out:?}");
        let vault = Vault::create(RELAY, name);
        let blobs = vec![VaultBlob {
            version: 1,
            ..vault.seal_item(ITEM_LOGKEY, 1, &logkey.to_bytes())
        }];
        SignedIn {
            relay_id: RELAY,
            name: name.to_string(),
            vault,
            identity,
            recovery: None,
            blobs,
        }
    }

    /// Another run of an account's app: what `memory` it kept, and nothing else.
    fn device_of(&mut self, account: usize, memory: LogMemory) -> usize {
        let signed = &self.accounts[account];
        let id = id_of(account as u64 + 1);
        let (mut sync, first) = AccountSync::start(signed, id, memory, false);
        sync.set_protocol(PROTOCOL_VERSION);
        let mut out: VecDeque<ClientMessage> = sync.pins_first().into_iter().collect();
        out.extend(first);
        out.extend(sync.set_prefs(Prefs {
            cloud: true,
            asked: true,
        }));
        self.devices.push(Device {
            id,
            sync,
            out,
            online: true,
            shares: false,
            may: false,
            texts: Vec::new(),
            seqs: Vec::new(),
        });
        self.devices.len() - 1
    }

    /// The account's app again, on what the relay holds of its vault now, as a sign-in has it.
    async fn sign_in_again(&mut self, account: usize, memory: LogMemory) -> usize {
        let id = id_of(account as u64 + 1);
        let held = self.relay.vault(AccountId(id)).await.unwrap();
        let signed = &mut self.accounts[account];
        signed.blobs.retain(|b| b.k == ITEM_LOGKEY);
        signed.blobs.extend(held);
        self.device_of(account, memory)
    }

    /// New pins out now, as a sign-out sends them, and everything that follows.
    async fn save_pins(&mut self, d: usize) {
        let out = self.devices[d].sync.flush_pins();
        self.devices[d].out.extend(out);
        self.pump().await;
    }

    /// People who sit in a channel with no app running: a seat and a key, the same key for
    /// them all, signed once, or a test of thousands is a test of signatures.
    async fn crowd(&mut self, conv: &str, n: usize) -> Vec<Id> {
        let identity = generate_identity_key_pair();
        let identity_key = identity.public_key().serialize().to_vec();
        let logkey = LogKey::generate();
        let (public, sig) = (logkey.public(), logkey.endorse(&identity));
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let id = id_of(self.next_id + 1_000_000);
            self.next_id += 1;
            let name = format!("crowd{}", self.next_id);
            self.relay
                .store()
                .create_user(
                    &NewUser {
                        id: AccountId(id),
                        username: name.clone(),
                        display_name: name,
                        email_pending: None,
                        password_hash: None,
                        created_at: 1,
                    },
                    None,
                )
                .await
                .unwrap();
            self.relay
                .set_identity(AccountId(id), &identity_key)
                .await
                .unwrap();
            db!(self.relay.store(), pool => {
                sqlx::query("INSERT INTO voipc_logkeys (account, logkey, sig, updated_at) VALUES ($1, $2, $3, 1)")
                    .bind(&id[..])
                    .bind(public.as_slice())
                    .bind(sig.as_slice())
                    .execute(pool)
                    .await
                    .unwrap();
            });
            let (joined, _) = log::join(&self.relay, AccountId(id), conv, true)
                .await
                .unwrap();
            assert!(matches!(joined, AccountReply::LogJoined { .. }));
            out.push(id);
        }
        out
    }

    fn deliver(&mut self, d: usize, reply: AccountReply) {
        if let AccountReply::ChainStored { behind, .. } = &reply {
            self.log.push(Line::Stored {
                device: d,
                behind: *behind,
            });
        }
        let Some((out, events)) = self.devices[d].sync.on_reply(&reply) else {
            return;
        };
        self.devices[d].out.extend(out);
        self.record(d, events);
    }

    fn record(&mut self, d: usize, events: Vec<Event>) {
        for e in events {
            match e {
                Event::ChannelMessage { envelope, seq, .. } => {
                    self.devices[d].texts.push(open_envelope(&envelope).text);
                    self.devices[d].seqs.push(seq);
                }
                Event::Readers {
                    accounts, history, ..
                } => self.log.push(Line::Named {
                    device: d,
                    accounts: accounts.into_iter().map(|(a, _)| a).collect(),
                    history,
                }),
                Event::NotKept { reason } => self.log.push(Line::NotKept { device: d, reason }),
                Event::Unopened { .. } => self.log.push(Line::Unopened { device: d }),
                Event::Clamped { window, .. } => self.log.push(Line::Clamped { device: d, window }),
                Event::IdentityChanged { account, .. } => {
                    self.log.push(Line::Warned { device: d, account })
                }
                Event::VaultProblem { problem, .. } => {
                    self.log.push(Line::Problem { device: d, problem })
                }
                _ => {}
            }
        }
    }

    async fn answer(
        &mut self,
        d: usize,
        req: &AccountRequest,
    ) -> (Vec<AccountReply>, Vec<(Id, AccountReply)>) {
        let me = AccountId(self.devices[d].id);
        let relay = &self.relay;
        let mut pushes = Vec::new();
        let mut then = Vec::new();
        let out = match req {
            AccountRequest::VaultPut { k, v, expect }
                if k == "item.pins" || k.starts_with("pins.") =>
            {
                relay.vault_put(me, k, v, *expect).await.unwrap()
            }
            AccountRequest::VaultPage { k } => relay.vault_page(me, k).await.unwrap(),
            AccountRequest::VaultPut { k, expect, .. } => AccountReply::VaultStored {
                k: k.clone(),
                version: *expect + 1,
            },
            AccountRequest::LogKeyPublish { logkey, sig } => {
                log::publish(relay, me, logkey, sig).await.unwrap()
            }
            AccountRequest::LogKeys { accounts } => log::keys(relay, accounts).await.unwrap(),
            AccountRequest::EpochPut { conv, epoch, wraps } => {
                let (out, told) = log::epoch_put(relay, me, conv, *epoch, wraps)
                    .await
                    .unwrap();
                pushes.extend(
                    told.into_iter()
                        .map(|r| (r, AccountReply::LogNews { conv: conv.clone() })),
                );
                out
            }
            AccountRequest::WrapsFetch { conv } => log::wraps(relay, me, conv).await.unwrap(),
            AccountRequest::LogAppend {
                conv,
                epoch,
                ct,
                ttl_secs,
            } => {
                self.appends.push((d, *epoch));
                log::append(relay, me, conv, *epoch, ct, *ttl_secs)
                    .await
                    .unwrap()
            }
            AccountRequest::LogFetch { conv, after } => {
                log::fetch(relay, me, conv, *after).await.unwrap()
            }
            AccountRequest::LogIndex => {
                let (convs, pending) = log::index(relay, me).await.unwrap();
                then.extend(pending);
                convs
            }
            AccountRequest::LogJoin { conv } => {
                let (out, owners) = log::join(relay, me, conv, true).await.unwrap();
                for o in owners {
                    pushes.push((
                        o,
                        AccountReply::LogPending {
                            conv: conv.clone(),
                            joiners: vec![me.0],
                        },
                    ));
                }
                out
            }
            AccountRequest::LogJoinMany { convs } => {
                let present = vec![true; convs.len()];
                let (out, told) = log::join_many(relay, me, convs, &present).await.unwrap();
                for (conv, owners) in told {
                    for o in owners {
                        pushes.push((
                            o,
                            AccountReply::LogPending {
                                conv: conv.clone(),
                                joiners: vec![me.0],
                            },
                        ));
                    }
                }
                out
            }
            AccountRequest::LogLeave { conv } => log::leave(relay, me, conv).await.unwrap(),
            AccountRequest::LogMembers { conv } => log::members_of(relay, me, conv).await.unwrap(),
            AccountRequest::LogPurge { conv } => {
                log::purge(relay, me, conv.as_deref()).await.unwrap()
            }
            AccountRequest::ChainPut {
                conv,
                epoch,
                self_wrap,
                step,
                link,
                wraps,
                buckets,
                seals,
                last,
            } => {
                let frame = log::ChainFrame {
                    epoch: *epoch,
                    self_wrap: self_wrap.clone(),
                    step: step.clone(),
                    link: link.clone(),
                    wraps: wraps.clone(),
                    buckets: buckets.clone(),
                    seals: seals.clone(),
                    last: *last,
                };
                let sharing = log::Sharing {
                    shares: self.devices[d].shares,
                    may: self.devices[d].may,
                };
                let (out, told) = log::chain_put(relay, me, conv, frame, sharing)
                    .await
                    .unwrap();
                pushes.extend(
                    told.into_iter()
                        .map(|r| (r, AccountReply::LogNews { conv: conv.clone() })),
                );
                out
            }
            AccountRequest::LogMemberIds { conv, after } => {
                log::member_ids(relay, me, conv, *after).await.unwrap()
            }
            AccountRequest::ChainFetch { conv, after } => {
                log::chain_fetch(relay, me, conv, *after).await.unwrap()
            }
            AccountRequest::WrapsPage { conv, asks } => {
                log::wraps_page(relay, me, conv, asks).await.unwrap()
            }
            AccountRequest::OwnChains { conv, before } => {
                log::own_chains(relay, me, conv, *before).await.unwrap()
            }
            AccountRequest::OwnBuckets { conv, after } => {
                log::own_buckets(relay, me, conv, *after).await.unwrap()
            }
            AccountRequest::BucketLists { conv, wanted } => {
                log::bucket_lists(relay, me, conv, wanted).await.unwrap()
            }
            AccountRequest::OwnChainRows { conv, chain, after } => {
                log::own_chain_rows(relay, me, conv, *chain, *after)
                    .await
                    .unwrap()
            }
            other => panic!("not one of the kept path's: {other:?}"),
        };
        let mut replies = then;
        replies.push(out);
        (replies, pushes)
    }

    /// Frames go and answers come back until nobody has anything to send.
    async fn pump(&mut self) {
        let mut rounds = 0;
        loop {
            rounds += 1;
            assert!(rounds < 2_000_000, "nobody stops asking");
            let has_out = |d: &usize| self.devices[*d].online && !self.devices[*d].out.is_empty();
            let Some(d) = self
                .reader
                .filter(has_out)
                .or_else(|| (0..self.devices.len()).find(has_out))
            else {
                return;
            };
            let Some(msg) = self.devices[d].out.pop_front() else {
                continue;
            };
            // As it goes on the wire: past the limit the relay ends the connection
            let bytes = encode_client_msg(&msg).expect("a frame the relay would take");
            let ClientMessage::Account(req) = decode_client_msg(&bytes[4..]).unwrap() else {
                continue;
            };
            let what = name_of(&req);
            self.log.push(Line::Sent { device: d, what });
            if matches!(req, AccountRequest::ChainPut { .. }) {
                self.puts.push((d, req.clone()));
            }
            let (replies, pushes) = self.answer(d, &req).await;
            for mut r in replies {
                let arrives = match self.tamper.as_mut() {
                    Some(t) => t(d, &req, &mut r),
                    None => true,
                };
                if arrives {
                    self.deliver(d, r);
                }
            }
            for (who, r) in pushes {
                let at: Vec<usize> = (0..self.devices.len())
                    .filter(|i| self.devices[*i].id == who && self.devices[*i].online)
                    .collect();
                for i in at {
                    self.deliver(i, r.clone());
                }
            }
            if let (AccountRequest::ChainPut { .. }, Some(r)) = (&req, self.reader) {
                self.waiting_after
                    .push(self.rows("SELECT COUNT(*) FROM voipc_pending").await);
                if r != d {
                    let s = self.devices[r].sync.enter(CONV);
                    self.devices[r].out.extend(s);
                }
            }
        }
    }

    /// Takes a seat, and reads.
    async fn join(&mut self, d: usize) {
        let s = self.devices[d].sync.enter(CONV);
        self.devices[d].out.extend(s);
        self.pump().await;
    }

    /// What it kept since last time.
    async fn read(&mut self, d: usize) {
        let s = self.devices[d].sync.enter(CONV);
        self.devices[d].out.extend(s);
        self.pump().await;
    }

    async fn post_in(&mut self, d: usize, conv: &str, text: &str) {
        self.next_at += 1;
        let env = envelope(&format!("m{}", self.next_at), text, None);
        let s = self.devices[d]
            .sync
            .send_channel(conv, env, self.next_at, None);
        self.devices[d].out.extend(s);
        self.pump().await;
    }

    async fn post(&mut self, d: usize, text: &str) {
        self.post_in(d, CONV, text).await;
    }

    /// It stops keeping the channel, and the relay takes it out; no wait to come back, unless
    /// a test is about that wait.
    async fn leave(&mut self, d: usize) {
        let s = self.devices[d].sync.leave(CONV, true);
        self.devices[d].out.extend(s);
        self.pump().await;
        db!(self.relay.store(), pool => {
            sqlx::query("DELETE FROM voipc_left").execute(pool).await.unwrap();
        });
    }

    fn texts(&self, d: usize) -> Vec<&str> {
        self.devices[d].texts.iter().map(String::as_str).collect()
    }

    fn id(&self, d: usize) -> Id {
        self.devices[d].id
    }

    fn sharing(&mut self, d: usize, on: bool) {
        self.devices[d].sync.set_share(on);
        self.devices[d].shares = on;
        self.devices[d].may = on;
    }

    fn named(&self, device: usize) -> Vec<Id> {
        self.log
            .iter()
            .filter_map(|l| match l {
                Line::Named {
                    device: d,
                    accounts,
                    ..
                } if *d == device => Some(accounts.clone()),
                _ => None,
            })
            .flatten()
            .collect()
    }

    /// The newest chain's number, and where it stands, by what its last post went on.
    fn last_epoch(&self, device: usize) -> (u32, u32) {
        let e = self
            .appends
            .iter()
            .rev()
            .find(|(d, _)| *d == device)
            .map(|(_, e)| *e)
            .unwrap_or(0);
        epoch_parts(e)
    }

    /// How many buckets the writer's newest chain is sealed to, as the relay has it.
    async fn live_buckets(&self, d: usize, conv: &str) -> Vec<(u64, u32, u32)> {
        let me = AccountId(self.devices[d].id);
        let mut all = Vec::new();
        let mut after = None;
        loop {
            let AccountReply::OwnBuckets { buckets, more, .. } =
                log::own_buckets(&self.relay, me, conv, after)
                    .await
                    .unwrap()
            else {
                panic!("not an answer");
            };
            after = buckets.last().map(|b| b.bucket);
            all.extend(
                buckets
                    .iter()
                    .filter(|b| b.sealed)
                    .map(|b| (b.bucket, b.version, b.seats)),
            );
            if !more {
                return all;
            }
        }
    }

    async fn rows(&self, sql: &str) -> i64 {
        raw(&self.relay, sql).await.unwrap()
    }
}

// ── What a first post and an arrival come to ─────────────────────────────

#[tokio::test]
async fn a_first_post_seats_everyone_and_they_read_it() {
    let mut w = World::new().await;
    let (alice, bob, cy) = (w.person().await, w.person().await, w.person().await);
    for d in [alice, bob, cy] {
        w.join(d).await;
    }
    w.post(alice, "one").await;
    assert_eq!(w.last_epoch(alice), (1, 0));
    w.read(bob).await;
    w.read(cy).await;
    assert_eq!(w.texts(bob), ["one"]);
    assert_eq!(w.texts(cy), ["one"]);
    assert_eq!(w.rows("SELECT COUNT(*) FROM voipc_wraps").await, 0);
    // Its author too, on another run of the app
    let again = w.device_of(alice, LogMemory::default());
    w.read(again).await;
    assert_eq!(w.texts(again), ["one"]);
    let mut named = w.named(alice);
    named.sort_unstable();
    let mut want = vec![w.id(bob), w.id(cy)];
    want.sort_unstable();
    assert_eq!(named, want, "everyone it reaches is named");
}

/// An arrival: a fresh step and one row, at the writer's next post. No new chain, and a
/// second post costs nothing more.
#[tokio::test]
async fn an_arrival_costs_one_wrap_and_one_step() {
    let mut w = World::new().await;
    let (alice, bob) = (w.person().await, w.person().await);
    w.join(alice).await;
    w.join(bob).await;
    w.post(alice, "before").await;
    let fred = w.person().await;
    w.join(fred).await;
    w.puts.clear();
    w.post(alice, "after").await;
    assert_eq!(w.last_epoch(alice), (1, 1));
    assert_eq!(w.puts.len(), 1);
    let AccountRequest::ChainPut {
        step,
        wraps,
        buckets,
        ..
    } = &w.puts[0].1
    else {
        unreachable!()
    };
    assert!(step.is_some());
    assert!(buckets.is_empty());
    assert_eq!(wraps.len(), 1);
    assert_eq!(wraps[0].recipient, w.id(fred));
    assert_eq!(wraps[0].index, 1);
    w.post(alice, "again").await;
    assert_eq!(w.puts.len(), 1, "no more keys for a post with nobody new");
    w.read(fred).await;
    assert_eq!(
        w.texts(fred),
        ["after", "again"],
        "from where they were given it"
    );
    w.read(bob).await;
    assert_eq!(w.texts(bob), ["before", "after", "again"]);
}

/// Given index 1, and handed what was written at index 0 by a relay that does not filter.
#[tokio::test]
async fn a_joiner_opens_nothing_below_their_index() {
    let mut w = World::new().await;
    let (alice, bob) = (w.person().await, w.person().await);
    w.join(alice).await;
    w.join(bob).await;
    w.post(alice, "before").await;
    let below = last_entry(&w, alice).await;
    let fred = w.person().await;
    w.join(fred).await;
    w.post(alice, "after").await;
    w.read(fred).await;
    assert_eq!(w.texts(fred), ["after"]);
    let (_, events) = w.devices[fred]
        .sync
        .on_reply(&page(CONV, vec![below]))
        .unwrap();
    assert!(!events
        .iter()
        .any(|e| matches!(e, Event::ChannelMessage { .. })));
}

#[tokio::test]
async fn every_reader_is_named_before_their_step_goes() {
    let mut w = World::new().await;
    let alice = w.person().await;
    w.join(alice).await;
    w.post(alice, "alone").await;
    let fred = w.person().await;
    w.join(fred).await;
    w.post(alice, "with fred").await;
    let fred_id = w.id(fred);
    let named = w
        .log
        .iter()
        .position(|l| matches!(l, Line::Named { device, accounts, .. } if *device == alice && accounts.contains(&fred_id)))
        .expect("named");
    let last_put = w
        .log
        .iter()
        .rposition(
            |l| matches!(l, Line::Sent { device, what } if *device == alice && what == "ChainPut"),
        )
        .unwrap();
    assert!(named < last_put, "the name comes before the row");
}

// ── Leaving ──────────────────────────────────────────────────────────────

/// The attack's scenario with no hostile relay: holds a state, leaves, and every state from
/// the writer's next post on is under a chain with no path from anything they hold. Their
/// real keys are tried on its rows in `a_leavers_own_keys_open_nothing_of_the_next_chain`.
#[tokio::test]
async fn a_leaver_cannot_open_the_next_chain() {
    let mut w = World::new().await;
    let (alice, bob, cy) = (w.person().await, w.person().await, w.person().await);
    for d in [alice, bob, cy] {
        w.join(d).await;
    }
    w.post(alice, "while here").await;
    w.read(bob).await;
    w.leave(bob).await;
    w.post(alice, "after").await;
    assert_eq!(w.last_epoch(alice).0, 2, "a new chain");
    assert_eq!(w.live_buckets(alice, CONV).await[0].1, 1, "a new version");
    w.read(cy).await;
    assert_eq!(w.texts(cy), ["while here", "after"]);
}

/// The newest entry a writer filed.
async fn last_entry(w: &World, d: usize) -> LogEntry {
    let AccountReply::ChainPage { entries, .. } =
        log::chain_fetch(&w.relay, AccountId(w.devices[d].id), CONV, -1)
            .await
            .unwrap()
    else {
        panic!("a page");
    };
    entries.last().cloned().expect("an entry")
}

fn page(conv: &str, entries: Vec<LogEntry>) -> AccountReply {
    AccountReply::ChainPage {
        conv: conv.to_string(),
        upto: entries.last().map_or(0, |e| e.seq),
        entries,
        more: false,
        owed: Vec::new(),
        skipped: 0,
        floor: 0,
        window: 10_000,
    }
}

/// A rejoiner under a writer with sharing off gets a fresh step of today's chain: nothing
/// written while they were gone, whatever the relay hands them.
#[tokio::test]
async fn a_share_off_rejoiner_opens_nothing_from_while_they_were_gone() {
    let mut w = World::new().await;
    let (alice, bob, cy) = (w.person().await, w.person().await, w.person().await);
    for d in [alice, bob, cy] {
        w.join(d).await;
    }
    w.post(alice, "before").await;
    w.read(bob).await;
    w.leave(bob).await;
    w.post(alice, "while gone").await;
    let gap = last_entry(&w, alice).await;
    assert_eq!(epoch_parts(gap.epoch), (2, 0));
    w.join(bob).await;
    w.post(alice, "back").await;
    assert_eq!(w.last_epoch(alice), (2, 1));
    w.read(bob).await;
    assert_eq!(w.texts(bob), ["before", "back"]);
    let bob_sync = &mut w.devices[bob].sync;
    let (_, events) = bob_sync.on_reply(&page(CONV, vec![gap])).unwrap();
    assert!(!events
        .iter()
        .any(|e| matches!(e, Event::ChannelMessage { .. })));
    assert_eq!(w.texts(bob), ["before", "back"]);
}

/// Publish a new key, then leave: the row stays, dead, and it still says they held a state.
#[tokio::test]
async fn a_new_log_key_and_a_leave_still_end_the_chain() {
    let mut w = World::new().await;
    let (alice, mallory, cy) = (w.person().await, w.person().await, w.person().await);
    for d in [alice, mallory, cy] {
        w.join(d).await;
    }
    w.post(alice, "with mallory").await;
    w.read(mallory).await;
    let id = AccountId(w.id(mallory));
    let identity = w.accounts[mallory].identity;
    let new_key = LogKey::generate();
    db!(w.relay.store(), pool => {
        // Past the minute a key has to stand
        sqlx::query("UPDATE voipc_logkeys SET updated_at = 0").execute(pool).await.unwrap();
    });
    let out = log::publish(&w.relay, id, &new_key.public(), &new_key.endorse(&identity))
        .await
        .unwrap();
    assert!(matches!(out, AccountReply::LogKeyStored), "{out:?}");
    w.leave(mallory).await;
    w.post(alice, "without").await;
    assert_eq!(
        w.last_epoch(alice).0,
        2,
        "a new chain, with no row of theirs on it"
    );
    w.read(cy).await;
    assert_eq!(w.texts(cy), ["with mallory", "without"]);
    let holder = w.devices[mallory].id;
    let AccountReply::WrapsPage { keys, .. } = log::wraps_page(
        &w.relay,
        AccountId(w.devices[cy].id),
        CONV,
        &[ChainAsk {
            owner: w.devices[alice].id,
            chain: 2,
            from: None,
        }],
    )
    .await
    .unwrap() else {
        panic!("keys");
    };
    assert!(keys[0].seal.is_some());
    assert_ne!(holder, w.devices[cy].id);
    let n = w
        .rows(&format!(
            "SELECT COUNT(*) FROM voipc_seats s JOIN voipc_seals x ON x.bucket = s.bucket AND x.version = s.version
              WHERE s.dead = FALSE AND lower(hex(s.recipient)) = '{}'",
            voipc_protocol::conv::hex(&holder)
        ))
        .await;
    assert_eq!(n, 0, "no live row of theirs is under any seal");
}

/// Stays seated with a new key: named again, and the row goes to the new key, not the old
/// one the writer's session still holds.
#[tokio::test]
async fn a_new_keys_missing_wraps_to_the_new_key() {
    let mut w = World::new().await;
    let (alice, mallory) = (w.person().await, w.person().await);
    w.join(alice).await;
    w.join(mallory).await;
    w.post(alice, "one").await;
    let identity = w.accounts[mallory].identity;
    let new_key = LogKey::generate();
    db!(w.relay.store(), pool => {
        sqlx::query("UPDATE voipc_logkeys SET updated_at = 0").execute(pool).await.unwrap();
    });
    log::publish(
        &w.relay,
        AccountId(w.id(mallory)),
        &new_key.public(),
        &new_key.endorse(&identity),
    )
    .await
    .unwrap();
    // A new run of their app, with the new key
    w.accounts[mallory].blobs = vec![VaultBlob {
        version: 1,
        ..w.accounts[mallory]
            .vault
            .seal_item(ITEM_LOGKEY, 1, &new_key.to_bytes())
    }];
    let phone = w.device_of(mallory, LogMemory::default());
    w.post(alice, "two").await;
    assert_eq!(w.last_epoch(alice), (1, 1), "a step");
    w.read(phone).await;
    assert_eq!(w.texts(phone), ["two"]);
}

/// Told someone is gone, a device ends its chain at its next post with the relay saying
/// nothing of it, and asks no permission to.
#[tokio::test]
async fn a_member_gone_ends_the_chain_at_the_next_post() {
    let mut w = World::new().await;
    let (alice, bob, cy) = (w.person().await, w.person().await, w.person().await);
    for d in [alice, bob, cy] {
        w.join(d).await;
    }
    w.post(alice, "one").await;
    // The relay keeps them as a member, and says nothing to the writer's post
    let gone = w.id(bob);
    w.devices[alice].sync.member_gone(CONV, Some(gone));
    w.post(alice, "two").await;
    assert_eq!(w.last_epoch(alice).0, 2, "a new chain");
    let buckets = w.live_buckets(alice, CONV).await;
    assert_eq!(buckets[0].1, 1, "rotated, with them out of it");
    // Back again with a row given at the next post, under their name
    w.post(alice, "three").await;
    assert_eq!(w.last_epoch(alice), (2, 1));
    let named: Vec<Id> = w.named(alice);
    assert_eq!(
        named.iter().filter(|a| **a == gone).count(),
        2,
        "named twice: at first, and again now"
    );
    w.read(cy).await;
    assert_eq!(w.texts(cy), ["one", "two", "three"]);
}

/// The attack's (c): a writer leaves and comes back. Its next post starts a chain, and it
/// names its readers again, as it said it would.
#[tokio::test]
async fn a_writers_own_return_names_its_readers_again() {
    let mut w = World::new().await;
    let (alice, bob) = (w.person().await, w.person().await);
    w.join(alice).await;
    w.join(bob).await;
    w.post(alice, "one").await;
    let bob_id = w.id(bob);
    assert_eq!(w.named(alice), [bob_id]);
    w.leave(alice).await;
    w.join(alice).await;
    w.post(alice, "two").await;
    assert_eq!(w.last_epoch(alice).0, 2);
    assert_eq!(w.named(alice), [bob_id, bob_id]);
    w.read(bob).await;
    assert_eq!(w.texts(bob), ["one", "two"]);
}

/// The control for the whole design: a relay shows a writer's device an old top and seats a
/// listener. The step the device makes is a fork, with its own randomness, and what was
/// written at that index on the true chain does not open under it. On a plain forward chain
/// it would, and all that followed.
#[tokio::test]
async fn a_writer_rolled_back_gives_a_listener_nothing_written_since() {
    let mut w = World::new().await;
    let (alice, bob, listener) = (w.person().await, w.person().await, w.person().await);
    w.join(alice).await;
    w.join(bob).await;
    w.post(alice, "at the start").await;
    let me = AccountId(w.id(alice));
    let rolled_back = log::own_chains(&w.relay, me, CONV, None).await.unwrap();
    let fred = w.person().await;
    w.join(fred).await;
    w.post(alice, "written since").await;
    assert_eq!(w.last_epoch(alice), (1, 1));
    let since = last_entry(&w, alice).await;
    // Another run of the writer's app, told the chain stands at 0, and of someone new
    w.join(listener).await;
    let who = w.id(listener);
    w.devices[alice].online = false;
    let again = w.device_of(alice, LogMemory::default());
    w.tamper = Some(Box::new(move |_, req, reply| {
        match req {
            AccountRequest::OwnChains { .. } => *reply = rolled_back.clone(),
            AccountRequest::LogAppend { conv, .. } => {
                *reply = AccountReply::ChainRekey {
                    conv: conv.clone(),
                    new_chain: false,
                    missing: vec![who],
                    gone: Vec::new(),
                }
            }
            _ => {}
        }
        true
    }));
    w.puts.clear();
    w.post(again, "on the fork").await;
    w.tamper = None;
    let AccountRequest::ChainPut { epoch, wraps, .. } = &w.puts[0].1 else {
        panic!("a step")
    };
    assert_eq!(
        epoch_parts(*epoch),
        (1, 1),
        "the same index as the true chain"
    );
    assert!(w.named(again).contains(&who), "named first");
    let row = wraps[0].wrapped.clone();
    // Now the listener, on a device with no cursor, is handed that row and the true entry
    // at that index
    let viewer = w.device_of(listener, LogMemory::default());
    let owner = w.id(alice);
    let keys = AccountReply::WrapsPage {
        conv: CONV.to_string(),
        keys: vec![ChainKeys {
            owner,
            chain: 1,
            self_wrap: None,
            direct: Some((1, row)),
            seal: None,
            seat: None,
            down: Vec::new(),
            link: None,
            steps: Vec::new(),
        }],
        served: 1,
    };
    let s = w.devices[viewer].sync.enter(CONV);
    w.devices[viewer].out.extend(s);
    w.tamper = Some(Box::new(move |_, req, reply| {
        match req {
            AccountRequest::WrapsPage { .. } => *reply = keys.clone(),
            AccountRequest::ChainFetch { .. } => *reply = page(CONV, vec![since.clone()]),
            _ => {}
        }
        true
    }));
    w.pump().await;
    w.tamper = None;
    assert!(w.texts(viewer).is_empty(), "{:?}", w.texts(viewer));
}

// ── A seal must name ─────────────────────────────────────────────────────

/// Told someone it reached is gone: no list counts as named any more, here or on this
/// device's next run, so each is named again before a seal.
#[tokio::test]
async fn a_member_gone_clears_what_this_device_has_named() {
    let mut w = World::new().await;
    let (alice, bob, cy) = (w.person().await, w.person().await, w.person().await);
    for d in [alice, bob, cy] {
        w.join(d).await;
    }
    w.post(alice, "one").await;
    assert_eq!(w.devices[alice].sync.memory().named[CONV].len(), 1);
    let gone = w.id(bob);
    w.devices[alice].sync.member_gone(CONV, Some(gone));
    assert!(!w.devices[alice].sync.memory().named.contains_key(CONV));
    w.post(alice, "two").await;
    assert_eq!(w.last_epoch(alice).0, 2);
    assert_eq!(w.devices[alice].sync.memory().named[CONV].len(), 1);
}

/// The attack's (a): another device of the writer seals to a bucket whose people it never
/// named. It reads the list first, and names them, before anything is sealed to them.
#[tokio::test]
async fn a_seal_names_whoever_this_device_has_not_named() {
    let mut w = World::new().await;
    let (desktop, listener, zed) = (w.person().await, w.person().await, w.person().await);
    w.join(desktop).await;
    w.join(zed).await;
    w.post(desktop, "one").await;
    w.join(listener).await;
    w.post(desktop, "two").await; // named on the desktop, a step
    w.leave(zed).await;
    w.post(desktop, "three").await; // a small bucket for the listener
    assert_eq!(w.live_buckets(desktop, CONV).await.len(), 1);
    let (who, phone) = (w.id(listener), w.device_of(desktop, LogMemory::default()));
    w.devices[desktop].online = false;
    let zed2 = w.person().await;
    w.join(zed2).await;
    w.post(phone, "four").await; // a step; nothing sealed yet
    w.leave(zed2).await;
    w.post(phone, "five").await;
    let named = w
        .log
        .iter()
        .position(|l| matches!(l, Line::Named { device, accounts, .. } if *device == phone && accounts.contains(&who)))
        .expect("the phone names them");
    let sealed = w
        .log
        .iter()
        .rposition(
            |l| matches!(l, Line::Sent { device, what } if *device == phone && what == "ChainPut"),
        )
        .unwrap();
    assert!(named < sealed, "named before the seal goes");
    assert!(w.log.iter().any(
        |l| matches!(l, Line::Sent { device, what } if *device == phone && what == "BucketLists")
    ));
}

/// Across a run of the app that kept its memory, a list named once is not read again.
#[tokio::test]
async fn a_named_list_is_not_read_again() {
    let mut w = World::new().await;
    let (alice, bob, cy, dan) = (
        w.person().await,
        w.person().await,
        w.person().await,
        w.person().await,
    );
    for d in [alice, bob, cy, dan] {
        w.join(d).await;
    }
    w.post(alice, "one").await;
    let memory = w.devices[alice].sync.memory();
    assert_eq!(memory.named[CONV].len(), 1);
    w.devices[alice].online = false;
    let again = w.device_of(alice, memory);
    w.leave(dan).await;
    w.post(again, "two").await;
    let lists = w
        .log
        .iter()
        .filter(|l| matches!(l, Line::Sent { device, what } if *device == again && what == "BucketLists"))
        .count();
    assert_eq!(lists, 1, "only the one someone left, to rotate it");
    assert!(
        !w.named(again).contains(&w.id(bob)),
        "and nobody new is named"
    );
}

/// The attack's (b): someone removed, and rotated out. The relay rolls back to the list
/// holding them and claims them a member. Nothing else looks new: the digest is what says so.
#[tokio::test]
async fn a_removed_member_back_on_a_rolled_back_list_is_named() {
    let mut w = World::new().await;
    let (alice, fred, cy) = (w.person().await, w.person().await, w.person().await);
    for d in [alice, fred, cy] {
        w.join(d).await;
    }
    w.post(alice, "one").await;
    // What the relay keeps to show later
    let me = AccountId(w.id(alice));
    let old_buckets = log::own_buckets(&w.relay, me, CONV, None).await.unwrap();
    let AccountReply::OwnBuckets { buckets, .. } = &old_buckets else {
        panic!()
    };
    let (id, version) = (buckets[0].bucket, buckets[0].version);
    let old_list = log::bucket_lists(&w.relay, me, CONV, &[(id, version)])
        .await
        .unwrap();
    let old_chains = log::own_chains(&w.relay, me, CONV, None).await.unwrap();
    let gone = w.id(fred);
    w.leave(fred).await;
    w.post(alice, "two").await;
    assert_eq!(w.live_buckets(alice, CONV).await[0].1, version + 1);
    let named_then = w.named(alice).iter().filter(|a| **a == gone).count();
    // Rolled back, and asked for a new chain: the old list, with them on it, reads as fine
    let memory = w.devices[alice].sync.memory();
    assert!(!memory.readers[CONV].contains(&gone), "told they left");
    w.devices[alice].online = false;
    let again = w.device_of(alice, memory);
    w.tamper = Some(Box::new(move |_, req, reply| {
        match req {
            AccountRequest::OwnBuckets { .. } => *reply = old_buckets.clone(),
            AccountRequest::BucketLists { .. } => *reply = old_list.clone(),
            AccountRequest::OwnChains { .. } => *reply = old_chains.clone(),
            AccountRequest::LogAppend { conv, .. } => {
                *reply = AccountReply::ChainRekey {
                    conv: conv.clone(),
                    new_chain: true,
                    missing: Vec::new(),
                    gone: Vec::new(),
                }
            }
            _ => {}
        }
        true
    }));
    w.post(again, "three").await;
    w.tamper = None;
    assert!(
        w.named(again).contains(&gone)
            && w.named(alice).iter().filter(|a| **a == gone).count() == named_then,
        "named on the device that seals to them"
    );
}

/// The attack's finding 2: the relay carries a bucket of one channel into another, with its
/// people. The context names the channel, so its own row does not open, and nobody on that
/// list reads here unnamed.
#[tokio::test]
async fn a_bucket_moved_to_another_channel_does_not_open_for_its_writer() {
    let mut w = World::new().await;
    let (alice, mallory, cy) = (w.person().await, w.person().await, w.person().await);
    w.join(alice).await;
    w.join(mallory).await;
    w.post(alice, "in the open").await;
    let me = AccountId(w.id(alice));
    let moved = log::own_buckets(&w.relay, me, CONV, None).await.unwrap();
    let AccountReply::OwnBuckets { buckets, .. } = &moved else {
        panic!()
    };
    let moved_id = buckets[0].bucket;
    // A chain there so a device goes on from it
    for d in [alice, cy] {
        let s = w.devices[d].sync.enter(OTHER);
        w.devices[d].out.extend(s);
    }
    w.pump().await;
    w.post_in(alice, OTHER, "first there").await;
    let fresh = w.device_of(alice, LogMemory::default());
    w.devices[alice].online = false;
    let dan = w.person().await;
    let s = w.devices[dan].sync.enter(OTHER);
    w.devices[dan].out.extend(s);
    w.pump().await;
    let moved_list = log::bucket_lists(&w.relay, me, CONV, &[(moved_id, 0)])
        .await
        .unwrap();
    let served = moved.clone();
    w.tamper = Some(Box::new(move |_, req, reply| {
        match req {
            AccountRequest::OwnBuckets { conv, .. } if conv == OTHER => {
                let AccountReply::OwnBuckets { buckets, .. } = &served else {
                    unreachable!()
                };
                *reply = AccountReply::OwnBuckets {
                    conv: conv.clone(),
                    buckets: buckets.clone(),
                    more: false,
                };
            }
            AccountRequest::BucketLists { conv, .. } if conv == OTHER => {
                *reply = moved_list.clone();
            }
            AccountRequest::LogAppend { conv, .. } if conv == OTHER => {
                *reply = AccountReply::ChainRekey {
                    conv: conv.clone(),
                    new_chain: true,
                    missing: Vec::new(),
                    gone: Vec::new(),
                };
            }
            _ => {}
        }
        true
    }));
    w.puts.clear();
    w.post_in(fresh, OTHER, "second there").await;
    w.tamper = None;
    let frames: Vec<&AccountRequest> = w
        .puts
        .iter()
        .filter(|(d, _)| *d == fresh)
        .map(|(_, r)| r)
        .collect();
    assert!(!frames.is_empty());
    for f in frames {
        let AccountRequest::ChainPut { seals, buckets, .. } = f else {
            unreachable!()
        };
        assert!(
            seals.iter().all(|s| s.bucket != moved_id),
            "nothing sealed to it"
        );
        for b in buckets {
            assert!(
                b.seats.iter().all(|s| s.recipient != w.devices[mallory].id),
                "and the list's people get no row here"
            );
        }
    }
    assert!(!w.named(fresh).contains(&w.id(mallory)));
    // And those who are members here, whose bucket that claimed to be, get one of their own
    let cy_id = w.id(cy);
    assert!(
        w.puts.iter().any(
            |(_, f)| matches!(f, AccountRequest::ChainPut { buckets, .. }
            if buckets.iter().any(|b| b.seats.iter().any(|s| s.recipient == cy_id)))
        ),
        "seated afresh"
    );
    assert!(w.named(fresh).contains(&cy_id), "and named");
}

/// A list that does not come, or is not the one its own row names, is no list: no seal, and
/// its people go in a new bucket, each named.
#[tokio::test]
async fn no_list_means_no_seal() {
    for forged in [false, true] {
        let mut w = World::new().await;
        let (alice, bob, cy) = (w.person().await, w.person().await, w.person().await);
        for d in [alice, bob, cy] {
            w.join(d).await;
        }
        w.post(alice, "one").await;
        let old = w.live_buckets(alice, CONV).await[0].0;
        w.devices[alice].online = false;
        let again = w.device_of(alice, LogMemory::default());
        w.tamper = Some(Box::new(move |_, req, reply| {
            match req {
                AccountRequest::BucketLists { .. } => {
                    if let AccountReply::BucketLists { lists, .. } = reply {
                        if forged {
                            lists[0].2[20] ^= 1;
                        } else {
                            lists.clear();
                        }
                    }
                }
                AccountRequest::LogAppend { conv, .. } => {
                    *reply = AccountReply::ChainRekey {
                        conv: conv.clone(),
                        new_chain: true,
                        missing: Vec::new(),
                        gone: Vec::new(),
                    };
                }
                _ => {}
            }
            true
        }));
        w.puts.clear();
        w.post(again, "two").await;
        w.tamper = None;
        let (mut sealed, mut seated) = (Vec::new(), Vec::new());
        for (_, f) in &w.puts {
            let AccountRequest::ChainPut { seals, buckets, .. } = f else {
                unreachable!()
            };
            sealed.extend(seals.iter().map(|s| s.bucket));
            seated.extend(
                buckets
                    .iter()
                    .flat_map(|b| b.seats.iter().map(|s| s.recipient)),
            );
        }
        assert!(!sealed.is_empty() && !sealed.contains(&old), "{sealed:?}");
        assert!(seated.contains(&w.id(bob)) && seated.contains(&w.id(cy)));
        assert!(w.named(again).contains(&w.id(bob)) && w.named(again).contains(&w.id(cy)));
    }
}

/// Only what the newest chain is sealed to is gone on with: a bucket merged away or emptied
/// stays on the relay's list until its seals go, and nothing new is sealed to it.
#[tokio::test]
async fn a_device_seals_only_to_what_the_newest_chain_is_sealed_to() {
    let mut w = World::new().await;
    let (alice, bob, cy, dan) = (
        w.person().await,
        w.person().await,
        w.person().await,
        w.person().await,
    );
    w.join(alice).await;
    w.join(bob).await;
    w.post(alice, "one").await;
    let emptied = w.live_buckets(alice, CONV).await[0].0;
    w.join(cy).await;
    w.join(dan).await;
    w.post(alice, "two").await;
    w.leave(bob).await;
    w.post(alice, "three").await;
    assert!(!w
        .live_buckets(alice, CONV)
        .await
        .iter()
        .any(|b| b.0 == emptied));
    // Another device, with nothing remembered, and the next chain
    w.devices[alice].online = false;
    let again = w.device_of(alice, LogMemory::default());
    w.leave(dan).await;
    w.puts.clear();
    w.post(again, "four").await;
    for (_, f) in &w.puts {
        let AccountRequest::ChainPut { seals, .. } = f else {
            unreachable!()
        };
        assert!(seals.iter().all(|s| s.bucket != emptied), "{seals:?}");
    }
    w.read(cy).await;
    assert_eq!(w.texts(cy), ["two", "three", "four"]);
}

// ── Crashes and stale devices ────────────────────────────────────────────

/// A mass leave takes several frames. The first lands, with rotations; the app dies. The old
/// chain is still in charge, and it must still end: nobody's post goes on it, and the next
/// device starts over from the versions there are.
#[tokio::test]
async fn a_crash_between_rotation_and_chain_still_ends_the_chain() {
    let mut w = World::new().await;
    let (alice, reader) = (w.person().await, w.person().await);
    w.join(alice).await;
    w.join(reader).await;
    let crowd = w.crowd(CONV, 62 * 7).await;
    w.post(alice, "one").await;
    let frames = w.puts.len();
    assert!(frames > 1, "a first post over several frames");
    let before = w.live_buckets(alice, CONV).await;
    assert!(before.len() >= 7);
    // One out of each bucket: every one of them rotates, so the next chain takes frames
    let me = AccountId(w.id(alice));
    let mut left = Vec::new();
    let seats: Vec<(Vec<u8>, i64)> = db!(w.relay.store(), pool => {
        sqlx::query_as("SELECT recipient, bucket FROM voipc_seats").fetch_all(pool).await.unwrap()
    });
    let reader_id = w.id(reader);
    let mut seen = BTreeSet::new();
    for (who, bucket) in seats {
        let who: Id = who.try_into().unwrap();
        if who != me.0 && who != reader_id && crowd.contains(&who) && seen.insert(bucket) {
            left.push(who);
        }
    }
    assert_eq!(left.len(), before.len());
    for who in &left {
        log::remove(w.relay.store(), CONV, who).await.unwrap();
    }
    // The first frame lands and the app is gone
    let mut seen_puts = 0;
    w.tamper = Some(Box::new(move |_, req, _| {
        if matches!(req, AccountRequest::ChainPut { .. }) {
            seen_puts += 1;
            return seen_puts < 1;
        }
        true
    }));
    w.post(alice, "two").await;
    w.tamper = None;
    w.devices[alice].online = false;
    // A rotation landed, and the chain did not: at most the newest is still chain 1
    let rotated = w.live_buckets(alice, CONV).await;
    assert!(rotated.iter().any(|(_, v, _)| *v == 1), "{rotated:?}");
    assert!(rotated.iter().any(|(_, v, _)| *v == 0), "{rotated:?}");
    // The old chain takes no post, on either count
    let phone = w.device_of(alice, LogMemory::default());
    w.post(phone, "three").await;
    let (chain, _) = w.last_epoch(phone);
    assert!(chain >= 3, "over the chain that never finished: {chain}");
    assert!(
        !w.log.iter().any(|l| matches!(l, Line::NotKept { .. })),
        "{:?}",
        w.log
    );
    w.read(reader).await;
    assert_eq!(w.texts(reader).last(), Some(&"three"));
    assert!(w.texts(reader).contains(&"one"));
    // The chain that never finished goes with the sweep. What the next one went on from, the
    // versions it made, are people's way in now, and stay.
    db!(w.relay.store(), pool => {
        sqlx::query("UPDATE voipc_chains SET created_at = 0 WHERE done = FALSE").execute(pool).await.unwrap();
        sqlx::query("UPDATE voipc_bucket_lists SET created_at = 0").execute(pool).await.unwrap();
    });
    log::sweep(&w.relay).await.unwrap();
    assert_eq!(
        w.rows("SELECT COUNT(*) FROM voipc_chains WHERE done = FALSE")
            .await,
        0
    );
    let fresh = w.device_of(reader, LogMemory::default());
    w.read(fresh).await;
    assert_eq!(
        w.texts(fresh).last(),
        Some(&"three"),
        "{:?}",
        w.texts(fresh)
    );
    assert!(w.texts(fresh).contains(&"one"), "{:?}", w.texts(fresh));
}

/// A device read its buckets back a moment before its other device rotated one. What it
/// seals to is no version's newest now: the relay says behind, and it reads back and goes on
/// from what is there.
#[tokio::test]
async fn a_seal_to_an_old_version_is_behind() {
    let mut w = World::new().await;
    let (desktop, cy) = (w.person().await, w.person().await);
    w.join(desktop).await;
    w.join(cy).await;
    w.crowd(CONV, 124).await;
    w.post(desktop, "one").await;
    let me = AccountId(w.id(desktop));
    let stale = log::own_buckets(&w.relay, me, CONV, None).await.unwrap();
    // One out of a bucket of the phone's doing, and later one out of another
    let seats: Vec<(Vec<u8>, i64)> = db!(w.relay.store(), pool => {
        sqlx::query_as("SELECT recipient, bucket FROM voipc_seats WHERE version = 0").fetch_all(pool).await.unwrap()
    });
    let cy_id = w.id(cy);
    let other: Vec<(Id, i64)> = seats
        .into_iter()
        .map(|(who, b)| (<Id>::try_from(who).unwrap(), b))
        .filter(|(who, _)| *who != me.0 && *who != cy_id)
        .collect();
    let (first, in_first) = other[0];
    let second = other.iter().find(|(_, b)| *b != in_first).unwrap().0;
    let phone = w.device_of(desktop, LogMemory::default());
    log::remove(w.relay.store(), CONV, &first).await.unwrap();
    w.post(phone, "two").await;
    assert!(w
        .live_buckets(phone, CONV)
        .await
        .iter()
        .any(|(_, v, _)| *v == 1));
    log::remove(w.relay.store(), CONV, &second).await.unwrap();
    w.log.clear();
    let mut once = Some(stale);
    w.tamper = Some(Box::new(move |_, req, reply| {
        if matches!(req, AccountRequest::OwnBuckets { .. }) {
            if let Some(stale) = once.take() {
                *reply = stale;
            }
        }
        true
    }));
    let fresh = w.device_of(desktop, w.devices[desktop].sync.memory());
    w.post(fresh, "three").await;
    w.tamper = None;
    assert!(
        w.log
            .iter()
            .any(|l| matches!(l, Line::Stored { device, behind: true } if *device == fresh)),
        "{:?}",
        w.log
    );
    assert!(
        !w.log.iter().any(|l| matches!(l, Line::NotKept { .. })),
        "{:?}",
        w.log
    );
    w.read(cy).await;
    assert_eq!(w.texts(cy), ["one", "two", "three"]);
}

#[tokio::test]
async fn a_stale_device_rereads_and_steps_from_the_top() {
    let mut w = World::new().await;
    let (desktop, bob) = (w.person().await, w.person().await);
    w.join(desktop).await;
    w.join(bob).await;
    w.post(desktop, "one").await;
    let phone = w.device_of(desktop, LogMemory::default());
    let fred = w.person().await;
    w.join(fred).await;
    w.post(phone, "two").await; // a step on the phone, at (1, 1)
    assert_eq!(w.last_epoch(phone), (1, 1));
    w.post(desktop, "three").await; // the desktop thinks (1, 0)
    assert_eq!(
        w.last_epoch(desktop),
        (1, 1),
        "read back and went on at the top"
    );
    w.read(fred).await;
    assert_eq!(w.texts(fred), ["two", "three"]);
}

/// Its next step is fresh, so no per-device chain, and what it writes opens for the others.
#[tokio::test]
async fn a_new_device_goes_on_and_its_next_step_is_fresh() {
    let mut w = World::new().await;
    let (desktop, bob) = (w.person().await, w.person().await);
    w.join(desktop).await;
    w.join(bob).await;
    w.post(desktop, "one").await;
    let fred = w.person().await;
    w.join(fred).await;
    w.post(desktop, "two").await;
    let phone = w.device_of(desktop, LogMemory::default());
    w.post(phone, "three").await;
    assert_eq!(
        w.last_epoch(phone),
        (1, 1),
        "the same chain, at the same top"
    );
    w.read(bob).await;
    assert_eq!(w.texts(bob), ["one", "two", "three"]);
    w.read(phone).await;
    assert_eq!(
        w.texts(phone),
        ["one", "two", "three"],
        "what it wrote itself reads back once, and the front end holds it by its id"
    );
}

/// A self-wrap the device cannot open is a chain it will not write under, whoever says it is
/// its newest.
#[tokio::test]
async fn a_self_wrap_that_does_not_open_means_a_new_chain() {
    let mut w = World::new().await;
    let (desktop, bob) = (w.person().await, w.person().await);
    w.join(desktop).await;
    w.join(bob).await;
    w.post(desktop, "one").await;
    let phone = w.device_of(desktop, LogMemory::default());
    w.tamper = Some(Box::new(|_, req, reply| {
        if matches!(req, AccountRequest::OwnChains { .. }) {
            if let AccountReply::OwnChains { chains, .. } = reply {
                for c in chains {
                    c.self_wrap[20] ^= 1;
                }
            }
        }
        true
    }));
    w.post(phone, "two").await;
    w.tamper = None;
    assert_eq!(w.last_epoch(phone).0, 2);
    w.read(bob).await;
    assert_eq!(w.texts(bob), ["one", "two"]);
}

/// A chain runs out of steps: the next arrival starts a new one, with no refused frame.
#[tokio::test]
async fn top_128_starts_a_new_chain() {
    let mut w = World::new().await;
    let (alice, bob) = (w.person().await, w.person().await);
    w.join(alice).await;
    w.join(bob).await;
    w.post(alice, "one").await;
    for i in 0..128 {
        let n = w.crowd(CONV, 1).await;
        w.post(alice, &format!("{i} for {:?}", n[0][15])).await;
    }
    assert_eq!(w.last_epoch(alice), (1, 128));
    w.crowd(CONV, 1).await;
    w.post(alice, "over").await;
    assert_eq!(w.last_epoch(alice).0, 2);
    assert!(
        !w.log.iter().any(|l| matches!(l, Line::NotKept { .. })),
        "{:?}",
        w.log
    );
    w.read(bob).await;
    assert_eq!(w.texts(bob).last(), Some(&"over"));
    assert_eq!(w.texts(bob).len(), 130);
}

// ── Flips ────────────────────────────────────────────────────────────────

/// The attack's first high: off, a joiner at index k, on, a leave. The new chain's link must
/// not reach them: they get index 1 of it, so nothing below where they came in opens.
#[tokio::test]
async fn a_flip_on_gives_nothing_below_a_seats_index() {
    let mut w = World::new().await;
    let (alice, bob, cy) = (w.person().await, w.person().await, w.person().await);
    for d in [alice, bob, cy] {
        w.join(d).await;
    }
    w.post(alice, "before fred").await;
    let fred = w.person().await;
    w.join(fred).await;
    w.post(alice, "fred is here").await;
    w.read(fred).await;
    assert_eq!(w.texts(fred), ["fred is here"]);
    let (old_entry, _) = (first_entry(&w, alice).await, 0);
    assert_eq!(epoch_parts(old_entry.epoch), (1, 0));
    w.sharing(alice, true);
    w.leave(bob).await;
    w.puts.clear();
    w.post(alice, "after the flip").await;
    assert_eq!(
        w.last_epoch(alice),
        (2, 1),
        "standing at index 1: nothing goes at 0"
    );
    let AccountRequest::ChainPut {
        link,
        step,
        buckets,
        seals,
        ..
    } = &w.puts[0].1
    else {
        unreachable!()
    };
    assert_eq!(link.as_ref().map(|(o, _)| *o), Some(1), "the link is there");
    assert!(step.is_some());
    let fred_bucket = buckets
        .iter()
        .find(|b| b.seats.iter().any(|s| s.recipient == w.devices[fred].id))
        .expect("a bucket of their own");
    let fred_seal = seals
        .iter()
        .find(|s| s.bucket == fred_bucket.bucket)
        .unwrap();
    assert_eq!(fred_seal.index, 1);
    assert!(
        seals.iter().any(|s| s.index == 0),
        "who held the start of chain 1 still holds this one's"
    );
    // Fred reads on, and below what was given does not open, whichever way it is handed him
    w.read(fred).await;
    assert_eq!(w.texts(fred), ["fred is here", "after the flip"]);
    let sync = &mut w.devices[fred].sync;
    let (_, events) = sync.on_reply(&page(CONV, vec![old_entry])).unwrap();
    assert!(!events
        .iter()
        .any(|e| matches!(e, Event::ChannelMessage { .. })));
    // Cy held it all along, and a newcomer now gets the lot by the link
    w.read(cy).await;
    assert_eq!(
        w.texts(cy),
        ["before fred", "fred is here", "after the flip"]
    );
    let ann = w.person().await;
    w.join(ann).await;
    w.read(ann).await;
    assert_eq!(
        w.texts(ann),
        ["before fred", "fred is here", "after the flip"]
    );
    assert!(w
        .log
        .iter()
        .any(|l| matches!(l, Line::Named { device, history: true, .. } if *device == alice)));
}

async fn first_entry(w: &World, d: usize) -> LogEntry {
    let AccountReply::ChainPage { entries, .. } =
        log::chain_fetch(&w.relay, AccountId(w.devices[d].id), CONV, 0)
            .await
            .unwrap()
    else {
        panic!("a page");
    };
    entries.first().cloned().expect("an entry")
}

/// A joiner under a sharer reads back through one row and the links.
#[tokio::test]
async fn a_sharers_joiner_opens_what_it_kept_by_the_links() {
    let mut w = World::new().await;
    let (alice, bob, cy) = (w.person().await, w.person().await, w.person().await);
    for d in [alice, bob, cy] {
        w.join(d).await;
    }
    w.sharing(alice, true);
    w.post(alice, "one").await;
    w.leave(bob).await;
    w.post(alice, "two").await;
    let dan = w.person().await;
    w.join(dan).await;
    w.leave(cy).await;
    w.post(alice, "three").await;
    assert_eq!(w.last_epoch(alice).0, 3);
    let ann = w.person().await;
    w.join(ann).await;
    w.read(ann).await;
    assert_eq!(w.texts(ann), ["one", "two", "three"]);
    w.read(dan).await;
    assert_eq!(w.texts(dan), ["one", "two", "three"]);
    // Off-era chains no link reaches go as one row each: chain 4 to come has one too
    assert!(w.named(alice).iter().any(|a| *a == w.devices[ann].id));
}

/// Off again: what was given stays, a joiner reads from a fresh step, no more links.
#[tokio::test]
async fn a_flip_off_leaves_keys_given_and_writes_no_link() {
    let mut w = World::new().await;
    let (alice, bob, cy) = (w.person().await, w.person().await, w.person().await);
    for d in [alice, bob, cy] {
        w.join(d).await;
    }
    w.sharing(alice, true);
    w.post(alice, "one").await;
    let ann = w.person().await;
    w.join(ann).await;
    w.read(ann).await;
    assert_eq!(w.texts(ann), ["one"]);
    w.sharing(alice, false);
    let dan = w.person().await;
    w.join(dan).await;
    w.post(alice, "two").await;
    assert_eq!(w.last_epoch(alice), (1, 1), "a step for the new one");
    let dan_id = w.id(dan);
    assert!(
        !w.log.iter().any(|l| matches!(l, Line::Named { accounts, history: true, .. } if accounts.contains(&dan_id))),
        "and nothing older offered: {:?}",
        w.log
    );
    assert!(
        !w.log.iter().any(|l| matches!(l, Line::NotKept { .. })),
        "{:?}",
        w.log
    );
    w.read(dan).await;
    assert_eq!(w.texts(dan), ["two"]);
    w.leave(bob).await;
    w.puts.clear();
    w.post(alice, "three").await;
    let AccountRequest::ChainPut { link, .. } = &w.puts[0].1 else {
        unreachable!()
    };
    assert!(link.is_none());
    w.read(ann).await;
    assert_eq!(w.texts(ann), ["one", "two", "three"]);
}

/// Taken away while the switch stays on: the same. The app is told by `set_share`.
#[tokio::test]
async fn a_lost_privilege_writes_no_link_and_gives_no_older_key() {
    let mut w = World::new().await;
    let (alice, bob, cy) = (w.person().await, w.person().await, w.person().await);
    for d in [alice, bob, cy] {
        w.join(d).await;
    }
    w.sharing(alice, true);
    w.post(alice, "one").await;
    w.sharing(alice, false);
    let ann = w.person().await;
    w.join(ann).await;
    w.leave(bob).await;
    w.puts.clear();
    w.post(alice, "two").await;
    assert!(matches!(
        &w.puts[0].1,
        AccountRequest::ChainPut { link: None, .. }
    ));
    w.read(ann).await;
    assert_eq!(w.texts(ann), ["two"]);
}

/// The relay's word for who held what is never asked: a relay that hides all history makes
/// a chain look like a first post, and then shows it again.
#[tokio::test]
async fn index_zero_goes_only_on_proof_never_on_the_relays_word() {
    let mut w = World::new().await;
    let (alice, bob, cy) = (w.person().await, w.person().await, w.person().await);
    for d in [alice, bob, cy] {
        w.join(d).await;
    }
    w.post(alice, "one").await;
    w.sharing(alice, true);
    w.leave(bob).await;
    // The relay will not show the rows that prove it
    w.tamper = Some(Box::new(|_, req, reply| {
        if matches!(req, AccountRequest::OwnChainRows { .. }) {
            if let AccountReply::OwnChainRows { seals, .. } = reply {
                seals.clear();
            }
        }
        true
    }));
    w.puts.clear();
    w.post(alice, "two").await;
    w.tamper = None;
    let AccountRequest::ChainPut { link, seals, .. } = &w.puts[0].1 else {
        unreachable!()
    };
    assert!(
        link.is_none(),
        "with nobody proven, no link for anyone to use"
    );
    assert!(
        seals.iter().all(|s| s.index == 0),
        "and so no reason for index 1"
    );
}

/// Purged: the next post starts a chain, with no link back, whatever the switch says.
#[tokio::test]
async fn a_purge_starts_a_chain_with_no_link() {
    let mut w = World::new().await;
    let (alice, bob) = (w.person().await, w.person().await);
    w.join(alice).await;
    w.join(bob).await;
    w.sharing(alice, true);
    w.post(alice, "one").await;
    w.devices[alice]
        .out
        .push_back(ClientMessage::Account(AccountRequest::LogPurge {
            conv: Some(CONV.to_string()),
        }));
    w.pump().await;
    w.puts.clear();
    w.post(alice, "two").await;
    let AccountRequest::ChainPut { link, .. } = &w.puts[0].1 else {
        unreachable!()
    };
    assert!(link.is_none());
    w.read(bob).await;
    assert_eq!(w.texts(bob), ["two"]);
}

// ── Buckets over time ────────────────────────────────────────────────────

/// Nothing says a post went on a chain a reader already holds, so a channel in quiet mode has
/// to be read when it comes on screen. Opening one takes no seat.
#[tokio::test]
async fn a_channel_that_slept_is_read_on_opening_and_takes_no_seat() {
    let mut w = World::new().await;
    let (alice, bob, cat) = (w.person().await, w.person().await, w.person().await);
    w.join(alice).await;
    w.join(bob).await;
    w.post(alice, "first").await;
    w.read(bob).await;
    assert!(w.texts(bob).contains(&"first"), "{:?}", w.texts(bob));
    w.post(alice, "while it slept").await;
    assert!(!w.texts(bob).contains(&"while it slept"), "no word of it");
    let s = w.devices[bob].sync.read_now(CONV);
    w.devices[bob].out.extend(s);
    w.pump().await;
    assert!(
        w.texts(bob).contains(&"while it slept"),
        "{:?}",
        w.texts(bob)
    );

    assert!(w.devices[cat].sync.read_now(CONV).is_empty());
}

/// A member in a bucket that gets merged reads on: what came before by their old row, what
/// comes after by their new one. Sixteen arrive before each leave, so the buckets are many
/// for the seats and too big to count as small: only a re-pack merges those.
#[tokio::test]
async fn a_member_reads_across_a_repack() {
    let mut w = World::new().await;
    let (alice, reader) = (w.person().await, w.person().await);
    w.join(alice).await;
    let mut big = w.crowd(CONV, 62).await;
    w.post(alice, "start").await;
    assert_eq!(w.live_buckets(alice, CONV).await.len(), 1);
    w.join(reader).await;
    w.crowd(CONV, 15).await;
    let mut said = vec!["from here"];
    w.post(alice, "from here").await;
    // ...and leavers out of the first bucket, which stays big, make each chain
    for _ in 0..26 {
        let who = big.pop().unwrap();
        log::remove(w.relay.store(), CONV, &who).await.unwrap();
        db!(w.relay.store(), pool => {
            sqlx::query("UPDATE voipc_writers SET new_this_hour = 0").execute(pool).await.unwrap();
        });
        w.post(alice, "next chain").await;
        said.push("next chain");
        w.crowd(CONV, 16).await;
    }
    let who = big.pop().unwrap();
    log::remove(w.relay.store(), CONV, &who).await.unwrap();
    db!(w.relay.store(), pool => {
        sqlx::query("UPDATE voipc_writers SET new_this_hour = 0").execute(pool).await.unwrap();
    });
    w.post(alice, "across").await;
    said.push("across");
    let live = w.live_buckets(alice, CONV).await;
    let total: u32 = live.iter().map(|(_, _, n)| *n).sum();
    assert!(
        (live.len() as f64) <= cap(i64::from(total)),
        "{} buckets for {total} seats",
        live.len()
    );
    assert!(
        live.iter().any(|(_, v, n)| *v == 0 && *n > 16),
        "a merged bucket is a fresh one: {live:?}"
    );
    w.read(reader).await;
    assert_eq!(w.texts(reader), said);
}

/// Each chain's arrival is a small bucket, and at sixteen of them they merge into one, with a
/// fresh key and no link, long before the buckets are many for the seats.
#[tokio::test]
async fn sixteen_small_buckets_merge_into_one() {
    let mut w = World::new().await;
    let (alice, reader) = (w.person().await, w.person().await);
    w.join(alice).await;
    let mut big = w.crowd(CONV, 62).await;
    w.post(alice, "start").await;
    w.join(reader).await;
    let mut said = Vec::new();
    for _ in 0..16 {
        w.post(alice, "for the arrival").await;
        said.push("for the arrival");
        let who = big.pop().unwrap();
        log::remove(w.relay.store(), CONV, &who).await.unwrap();
        db!(w.relay.store(), pool => {
            sqlx::query("UPDATE voipc_writers SET new_this_hour = 0").execute(pool).await.unwrap();
        });
        w.post(alice, "next chain").await;
        said.push("next chain");
        w.crowd(CONV, 1).await;
    }
    let live = w.live_buckets(alice, CONV).await;
    assert!(
        live.iter().filter(|(_, _, n)| *n < 16).count() < 16,
        "{live:?}"
    );
    assert!(live.iter().any(|(_, v, n)| *v == 0 && *n >= 15), "{live:?}");
    w.read(reader).await;
    assert_eq!(w.texts(reader), said, "and whoever was in them reads on");
}

fn cap(seats: i64) -> f64 {
    1.5 * seats as f64 / 62.0 + 16.0
}

/// Five arrive and five leave a day, for a year, a chain a day. Buckets only shrink and
/// nothing else merges the big ones, so without a re-pack this climbs without end.
#[tokio::test]
async fn buckets_stay_under_the_cap_through_a_year_of_churn() {
    let mut w = World::new().await;
    let (alice, reader) = (w.person().await, w.person().await);
    w.join(alice).await;
    w.join(reader).await;
    let mut seated: VecDeque<Id> = w.crowd(CONV, 124).await.into_iter().collect();
    // Who comes and goes come back in turn: the same keys, so only the channel is at work
    let mut outside: VecDeque<Id> = w.crowd(OTHER, 20).await.into_iter().collect();
    w.post(alice, "start").await;
    let mut highest = 0usize;
    for day in 0..365 {
        // As `log::remove` and `log::join` leave it, in one transaction: a year of the
        // statements of those two is most of a minute, and neither is under test here
        let mut churn = Vec::new();
        for _ in 0..5 {
            let who = seated.pop_front().unwrap();
            let back = outside.pop_front().unwrap();
            seated.push_back(back);
            outside.push_back(who);
            churn.push((who, back));
        }
        db!(w.relay.store(), pool => {
            let mut tx = pool.begin().await.unwrap();
            for (who, back) in &churn {
                sqlx::query("DELETE FROM voipc_members WHERE conv = $1 AND account = $2")
                    .bind(CONV)
                    .bind(&who[..])
                    .execute(&mut *tx)
                    .await
                    .unwrap();
                sqlx::query("INSERT INTO voipc_members (conv, account, joined_at) VALUES ($1, $2, 1)")
                    .bind(CONV)
                    .bind(&back[..])
                    .execute(&mut *tx)
                    .await
                    .unwrap();
            }
            sqlx::query("UPDATE voipc_writers SET new_this_hour = 0").execute(&mut *tx).await.unwrap();
            tx.commit().await.unwrap();
        });
        w.post(alice, &format!("day {day}")).await;
        let live = w.live_buckets(alice, CONV).await;
        highest = highest.max(live.len());
        let total: u32 = live.iter().map(|(_, _, n)| *n).sum();
        assert!(
            (live.len() as f64) <= cap(i64::from(total)),
            "day {day}: {} buckets for {total} seats",
            live.len()
        );
    }
    assert!(
        !w.log.iter().any(|l| matches!(l, Line::NotKept { .. })),
        "{:?}",
        w.log.iter().find(|l| matches!(l, Line::NotKept { .. }))
    );
    assert!(highest >= 5, "{highest}");
    w.read(reader).await;
    assert_eq!(
        w.texts(reader).len(),
        366,
        "and a reader in there read it all"
    );
}

// ── A reader ─────────────────────────────────────────────────────────────

/// A relay's ECIES row at a chain's epoch does not open: it would pick a state we adopt.
#[tokio::test]
async fn an_ecies_row_on_a_chain_does_not_open() {
    let mut w = World::new().await;
    let (alice, bob) = (w.person().await, w.person().await);
    w.join(alice).await;
    w.join(bob).await;
    w.post(alice, "one").await;
    let logkey = {
        let AccountReply::LogKeysFound { keys } = log::keys(&w.relay, &[w.id(bob)]).await.unwrap()
        else {
            panic!()
        };
        keys[0].logkey.clone()
    };
    let (owner, me) = (w.id(alice), w.id(bob));
    let epoch = chain_epoch(1, 0).unwrap();
    let relay_state = [9u8; 32];
    let ecies = voipc_crypto::log::wrap(&logkey, &relay_state, CONV, &owner, epoch, &me).unwrap();
    w.tamper = Some(Box::new(move |_, req, reply| {
        if matches!(req, AccountRequest::WrapsPage { .. }) {
            *reply = AccountReply::WrapsPage {
                conv: CONV.to_string(),
                keys: vec![ChainKeys {
                    owner,
                    chain: 1,
                    self_wrap: None,
                    direct: Some((0, ecies.clone())),
                    seal: None,
                    seat: None,
                    down: Vec::new(),
                    link: None,
                    steps: Vec::new(),
                }],
                served: 1,
            };
        }
        true
    }));
    w.read(bob).await;
    w.tamper = None;
    assert!(w.texts(bob).is_empty());
    assert!(w
        .log
        .iter()
        .any(|l| matches!(l, Line::Unopened { device } if *device == bob)));
}

/// Rows for a writer whose keys do not check out wait for nothing, and asks stop.
#[tokio::test]
async fn a_distrusted_writers_rows_are_dropped_and_not_asked_again() {
    let mut w = World::new().await;
    let (alice, bob) = (w.person().await, w.person().await);
    w.join(alice).await;
    w.join(bob).await;
    w.post(alice, "one").await;
    w.tamper = Some(Box::new(|_, req, reply| {
        if matches!(req, AccountRequest::LogKeys { .. }) {
            if let AccountReply::LogKeysFound { keys } = reply {
                for k in keys {
                    k.sig[0] ^= 1;
                }
            }
        }
        true
    }));
    w.log.clear();
    w.read(bob).await;
    w.tamper = None;
    assert!(w.texts(bob).is_empty());
    assert!(
        !w.log.iter().any(
            |l| matches!(l, Line::Sent { device, what } if *device == bob && what == "WrapsPage")
        ),
        "a row of theirs could not open: nothing asked"
    );
    assert!(w
        .log
        .iter()
        .any(|l| matches!(l, Line::Unopened { device } if *device == bob)));
}

/// `skipped` moves the cursor, so `LogConvs` does not call the log unread at every connect,
/// and it says the quiet line. No toast.
#[tokio::test]
async fn skipped_entries_move_the_cursor_and_say_the_quiet_line() {
    let mut w = World::new().await;
    let (alice, bob) = (w.person().await, w.person().await);
    w.join(alice).await;
    w.join(bob).await;
    w.post(alice, "one").await;
    let fred = w.person().await;
    w.log.clear();
    w.join(fred).await;
    assert!(w.texts(fred).is_empty());
    assert!(w
        .log
        .iter()
        .any(|l| matches!(l, Line::Unopened { device } if *device == fred)));
    assert!(!w
        .log
        .iter()
        .any(|l| matches!(l, Line::NotKept { device, .. } if *device == fred)));
    let cursor = w.devices[fred].sync.memory().cursors[CONV];
    assert!(cursor > 0, "past what it can never open");
}

/// One re-read of the wraps for an entry on a chain made during the read, before it counts.
#[tokio::test]
async fn an_entry_on_a_chain_minted_during_a_read_gets_one_more_ask() {
    let mut w = World::new().await;
    let (alice, bob) = (w.person().await, w.person().await);
    w.join(alice).await;
    w.join(bob).await;
    w.post(alice, "one").await;
    let mut first = true;
    w.tamper = Some(Box::new(move |d, req, reply| {
        if d == 1 && matches!(req, AccountRequest::WrapsPage { .. }) && first {
            first = false;
            if let AccountReply::WrapsPage { keys, .. } = reply {
                for k in keys {
                    k.seal = None;
                    k.seat = None;
                    k.direct = None;
                }
            }
        }
        true
    }));
    w.read(bob).await;
    w.tamper = None;
    assert_eq!(w.texts(bob), ["one"]);
}

/// Alice, sharing, ends a chain four times; someone new, seated on the newest, has that whole
/// run of links to come down. Each ask from nothing brings the first two hops, as a long run
/// does. What the reader asks past that goes in `asks`, and with `only_oldest` its pages
/// carry nothing but the oldest chain's two entries, so no entry above asks for its own chain.
async fn read_down_a_run(only_oldest: bool) -> (World, usize, Vec<ChainAsk>) {
    let mut w = World::new().await;
    let (alice, bob) = (w.person().await, w.person().await);
    w.join(alice).await;
    w.join(bob).await;
    w.sharing(alice, true);
    w.post(alice, "one").await;
    for i in 0..4 {
        let leaver = w.person().await;
        w.join(leaver).await;
        w.post(alice, &format!("for {i}")).await;
        w.leave(leaver).await;
        w.post(alice, &format!("gone {i}")).await;
    }
    let ann = w.person().await;
    let seen: std::sync::Arc<std::sync::Mutex<Vec<ChainAsk>>> = Default::default();
    let saw = seen.clone();
    w.tamper = Some(Box::new(move |d, req, reply| {
        if d != ann {
            return true;
        }
        match (req, reply) {
            (
                AccountRequest::WrapsPage { asks, .. },
                AccountReply::WrapsPage { keys, served, .. },
            ) => {
                saw.lock().unwrap().extend(asks.iter().cloned());
                if asks[0].from.is_none() && keys.len() > 2 {
                    keys.truncate(2);
                    *served = 1;
                }
            }
            (_, AccountReply::ChainPage { entries, .. }) if only_oldest => entries.truncate(2),
            _ => {}
        }
        true
    }));
    w.join(ann).await;
    w.read(ann).await;
    w.tamper = None;
    let asks = seen.lock().unwrap().clone();
    (w, ann, asks)
}

/// A run of links too long for one answer: the asked chain does not come, and walking on
/// from the last link brought does.
#[tokio::test]
async fn a_run_of_links_past_one_answer_is_walked_on() {
    let (w, ann, _) = read_down_a_run(false).await;
    // In the order they came to open: the app files them by time
    assert_eq!(w.texts(ann).len(), 9, "{:?}", w.texts(ann));
    assert!(w.texts(ann).contains(&"one"), "{:?}", w.texts(ann));
}

/// With nothing above to read, the walk alone gets there: chains no entry asked for, each
/// from its start, and then the oldest.
#[tokio::test]
async fn a_walk_goes_down_chains_no_entry_asked_for() {
    let (w, ann, asks) = read_down_a_run(true).await;
    assert_eq!(w.texts(ann), ["one", "for 0"]);
    let walked: Vec<u32> = asks
        .iter()
        .filter(|a| a.chain != 1 && a.from == Some(0))
        .map(|a| a.chain)
        .collect();
    assert!(walked.contains(&3) && walked.contains(&2), "{asks:?}");
}

/// A cursor below what the channel still keeps was moved up, and the line says how many.
#[tokio::test]
async fn a_cursor_below_the_floor_says_the_windows_number() {
    let mut w = World::with(|c| c.kept_window = 3).await;
    let (alice, bob) = (w.person().await, w.person().await);
    w.join(alice).await;
    w.join(bob).await;
    w.post(alice, "one").await;
    w.read(bob).await;
    for i in 0..6 {
        w.post(alice, &format!("{i}")).await;
    }
    db!(w.relay.store(), pool => {
        // Settled, so the sweep may move the floor
        sqlx::query("UPDATE voipc_log SET server_at = 0").execute(pool).await.unwrap();
    });
    log::sweep(&w.relay).await.unwrap();
    w.log.clear();
    w.read(bob).await;
    assert!(
        w.log
            .iter()
            .any(|l| matches!(l, Line::Clamped { device, window: 3 } if *device == bob)),
        "{:?}",
        w.log
    );
    assert_eq!(w.texts(bob).len(), 1 + 3);
}

// ── Seating ──────────────────────────────────────────────────────────────

/// In one frame, and reads what each kept; a log that is full for a silent follow says so
/// to nobody.
#[tokio::test]
async fn following_many_channels_seats_them_in_one_frame() {
    let mut w = World::with(|c| c.kept_seats = 2).await;
    let (alice, bob) = (w.person().await, w.person().await);
    let s = w.devices[alice].sync.enter_many(&[CONV.to_string()]);
    w.devices[alice].out.extend(s);
    w.pump().await;
    w.post(alice, "one").await;
    w.log.clear();
    let s = w.devices[bob]
        .sync
        .enter_many(&[CONV.to_string(), OTHER.to_string()]);
    w.devices[bob].out.extend(s);
    w.pump().await;
    let frames = w
        .log
        .iter()
        .filter(|l| matches!(l, Line::Sent { what, .. } if what == "LogJoinMany"))
        .count();
    assert_eq!(frames, 1);
    assert!(!w.log.iter().any(|l| matches!(l, Line::NotKept { .. })));
    // Half of two seats was taken by alice: bob's silent follow was refused, for free
    let seated = w
        .rows("SELECT COUNT(*) FROM voipc_members WHERE conv = 'c:lounge'")
        .await;
    assert_eq!(seated, 1);
    assert_eq!(
        w.rows("SELECT COUNT(*) FROM voipc_members WHERE conv = 'c:other'")
            .await,
        1
    );
}

/// Told by the relay that it has to wait after leaving: no message about it, and asking
/// again later works.
#[tokio::test]
async fn a_wait_after_leaving_is_quiet() {
    let mut w = World::new().await;
    let (alice, bob) = (w.person().await, w.person().await);
    w.join(alice).await;
    w.join(bob).await;
    w.post(alice, "one").await;
    let s = w.devices[bob].sync.leave(CONV, true);
    w.devices[bob].out.extend(s);
    w.pump().await;
    w.log.clear();
    w.join(bob).await;
    assert!(
        !w.log.iter().any(|l| matches!(l, Line::NotKept { .. })),
        "{:?}",
        w.log
    );
    assert_eq!(
        w.rows("SELECT COUNT(*) FROM voipc_members WHERE conv = 'c:lounge'")
            .await,
        1
    );
    db!(w.relay.store(), pool => {
        sqlx::query("DELETE FROM voipc_left").execute(pool).await.unwrap();
    });
    w.join(bob).await;
    assert_eq!(
        w.rows("SELECT COUNT(*) FROM voipc_members WHERE conv = 'c:lounge'")
            .await,
        2
    );
}

/// A writer's log key gone: its rows are dead, so its buckets are lost and its chains closed
/// to it. It starts over from the ids, each person named, and goes on being read.
#[tokio::test]
async fn a_writers_new_log_key_means_new_buckets_each_person_named() {
    let mut w = World::new().await;
    let (alice, bob) = (w.person().await, w.person().await);
    w.join(alice).await;
    w.join(bob).await;
    w.post(alice, "one").await;
    let identity = w.accounts[alice].identity;
    let new_key = LogKey::generate();
    db!(w.relay.store(), pool => {
        sqlx::query("UPDATE voipc_logkeys SET updated_at = 0").execute(pool).await.unwrap();
    });
    log::publish(
        &w.relay,
        AccountId(w.id(alice)),
        &new_key.public(),
        &new_key.endorse(&identity),
    )
    .await
    .unwrap();
    w.accounts[alice].blobs = vec![VaultBlob {
        version: 1,
        ..w.accounts[alice]
            .vault
            .seal_item(ITEM_LOGKEY, 1, &new_key.to_bytes())
    }];
    w.devices[alice].online = false;
    let phone = w.device_of(alice, LogMemory::default());
    w.log.clear();
    w.post(phone, "two").await;
    assert_eq!(w.last_epoch(phone).0, 2);
    assert!(w.named(phone).contains(&w.id(bob)));
    assert!(w
        .log
        .iter()
        .any(|l| matches!(l, Line::Sent { what, .. } if what == "LogMemberIds")));
    // What was signed under the old key stops verifying, on anyone's device, as it did
    let fresh = w.device_of(bob, LogMemory::default());
    w.read(fresh).await;
    assert_eq!(w.texts(fresh), ["two"]);
}

/// With the relay saying nothing of it, a seat on a list under another log key is someone
/// else on that account, or the same one with whoever holds the old key still in: out.
#[tokio::test]
async fn a_seat_under_an_old_log_key_is_rotated_out_on_the_writers_own_word() {
    let mut w = World::new().await;
    let (alice, bob, cy) = (w.person().await, w.person().await, w.person().await);
    for d in [alice, bob, cy] {
        w.join(d).await;
    }
    w.post(alice, "one").await;
    let identity = w.accounts[cy].identity;
    let new_key = LogKey::generate();
    db!(w.relay.store(), pool => {
        sqlx::query("UPDATE voipc_logkeys SET updated_at = 0").execute(pool).await.unwrap();
    });
    log::publish(
        &w.relay,
        AccountId(w.id(cy)),
        &new_key.public(),
        &new_key.endorse(&identity),
    )
    .await
    .unwrap();
    // A new run with no memory, so it reads the list and asks for today's key; the relay
    // does not say anyone has gone
    w.devices[alice].online = false;
    let again = w.device_of(alice, LogMemory::default());
    w.tamper = Some(Box::new(|_, req, reply| {
        if let AccountRequest::LogAppend { conv, .. } = req {
            *reply = AccountReply::ChainRekey {
                conv: conv.clone(),
                new_chain: true,
                missing: Vec::new(),
                gone: Vec::new(),
            };
        }
        true
    }));
    w.post(again, "two").await;
    w.tamper = None;
    assert_eq!(
        w.live_buckets(again, CONV).await[0].1,
        1,
        "a new version, without them"
    );
}

/// `missing` at its cap may be cut short: a new chain rather than a step.
#[tokio::test]
async fn missing_at_its_cap_starts_a_new_chain() {
    let mut w = World::new().await;
    let (alice, bob) = (w.person().await, w.person().await);
    w.join(alice).await;
    w.join(bob).await;
    w.post(alice, "one").await;
    w.crowd(CONV, 256).await;
    w.post(alice, "two").await;
    assert_eq!(w.last_epoch(alice).0, 2);
    w.read(bob).await;
    assert_eq!(w.texts(bob), ["one", "two"]);
}

/// `gone` at its cap: the rest are found from all the ids and all the lists.
#[tokio::test]
async fn gone_at_its_cap_goes_by_the_ids() {
    let mut w = World::new().await;
    let (alice, bob, cy) = (w.person().await, w.person().await, w.person().await);
    for d in [alice, bob, cy] {
        w.join(d).await;
    }
    w.post(alice, "one").await;
    log::remove(w.relay.store(), CONV, &w.id(cy)).await.unwrap();
    w.tamper = Some(Box::new(|_, req, reply| {
        if let AccountRequest::LogAppend { conv, .. } = req {
            *reply = AccountReply::ChainRekey {
                conv: conv.clone(),
                new_chain: true,
                missing: Vec::new(),
                gone: (0..1024).map(|i| (id_of(90_000 + i), i)).collect(),
            };
        }
        true
    }));
    w.log.clear();
    w.post(alice, "two").await;
    w.tamper = None;
    assert!(w
        .log
        .iter()
        .any(|l| matches!(l, Line::Sent { what, .. } if what == "LogMemberIds")));
    assert_eq!(w.live_buckets(alice, CONV).await[0].1, 1, "out of it");
    w.read(bob).await;
    // The answer was changed on its way back: the relay had filed the post under the old key
    assert_eq!(w.texts(bob), ["one", "two", "two"]);
}

/// A reader's log keys come first, and it asks only for the chains of what it is reading.
#[tokio::test]
async fn a_reader_asks_keys_first_and_only_for_the_chains_it_reads() {
    let mut w = World::new().await;
    let (alice, bob, cy) = (w.person().await, w.person().await, w.person().await);
    for d in [alice, bob, cy] {
        w.join(d).await;
    }
    w.post(alice, "one").await;
    w.read(bob).await;
    w.leave(cy).await;
    w.post(alice, "two").await;
    let seen: std::sync::Arc<std::sync::Mutex<Vec<ChainAsk>>> = Default::default();
    let asks = seen.clone();
    w.tamper = Some(Box::new(move |_, req, _| {
        if let AccountRequest::WrapsPage { asks: these, .. } = req {
            asks.lock().unwrap().extend(these.iter().cloned());
        }
        true
    }));
    w.read(bob).await;
    w.tamper = None;
    assert_eq!(w.texts(bob), ["one", "two"]);
    assert_eq!(
        seen.lock()
            .unwrap()
            .iter()
            .map(|a| a.chain)
            .collect::<Vec<_>>(),
        [2],
        "the chain it already read is not asked for again"
    );
    // A new device, keys first
    let fresh = w.device_of(bob, LogMemory::default());
    w.log.clear();
    w.read(fresh).await;
    let at = |name: &str| {
        w.log.iter().position(
            |l| matches!(l, Line::Sent { device, what } if *device == fresh && what == name),
        )
    };
    assert!(at("LogKeys").unwrap() < at("WrapsPage").unwrap());
    assert_eq!(w.texts(fresh), ["one", "two"]);
}

// ── What a version before chains kept ────────────────────────────────────

impl World {
    /// An entry and its wraps as a relay before protocol 21 kept them.
    async fn old_entry(&mut self, writer: usize, to: &[usize], text: &str) -> i64 {
        let signed = &self.accounts[writer];
        let item = signed.vault.open_item(&signed.blobs, ITEM_LOGKEY).unwrap();
        let logkey = LogKey::from_bytes(&item.payload).unwrap();
        let owner = id_of(writer as u64 + 1);
        let epoch = 0x1000_0001u32;
        let key = voipc_crypto::log::epoch_key();
        let mut rows = vec![(
            owner,
            voipc_crypto::log::self_wrap(&logkey, &key, CONV, &owner, epoch),
        )];
        for d in to {
            let them = id_of(*d as u64 + 1);
            let AccountReply::LogKeysFound { keys } =
                log::keys(&self.relay, &[them]).await.unwrap()
            else {
                panic!()
            };
            rows.push((
                them,
                voipc_crypto::log::wrap(&keys[0].logkey, &key, CONV, &owner, epoch, &them).unwrap(),
            ));
        }
        self.next_at += 1;
        let ct = voipc_crypto::log::seal_entry(
            &key,
            CONV,
            &owner,
            epoch,
            &logkey,
            &envelope(&format!("old{}", self.next_at), text, None),
            self.next_at,
        );
        db!(self.relay.store(), pool => {
            for (who, wrapped) in &rows {
                sqlx::query("INSERT INTO voipc_wraps (conv, owner, epoch, recipient, wrapped, created_at) VALUES ($1, $2, $3, $4, $5, 1)")
                    .bind(CONV)
                    .bind(&owner[..])
                    .bind(i64::from(epoch))
                    .bind(&who[..])
                    .bind(wrapped.as_slice())
                    .execute(pool)
                    .await
                    .unwrap();
            }
            sqlx::query_scalar("INSERT INTO voipc_log (conv, sender, epoch, server_at, keep_until, ct) VALUES ($1, $2, $3, 1, $4, $5) RETURNING seq")
                .bind(CONV)
                .bind(&owner[..])
                .bind(i64::from(epoch))
                .bind(i64::MAX)
                .bind(ct.as_slice())
                .fetch_one(pool)
                .await
                .unwrap()
        })
    }
}

/// "Every 1.x opens everything any earlier 1.x wrote": a relay updated with rows on epochs
/// serves them to who holds a key, the writer's next post goes on a chain, and someone who
/// holds no key is not sent it.
#[tokio::test]
async fn what_a_version_before_chains_kept_stays_readable() {
    let mut w = World::new().await;
    let (alice, bob, cy) = (w.person().await, w.person().await, w.person().await);
    for d in [alice, bob, cy] {
        w.join(d).await;
    }
    w.old_entry(alice, &[bob], "from before").await;
    w.post(alice, "on a chain").await;
    assert_eq!(w.last_epoch(alice).0, 1);
    w.read(bob).await;
    let mut read = w.texts(bob);
    read.sort_unstable();
    assert_eq!(read, ["from before", "on a chain"]);
    w.read(cy).await;
    assert_eq!(w.texts(cy), ["on a chain"]);
    // And on its writer's other device
    let again = w.device_of(alice, LogMemory::default());
    w.read(again).await;
    let mut read = w.texts(again);
    read.sort_unstable();
    assert_eq!(read, ["from before", "on a chain"]);
}

/// A writer who shares hands its old keys on too: that is what the switch says.
#[tokio::test]
async fn a_sharers_joiner_gets_the_keys_of_a_version_before_chains() {
    let mut w = World::new().await;
    let (alice, bob) = (w.person().await, w.person().await);
    w.join(alice).await;
    w.join(bob).await;
    w.sharing(alice, true);
    w.old_entry(alice, &[bob], "from before").await;
    w.post(alice, "on a chain").await;
    let ann = w.person().await;
    w.join(ann).await;
    w.read(ann).await;
    let mut read = w.texts(ann);
    read.sort_unstable();
    assert_eq!(read, ["from before", "on a chain"]);
    // A new key on a channel is a chain's: no writer starts an epoch here
    let AccountReply::Error { .. } = log::epoch_put(
        &w.relay,
        AccountId(w.id(alice)),
        CONV,
        7,
        &[voipc_protocol::messages::WrapIn {
            recipient: w.id(ann),
            wrapped: vec![1; 93],
        }],
    )
    .await
    .unwrap()
    .0
    else {
        panic!("a new epoch on a channel")
    };
}

// ── What it does not do ──────────────────────────────────────────────────

#[tokio::test]
async fn a_relay_cannot_start_a_chain_unasked() {
    let mut w = World::new().await;
    let (alice, bob) = (w.person().await, w.person().await);
    w.join(alice).await;
    w.join(bob).await;
    w.post(alice, "one").await;
    w.puts.clear();
    w.log.clear();
    w.deliver(
        alice,
        AccountReply::ChainRekey {
            conv: CONV.to_string(),
            new_chain: true,
            missing: vec![id_of(99)],
            gone: Vec::new(),
        },
    );
    w.pump().await;
    assert!(w.puts.is_empty(), "nothing of ours asked for it");
    assert!(w.named(alice).iter().all(|a| *a != id_of(99)));
}

/// A chain that cannot reach someone gives up after a few rounds, and a new chain counts as
/// a round: otherwise a relay answering `new_chain` each time costs a whole chain per try.
#[tokio::test]
async fn rounds_of_new_chains_give_up() {
    let mut w = World::new().await;
    let (alice, bob) = (w.person().await, w.person().await);
    w.join(alice).await;
    w.join(bob).await;
    w.post(alice, "one").await;
    w.tamper = Some(Box::new(|_, req, reply| {
        if let AccountRequest::LogAppend { conv, .. } = req {
            *reply = AccountReply::ChainRekey {
                conv: conv.clone(),
                new_chain: true,
                missing: Vec::new(),
                gone: Vec::new(),
            };
        }
        true
    }));
    w.puts.clear();
    w.post(alice, "two").await;
    w.tamper = None;
    assert!(w.puts.len() <= 3, "{}", w.puts.len());
    assert!(w.log.iter().any(|l| matches!(l, Line::NotKept { .. })));
}

/// A step with no reader for it would be a modified app's: this app never sends one.
#[tokio::test]
async fn nobody_new_means_no_step() {
    let mut w = World::new().await;
    let (alice, bob) = (w.person().await, w.person().await);
    w.join(alice).await;
    w.join(bob).await;
    w.post(alice, "one").await;
    w.puts.clear();
    for i in 0..20 {
        w.post(alice, &format!("{i}")).await;
    }
    assert!(w.puts.is_empty());
}

// ── Pins past the sign-in frame, and seats past the old wall ─────────────

async fn pin_pages(w: &World, me: AccountId) -> i64 {
    w.relay.store().blob_count(me, PINS_NS).await.unwrap()
}

/// The relay's word for `account`, under an identity of its own.
fn swapped(account: Id, name: &str) -> AccountReply {
    let liar = generate_identity_key_pair();
    let logkey = LogKey::generate();
    AccountReply::LogKeysFound {
        keys: vec![LogKeyInfo {
            account,
            name: name.to_string(),
            identity: liar.public_key().serialize().to_vec(),
            logkey: logkey.public(),
            sig: logkey.endorse(&liar),
        }],
    }
}

/// Nobody's page travels in the sign-in frame, each is read back after it across a page
/// boundary, and a key the relay swaps while they are out is told of once they are in.
#[tokio::test]
async fn a_real_account_sync_reads_its_pins_across_a_page_boundary() {
    let mut w = World::new().await;
    let alice = w.person().await;
    w.join(alice).await;
    let crowd = w.crowd(CONV, 800).await;
    w.post(alice, "one").await;
    let me = AccountId(w.id(alice));
    assert_eq!(pin_pages(&w, me).await, 0, "a save per person");
    assert!(w.devices[alice].sync.pinned(&crowd[799]).is_some());

    w.save_pins(alice).await;
    assert_eq!(pin_pages(&w, me).await, 2);
    let frame = w.relay.vault(me).await.unwrap();
    assert!(
        frame.iter().map(|b| b.v.len()).sum::<usize>() < 1024,
        "the sign-in frame holds an index, not 800 people"
    );

    let memory = w.devices[alice].sync.memory();
    assert!(memory.vault_gens.contains_key("pins.1"));
    w.devices[alice].online = false;
    let again = w.sign_in_again(0, memory).await;
    assert!(!w.devices[again].sync.pins_in());
    assert!(w.devices[again].sync.pinned(&crowd[0]).is_none());
    w.deliver(again, swapped(crowd[0], ""));
    w.deliver(again, swapped(crowd[799], ""));
    assert!(
        !w.log.iter().any(|l| matches!(l, Line::Warned { .. })),
        "decided on no pins"
    );

    w.pump().await;
    assert!(w.devices[again].sync.pins_in());
    let warned: Vec<Id> = w
        .log
        .iter()
        .filter_map(|l| match l {
            Line::Warned { device, account } if *device == again => Some(*account),
            _ => None,
        })
        .collect();
    assert_eq!(warned, [crowd[0], crowd[799]], "both pages, once each");
    assert!(w.devices[again].sync.pinned(&crowd[400]).is_some());
    // A change goes at once: both pages and then the index are stored by now
    let held = w.relay.vault_page(me, "pins.1").await.unwrap();
    let AccountReply::VaultPageFound { blob: Some(b), .. } = held else {
        panic!("page 1 is there");
    };
    assert_eq!(b.version, 2);
    w.post(again, "two").await;
    assert_eq!(
        w.texts(again),
        ["one", "two"],
        "its own posts read back once, for the front end to hold by their ids, as no news"
    );
}

/// A relay that hands a page from before: the device that saw the newer one says so, and
/// what the relay holds is not written over.
#[tokio::test]
async fn a_relay_handing_an_old_page_is_told_of_and_not_saved_over() {
    let mut w = World::new().await;
    let alice = w.person().await;
    w.join(alice).await;
    let crowd = w.crowd(CONV, 3).await;
    w.post(alice, "one").await;
    w.save_pins(alice).await;
    let me = AccountId(w.id(alice));
    let AccountReply::VaultPageFound {
        blob: Some(old), ..
    } = w.relay.vault_page(me, "pins.0").await.unwrap()
    else {
        panic!("no page");
    };
    // A change saves over it, and this device has seen that one
    w.deliver(alice, swapped(crowd[0], ""));
    w.pump().await;
    let memory = w.devices[alice].sync.memory();
    w.devices[alice].online = false;
    let again = w.sign_in_again(0, memory).await;
    w.tamper = Some(Box::new(move |_, req, reply| {
        if matches!(req, AccountRequest::VaultPage { .. }) {
            *reply = AccountReply::VaultPageFound {
                k: "pins.0".into(),
                blob: Some(old.clone()),
            };
        }
        true
    }));
    w.pump().await;
    assert!(w.log.contains(&Line::Problem {
        device: again,
        problem: "older",
    }));
    let s = w.devices[again].sync.flush_pins();
    assert!(s.is_empty(), "saved over a page it will not trust: {s:?}");
}

/// Past half a setting's seats, a silent follow is refused and asking is not; past the setting
/// nobody is. A writer's first post reaches all 5000, each named, and its pins come back on
/// their pages at the next sign-in.
#[tokio::test]
async fn a_setting_of_5000_seats_truly_works() {
    let mut w = World::with(|c| c.kept_seats = 5000).await;
    let (alice, bob, carol, dave) = (
        w.person().await,
        w.person().await,
        w.person().await,
        w.person().await,
    );
    w.join(alice).await;
    w.join(bob).await;
    let mut crowd = w.crowd(CONV, 2498).await;
    let convs = vec![CONV.to_string()];
    let (silent, _) = log::join_many(&w.relay, AccountId(w.id(carol)), &convs, &[true])
        .await
        .unwrap();
    assert!(
        matches!(&silent, AccountReply::LogJoinedMany { joined, .. } if joined.is_empty()),
        "half of them follow silently: {silent:?}"
    );
    w.join(carol).await;
    assert!(
        !w.log.iter().any(|l| matches!(l, Line::NotKept { .. })),
        "asking goes past the half"
    );
    crowd.extend(w.crowd(CONV, 2499).await);
    let (full, _) = log::join(&w.relay, AccountId(w.id(dave)), CONV, true)
        .await
        .unwrap();
    assert!(matches!(full, AccountReply::Error { .. }), "{full:?}");

    w.post(alice, "one").await;
    assert!(
        !w.log.iter().any(|l| matches!(l, Line::NotKept { .. })),
        "{:?}",
        w.log.iter().rev().take(4).collect::<Vec<_>>()
    );
    assert_eq!(w.named(alice).len(), 4999, "everyone named, before a seal");
    assert!(w.live_buckets(alice, CONV).await.len() >= 4999 / 62);
    w.read(bob).await;
    assert_eq!(w.texts(bob), ["one"]);

    w.save_pins(alice).await;
    let me = AccountId(w.id(alice));
    let pages = pin_pages(&w, me).await;
    assert!(pages >= 7, "at about 650 a page: {pages}");
    let memory = w.devices[alice].sync.memory();
    w.devices[alice].online = false;
    let again = w.sign_in_again(0, memory).await;
    w.pump().await;
    for who in [crowd[0], crowd[2500], crowd[crowd.len() - 1]] {
        assert!(w.devices[again].sync.pinned(&who).is_some());
    }
    w.post(again, "two").await;
    w.read(bob).await;
    assert_eq!(w.texts(bob), ["one", "two"]);
}

/// More joiners wait for a writer away than one index carries: the rest come once those are
/// answered, not at the next connect. A joiner nobody can answer does not go round for ever.
#[tokio::test]
async fn joiners_past_one_index_are_asked_for_again() {
    let mut w = World::new().await;
    let alice = w.person().await;
    w.join(alice).await;
    w.sharing(alice, true);
    w.post(alice, "one").await;
    w.devices[alice].online = false;
    w.crowd(CONV, 2060).await;
    let pending = "SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_pending";
    assert_eq!(w.rows(pending).await, 2060);

    let memory = w.devices[alice].sync.memory();
    let again = w.sign_in_again(0, memory).await;
    w.sharing(again, true);
    w.pump().await;
    assert_eq!(w.rows(pending).await, 12, "one index's worth");
    let (s, events) = w.devices[again].sync.tick();
    w.devices[again].out.extend(s);
    w.record(again, events);
    w.pump().await;
    assert_eq!(w.rows(pending).await, 0, "and the rest");
    w.log.clear();
    let (s, _) = w.devices[again].sync.tick();
    w.devices[again].out.extend(s);
    w.pump().await;
    assert!(
        !w.log
            .iter()
            .any(|l| matches!(l, Line::Sent { what, .. } if what == "LogIndex")),
        "nothing more to ask for"
    );
}

/// Pages of ids let a relay name any number of people, and a writer would upload a row to
/// each. It stops where the pins do, and what waited goes unkept with a word.
#[tokio::test]
async fn a_relay_naming_too_many_seats_is_refused() {
    let mut w = World::new().await;
    let alice = w.person().await;
    w.join(alice).await;
    let mut next = 0u64;
    w.tamper = Some(Box::new(move |_, req, reply| {
        if let AccountRequest::LogMemberIds { conv, .. } = req {
            let ids = (0..2048)
                .map(|i| id_of(50_000_000 + next + i))
                .collect::<Vec<_>>();
            next += 2048;
            *reply = AccountReply::LogMemberIdsFound {
                conv: conv.clone(),
                ids,
                more: true,
            };
        }
        true
    }));
    w.post(alice, "one").await;
    let asked = w
        .log
        .iter()
        .filter(|l| matches!(l, Line::Sent { what, .. } if what == "LogMemberIds"))
        .count();
    assert_eq!(asked, 16, "32,000 and no further");
    assert!(w.puts.is_empty(), "a row for someone made up");
    assert!(w
        .log
        .iter()
        .any(|l| matches!(l, Line::NotKept { reason, .. } if reason.contains("readers"))));
}

// ── A sharer's answer to joiners ─────────────────────────────────────────

/// A writer with `chains` chains no link reaches (kept with the switch off), the switch on
/// now, and someone new waiting for its answer to come in frames. They read after each.
async fn an_answer_in_frames(chains: usize) -> (World, usize, usize, usize) {
    let mut w = World::new().await;
    let (alice, bob) = (w.person().await, w.person().await);
    w.join(alice).await;
    w.join(bob).await;
    for i in 0..chains {
        w.post(alice, &format!("chain {i}")).await;
        w.leave(bob).await;
        w.post(alice, &format!("chain {i}, alone")).await;
        w.join(bob).await;
    }
    w.sharing(alice, true);
    log::set_shares(w.relay.store(), &w.id(alice), true)
        .await
        .unwrap();
    let fred = w.person().await;
    w.reader = Some(fred);
    (w, alice, bob, fred)
}

fn all_of(mut got: Vec<&str>) -> Vec<String> {
    got.sort_unstable();
    got.dedup();
    got.into_iter().map(str::to_string).collect()
}

/// The joiner waits until the last frame of the answer, whenever it reads: told at the
/// first, it read past the chains with no row yet, and no later frame told it again.
#[tokio::test]
async fn a_sharers_answer_counts_at_its_last_frame_and_the_reader_loses_nothing() {
    let (mut w, alice, _, fred) = an_answer_in_frames(4).await;
    w.join(fred).await;
    assert!(w.waiting_after.len() > 2, "{:?}", w.waiting_after);
    let (last, before) = w.waiting_after.split_last().unwrap();
    assert!(before.iter().all(|n| *n == 1), "{:?}", w.waiting_after);
    assert_eq!(*last, 0);
    w.reader = None;
    w.read(fred).await;
    let want: Vec<String> = (0..4)
        .flat_map(|i| [format!("chain {i}"), format!("chain {i}, alone")])
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    assert_eq!(all_of(w.texts(fred)), want);
    assert!(w.named(alice).contains(&w.id(fred)));
}

/// An answer cut off at the second frame: still waiting, so the next `LogIndex` answers it
/// again, whole, and then it counts.
#[tokio::test]
async fn an_answer_cut_off_is_answered_again_at_the_next_index() {
    let (mut w, alice, _, fred) = an_answer_in_frames(3).await;
    let mut frames = 0;
    w.tamper = Some(Box::new(move |_, req, _| {
        if matches!(req, AccountRequest::ChainPut { .. }) {
            frames += 1;
            return frames < 2;
        }
        true
    }));
    w.join(fred).await;
    w.tamper = None;
    assert_eq!(w.rows("SELECT COUNT(*) FROM voipc_pending").await, 1);
    let before = w.devices[fred].texts.len();
    assert!(before < 6, "some of it: {before}");
    // The app goes, and comes back
    let memory = w.devices[alice].sync.memory();
    w.devices[alice].online = false;
    let again = w.sign_in_again(alice, memory).await;
    w.sharing(again, true);
    w.pump().await;
    assert_eq!(w.rows("SELECT COUNT(*) FROM voipc_pending").await, 0);
    w.reader = None;
    w.read(fred).await;
    assert_eq!(all_of(w.texts(fred)).len(), 6);
}

/// An answer lost in this run: what is left goes round again at the ticks, and it does the
/// same when someone's leave ends the chain in the middle of it.
#[tokio::test]
async fn the_rest_of_an_answer_goes_round_again_in_the_same_run() {
    for told_of_a_leave in [false, true] {
        let (mut w, alice, bob, fred) = an_answer_in_frames(3).await;
        let mut frames = 0;
        w.tamper = Some(Box::new(move |_, req, _| {
            if matches!(req, AccountRequest::ChainPut { .. }) {
                frames += 1;
                return frames != 2;
            }
            true
        }));
        w.join(fred).await;
        w.tamper = None;
        assert_eq!(w.rows("SELECT COUNT(*) FROM voipc_pending").await, 1);
        if told_of_a_leave {
            let gone = w.id(bob);
            w.devices[alice].sync.member_gone(CONV, Some(gone));
        }
        for _ in 0..4 {
            let (s, events) = w.devices[alice].sync.tick();
            w.devices[alice].out.extend(s);
            w.record(alice, events);
            w.pump().await;
        }
        assert_eq!(
            w.rows("SELECT COUNT(*) FROM voipc_pending").await,
            0,
            "told of a leave: {told_of_a_leave}"
        );
        w.reader = None;
        w.read(fred).await;
        assert_eq!(
            all_of(w.texts(fred)).len(),
            6,
            "told of a leave: {told_of_a_leave}"
        );
    }
}

/// Past what a frame holds, on both roads: rows of chains, and keys of a version before
/// chains. The harness encodes every frame, so one too long fails here as it would at the
/// relay, which ends the connection at it, voice included, at every connect.
#[tokio::test]
async fn an_answer_to_many_joiners_is_split_on_every_road() {
    let mut w = World::new().await;
    let alice = w.person().await;
    w.join(alice).await;
    w.sharing(alice, true);
    w.old_entry(alice, &[], "from before").await;
    w.post(alice, "one").await;
    w.devices[alice].online = false;
    w.crowd(CONV, 900).await;
    assert_eq!(w.rows("SELECT COUNT(*) FROM voipc_pending").await, 900);
    let memory = w.devices[alice].sync.memory();
    let again = w.sign_in_again(0, memory).await;
    w.sharing(again, true);
    w.log.clear();
    w.pump().await;
    assert_eq!(w.rows("SELECT COUNT(*) FROM voipc_pending").await, 0);
    assert_eq!(
        w.rows("SELECT COUNT(*) FROM voipc_chain_wraps").await,
        900,
        "a row each"
    );
    assert_eq!(
        w.rows("SELECT COUNT(*) FROM voipc_wraps").await,
        901,
        "and the old key each, beside its writer's"
    );
    let sent = |what: &str| {
        w.log
            .iter()
            .filter(|l| matches!(l, Line::Sent { what: s, .. } if s == what))
            .count()
    };
    assert!(sent("EpochPut") >= 2, "{}", sent("EpochPut"));
    assert!(sent("ChainPut") >= 2, "{}", sent("ChainPut"));
    assert!(!w.log.iter().any(|l| matches!(l, Line::NotKept { .. })));
}

// ── Someone a writer cannot reach ────────────────────────────────────────

impl World {
    /// Someone seated with no log key, by asking or by following; their app comes later.
    async fn seated_with_no_key(&mut self, follows: bool) -> usize {
        let d = self.person().await;
        self.devices[d].online = false;
        let me = AccountId(self.id(d));
        db!(self.relay.store(), pool => {
            sqlx::query("DELETE FROM voipc_logkeys WHERE account = $1")
                .bind(&me.0[..])
                .execute(pool)
                .await
                .unwrap();
        });
        let joined = if follows {
            let convs = [CONV.to_string()];
            log::join_many(&self.relay, me, &convs, &[true])
                .await
                .unwrap()
                .0
        } else {
            log::join(&self.relay, me, CONV, true).await.unwrap().0
        };
        assert!(
            !matches!(joined, AccountReply::Error { .. }),
            "a seat takes no key: {joined:?}"
        );
        d
    }

    fn not_kept(&self) -> usize {
        self.log
            .iter()
            .filter(|l| matches!(l, Line::NotKept { .. }))
            .count()
    }
}

/// One member with no key stopped every writer's kept posts. They get a row that opens for
/// nobody, at the index of the post, and are named to nobody. Their first key makes that a
/// missing row, and the next post brings a real one, named.
#[tokio::test]
async fn a_member_with_no_log_key_stops_nobody_and_a_key_brings_a_real_row() {
    for follows in [false, true] {
        let mut w = World::new().await;
        let (alice, bob) = (w.person().await, w.person().await);
        w.join(alice).await;
        w.join(bob).await;
        let m = w.seated_with_no_key(follows).await;
        let m_id = w.id(m);
        w.post(alice, "one").await;
        w.post(bob, "from bob").await;
        w.puts.clear();
        w.post(alice, "two").await;
        assert!(w.puts.is_empty(), "no more keys for a post with nobody new");
        assert_eq!(w.not_kept(), 0, "{:?}", w.log);
        assert!(!w.named(alice).contains(&m_id) && !w.named(bob).contains(&m_id));
        assert_eq!(
            w.rows("SELECT COUNT(*) FROM voipc_chain_wraps").await,
            2,
            "one from each writer"
        );
        w.read(bob).await;
        assert_eq!(w.texts(bob), ["one", "from bob", "two"]);

        // Their app comes, and publishes
        w.devices[m].online = true;
        w.join(m).await;
        assert_eq!(
            w.rows("SELECT COUNT(*) FROM voipc_chain_wraps WHERE dead = FALSE")
                .await,
            0,
            "nothing they could open counts as a row now"
        );
        w.post(alice, "three").await;
        assert!(w.named(alice).contains(&m_id), "named once it can read");
        w.read(m).await;
        assert_eq!(w.texts(m), ["three"], "from there on");
        assert!(w.log.contains(&Line::Unopened { device: m }));
        assert_eq!(w.not_kept(), 0, "{:?}", w.log);
    }
}

/// A key the relay holds back, or one its identity never signed, comes to the same: posts go
/// on. The reader sees nothing new: that writer's posts count as unopened, and its cursor
/// does not stick on them. Each new chain asks for the key again, so a real one means a seat.
#[tokio::test]
async fn a_member_a_writer_does_not_trust_stops_nobody_and_reads_nothing_of_theirs() {
    for junk in [false, true] {
        let mut w = World::new().await;
        let (alice, bob, m) = (w.person().await, w.person().await, w.person().await);
        for d in [alice, bob, m] {
            w.join(d).await;
        }
        let m_id = w.id(m);
        w.tamper = Some(Box::new(move |_, _, reply| {
            if let AccountReply::LogKeysFound { keys } = reply {
                if junk {
                    keys.iter_mut()
                        .filter(|k| k.account == m_id)
                        .for_each(|k| k.sig = vec![7; 64]);
                } else {
                    keys.retain(|k| k.account != m_id);
                }
            }
            true
        }));
        w.post(alice, "one").await;
        w.post(alice, "two").await;
        assert_eq!(w.not_kept(), 0, "{:?}", w.log);
        assert!(!w.named(alice).contains(&m_id));
        w.read(m).await;
        assert!(w.texts(m).is_empty(), "{:?}", w.texts(m));
        assert!(w.log.contains(&Line::Unopened { device: m }));
        assert!(
            w.devices[m].sync.memory().cursors[CONV] >= 2,
            "read past them"
        );
        w.read(bob).await;
        assert_eq!(w.texts(bob), ["one", "two"]);

        // The relay gives it after all, and someone leaves
        w.tamper = None;
        w.leave(bob).await;
        w.post(alice, "three").await;
        assert_eq!(w.last_epoch(alice).0, 2);
        assert!(w.named(alice).contains(&m_id), "named at the new chain");
        w.read(m).await;
        assert_eq!(w.texts(m), ["three"]);
    }
}

/// A joiner a sharer cannot reach is not a wait for ever: its answer ends it, with nothing
/// handed over and nobody named.
#[tokio::test]
async fn a_sharer_ends_the_wait_of_a_joiner_it_cannot_reach() {
    let (mut w, alice, _, _) = an_answer_in_frames(2).await;
    w.reader = None;
    let m = w.seated_with_no_key(false).await;
    let m_id = w.id(m);
    assert_eq!(w.rows("SELECT COUNT(*) FROM voipc_pending").await, 1);
    w.deliver(
        alice,
        AccountReply::LogPending {
            conv: CONV.to_string(),
            joiners: vec![m_id],
        },
    );
    w.pump().await;
    assert_eq!(w.rows("SELECT COUNT(*) FROM voipc_pending").await, 0);
    assert!(!w.named(alice).contains(&m_id));
    w.post(alice, "on").await;
    assert_eq!(w.not_kept(), 0, "{:?}", w.log);
}

// ── A post that cannot go ────────────────────────────────────────────────

/// Back in a channel before the wait is over, and a post: the wait itself is quiet, the
/// post lost to it is not.
#[tokio::test]
async fn a_post_during_a_wait_for_a_seat_is_told() {
    let mut w = World::new().await;
    let (alice, bob) = (w.person().await, w.person().await);
    w.join(alice).await;
    w.join(bob).await;
    w.post(alice, "one").await;
    let s = w.devices[bob].sync.leave(CONV, true);
    w.devices[bob].out.extend(s);
    w.pump().await;
    w.log.clear();
    w.post(bob, "while waiting").await;
    assert_eq!(w.not_kept(), 1, "{:?}", w.log);
    assert!(w.devices[bob].sync.copy_refused());
    assert_eq!(
        w.rows("SELECT COUNT(*) FROM voipc_log WHERE sender = x'aaaaaaaaaaaaaaaa0000000000000002'")
            .await,
        0
    );
    db!(w.relay.store(), pool => {
        sqlx::query("DELETE FROM voipc_left").execute(pool).await.unwrap();
    });
    w.post(bob, "after").await;
    assert_eq!(w.not_kept(), 1);
    assert!(!w.devices[bob].sync.copy_refused());
}

/// A follow stops at half a log's seats, and a post is the other way to one: written as the
/// follow is refused, it takes the seat and is kept.
#[tokio::test]
async fn a_post_as_a_follow_is_refused_takes_a_seat_by_asking() {
    let mut w = World::with(|c| c.kept_seats = 2).await;
    let (alice, carol) = (w.person().await, w.person().await);
    w.join(alice).await;
    w.pump().await;
    let follow = w.devices[carol].sync.enter_many(&[CONV.to_string()]);
    w.devices[carol].out.extend(follow);
    w.next_at += 1;
    let env = envelope("the post", "written at once", None);
    let post = w.devices[carol]
        .sync
        .send_channel(CONV, env, w.next_at, None);
    w.devices[carol].out.extend(post);
    w.pump().await;
    assert_eq!(w.not_kept(), 0, "{:?}", w.log);
    let (s, events) = w.devices[carol].sync.tick();
    w.devices[carol].out.extend(s);
    w.record(carol, events);
    w.pump().await;
    assert_eq!(w.not_kept(), 0, "{:?}", w.log);
    w.read(alice).await;
    assert_eq!(w.texts(alice), ["written at once"]);
}

/// The relay's answer to a post lost on a full queue: what comes after waits behind it, and
/// goes on once it has aged out, with a word for what was given up.
#[tokio::test]
async fn one_lost_answer_to_a_post_does_not_stop_the_posts_after_it() {
    let mut w = World::new().await;
    let (alice, bob) = (w.person().await, w.person().await);
    w.join(alice).await;
    w.join(bob).await;
    w.post(alice, "stored").await;
    let mut lost = false;
    w.tamper = Some(Box::new(move |_, _, reply| {
        if matches!(reply, AccountReply::LogAppended { .. }) && !lost {
            lost = true;
            return false;
        }
        true
    }));
    w.post(alice, "its answer is lost").await;
    w.tamper = None;
    // Someone new, so the next post is refused: that refusal answers the wrong one
    let fred = w.person().await;
    w.join(fred).await;
    w.log.clear();
    w.post(alice, "refused").await;
    assert_eq!(w.not_kept(), 0, "not yet");
    let mut ticks = 0;
    while w.not_kept() == 0 {
        ticks += 1;
        assert!(ticks <= 15, "aged out at about 30 s");
        let (s, events) = w.devices[alice].sync.tick();
        w.devices[alice].out.extend(s);
        w.record(alice, events);
        w.pump().await;
    }
    assert!(
        ticks > 3,
        "slower than a read: sent again, it is kept twice"
    );
    assert_eq!(w.not_kept(), 1);
    w.post(alice, "after").await;
    assert_eq!(w.not_kept(), 1, "{:?}", w.log);
    w.read(fred).await;
    assert!(w.texts(fred).contains(&"after"), "{:?}", w.texts(fred));
    w.read(bob).await;
    assert!(w.texts(bob).contains(&"after"), "{:?}", w.texts(bob));
}

/// Several posts out at one refusal come back one by one: none goes again until the last
/// has, or each is sent again behind the next and the refusal never settles.
#[tokio::test]
async fn posts_out_together_at_a_refusal_settle_and_go_in_order() {
    let mut w = World::new().await;
    let (alice, bob) = (w.person().await, w.person().await);
    w.join(alice).await;
    w.join(bob).await;
    w.post(alice, "one").await;
    let fred = w.person().await;
    w.join(fred).await;
    for text in ["two", "three", "four"] {
        w.next_at += 1;
        let env = envelope(&format!("m{}", w.next_at), text, None);
        let s = w.devices[alice]
            .sync
            .send_channel(CONV, env, w.next_at, None);
        w.devices[alice].out.extend(s);
    }
    w.pump().await;
    assert_eq!(w.not_kept(), 0, "{:?}", w.log);
    w.read(bob).await;
    assert_eq!(w.texts(bob), ["one", "two", "three", "four"]);
    w.read(fred).await;
    assert_eq!(w.texts(fred), ["two", "three", "four"]);
}

// ── Who left, and what it costs ──────────────────────────────────────────

/// Gone while this device was away, which it learns only from the relay's refusal: with
/// nothing telling it by hand, it forgets it named them, and names them when they are back.
/// By a seat, and by a row of their own.
#[tokio::test]
async fn someone_gone_while_a_writer_was_away_is_named_again_when_back() {
    let mut w = World::new().await;
    let (alice, fred, cy) = (w.person().await, w.person().await, w.person().await);
    for d in [alice, fred, cy] {
        w.join(d).await;
    }
    w.post(alice, "one").await;
    let gone = w.id(fred);
    let named = |w: &World, who: Id| w.named(alice).iter().filter(|a| **a == who).count();
    assert_eq!(named(&w, gone), 1);

    w.devices[alice].online = false;
    w.leave(fred).await;
    w.devices[alice].online = true;
    w.post(alice, "two").await;
    assert_eq!(w.last_epoch(alice).0, 2);
    assert!(!w.devices[alice].sync.memory().readers[CONV].contains(&gone));
    w.join(fred).await;
    w.post(alice, "three").await;
    assert_eq!(named(&w, gone), 2, "by a seat they lost");

    // Fred holds only a row now
    w.devices[alice].online = false;
    w.leave(fred).await;
    w.devices[alice].online = true;
    w.post(alice, "four").await;
    assert!(!w.devices[alice].sync.memory().readers[CONV].contains(&gone));
    w.join(fred).await;
    w.post(alice, "five").await;
    assert_eq!(named(&w, gone), 3, "by a row of their own");
    w.read(fred).await;
    assert!(w.texts(fred).contains(&"five"));
}

/// A leave spends every writer's budget of new chains, so only someone it could have reached
/// ends one: not a guest, and not someone with an account who was only in the channel's list.
#[tokio::test]
async fn a_leave_of_someone_with_no_seat_ends_no_chain() {
    let mut w = World::new().await;
    let (alice, bob) = (w.person().await, w.person().await);
    w.join(alice).await;
    w.join(bob).await;
    w.post(alice, "one").await;
    let named = w.devices[alice].sync.memory().named[CONV].clone();
    w.devices[alice].sync.member_gone(CONV, None);
    w.devices[alice].sync.member_gone(CONV, Some(id_of(99)));
    w.puts.clear();
    w.post(alice, "two").await;
    assert_eq!(w.last_epoch(alice), (1, 0), "the same chain");
    assert!(w.puts.is_empty());
    assert_eq!(w.devices[alice].sync.memory().named[CONV], named);
    let gone = w.id(bob);
    w.devices[alice].sync.member_gone(CONV, Some(gone));
    w.post(alice, "three").await;
    assert_eq!(w.last_epoch(alice).0, 2, "and someone it reached does");
}

// ── A leaver's own keys ──────────────────────────────────────────────────

/// Row 12 with the leaver's real keys in hand and every row of the next chain, as a database
/// copy gives them: their log key, the bucket key from their seat, the chain's start from
/// the seal. Not a read refused for lack of a row, but each key tried on each row. The
/// control is that the same keys do open the chain they were given.
#[tokio::test]
async fn a_leavers_own_keys_open_nothing_of_the_next_chain() {
    let mut w = World::new().await;
    let (alice, bob, cy) = (w.person().await, w.person().await, w.person().await);
    for d in [alice, bob, cy] {
        w.join(d).await;
    }
    w.post(alice, "while here").await;
    let (a_id, b_id) = (w.id(alice), w.id(bob));
    let first = last_entry(&w, alice).await;
    assert_eq!(epoch_parts(first.epoch), (1, 0));

    let signed = &w.accounts[bob];
    let item = signed.vault.open_item(&signed.blobs, ITEM_LOGKEY).unwrap();
    let bob_key = LogKey::from_bytes(&item.payload).unwrap();
    let AccountReply::LogKeysFound { keys } = log::keys(&w.relay, &[a_id]).await.unwrap() else {
        panic!()
    };
    let alice_public = keys[0].logkey.clone();
    let shared = StaticKey::new(&bob_key, &alice_public).unwrap();

    type SeatRow = (i64, i32, Vec<u8>);
    let (bucket, version, seat): SeatRow = db!(w.relay.store(), pool => {
        sqlx::query_as("SELECT bucket, version, wrapped FROM voipc_seats WHERE recipient = $1")
            .bind(&b_id[..])
            .fetch_one(pool)
            .await
            .unwrap()
    });
    let (bucket, version) = (bucket as u64, version as u32);
    let at = |version: u32| Bucket {
        conv: CONV,
        owner: &a_id,
        id: bucket,
        version,
    };
    let bucket_key = shared.open_seat(&seat, at(version), &b_id).unwrap();
    type SealRow = (i64, i32, i16, Vec<u8>);
    let seals = async |w: &World, chain: i32| -> Vec<SealRow> {
        db!(w.relay.store(), pool => {
            sqlx::query_as(
                "SELECT s.bucket, s.version, s.idx, s.sealed FROM voipc_seals s
                   JOIN voipc_chains c ON c.id = s.chain_id WHERE c.chain = $1",
            )
            .bind(chain)
            .fetch_all(pool)
            .await
            .unwrap()
        })
    };
    let held = seals(&w, 1).await;
    let (_, _, index, sealed) = &held[0];
    let start = at(version)
        .open_seal(&bucket_key, 1, *index as u32, sealed)
        .expect("the control: their keys open what they were given");
    assert!(open_chain_entry(&start, CONV, &a_id, first.epoch, &alice_public, &first.ct).is_ok());

    w.leave(bob).await;
    w.post(alice, "after").await;
    let next = last_entry(&w, alice).await;
    let (chain, top) = epoch_parts(next.epoch);
    assert_eq!(chain, 2, "a new chain");

    // The state they hold, on what it wrote next
    assert!(
        open_chain_entry(&start, CONV, &a_id, next.epoch, &alice_public, &next.ct).is_err(),
        "the next chain's post under the state they held"
    );
    // The bucket key they hold, on every seal of the next chain, at every version
    let later = seals(&w, chain as i32).await;
    assert!(!later.is_empty());
    for (id, v, index, sealed) in &later {
        for version in [*v as u32, version] {
            let at = Bucket {
                conv: CONV,
                owner: &a_id,
                id: *id as u64,
                version,
            };
            assert!(
                at.open_seal(&bucket_key, chain, *index as u32, sealed)
                    .is_err(),
                "a seal of the next chain under the bucket key they held"
            );
            assert!(
                at.open_seal(&start, chain, *index as u32, sealed).is_err(),
                "or under the state"
            );
        }
    }
    // Their log key, on every row with their name that is not theirs, and on the others' seats
    let rows: Vec<(Vec<u8>, i64, i32, Vec<u8>)> = db!(w.relay.store(), pool => {
        sqlx::query_as("SELECT recipient, bucket, version, wrapped FROM voipc_seats")
            .fetch_all(pool)
            .await
            .unwrap()
    });
    for (recipient, id, v, row) in &rows {
        let at = Bucket {
            conv: CONV,
            owner: &a_id,
            id: *id as u64,
            version: *v as u32,
        };
        let theirs = recipient.as_slice() == b_id && *v as u32 == version;
        assert_eq!(
            shared.open_seat(row, at, &b_id).is_ok(),
            theirs,
            "a seat at version {v}"
        );
    }
    // The steps walk up from a state of that chain, and from nothing they hold
    let walker = Chain {
        conv: CONV,
        owner: &a_id,
        chain,
    };
    let steps: Vec<(i16, Vec<u8>)> = db!(w.relay.store(), pool => {
        sqlx::query_as(
            "SELECT s.idx, s.sealed FROM voipc_chain_steps s
               JOIN voipc_chains c ON c.id = s.chain_id WHERE c.chain = $1",
        )
        .bind(chain as i32)
        .fetch_all(pool)
        .await
        .unwrap()
    });
    for (i, row) in &steps {
        assert!(walker.follow(*i as u32, &start, row).is_err());
    }
    assert_eq!(top, 0, "nothing else went on it");
}

// ── An own post, and what a crash leaves ─────────────────────────────────

/// A post's cursor reaches disk ahead of the post, whose save waits in the front end. Quit in
/// between, and the post is on no screen of this device: it reads back at the next run.
#[tokio::test]
async fn an_own_post_reads_back_after_an_exit_with_no_save() {
    let mut w = World::new().await;
    let (alice, bob) = (w.person().await, w.person().await);
    w.join(alice).await;
    w.join(bob).await;
    w.post(alice, "the first of all").await;
    let memory = w.devices[alice].sync.memory();
    assert_eq!(
        memory.cursors.get(CONV).copied().unwrap_or(0),
        0,
        "a post moves no cursor"
    );
    w.devices[alice].online = false;
    let again = w.device_of(alice, memory);
    w.read(again).await;
    assert_eq!(w.texts(again), ["the first of all"]);
    // Read back once: the cursor is past it now
    let memory = w.devices[again].sync.memory();
    assert!(memory.cursors[CONV] >= 1);
    w.devices[again].online = false;
    let third = w.device_of(alice, memory);
    w.read(third).await;
    assert!(w.texts(third).is_empty());
}
