//! A stand-in Discord: no socket and no real host, so nothing that uses this can reach the
//! real one. It answers routes from a map of file names to bytes (`testkit/6-mock-discord`,
//! which is written from Discord's docs and is not a copy of anything Discord sent), and
//! pages the way the docs say. Whoever holds the files loads them: this crate touches no disk.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::sync::{Mutex, MutexGuard};

use serde_json::{json, Value};

use crate::api::{Method, Req, Resp, Transport, BASE};

/// The guild `big` makes.
pub const BIG_GUILD: u64 = 1_190_000_000_000_000_001;
/// Its bot.
pub const BIG_BOT: u64 = 1_190_000_000_000_000_002;
const BIG_MANAGED_ROLE: u64 = 1_190_000_000_000_000_099;
const BIG_ROLES: u64 = 1_190_000_000_000_010_000;
const BIG_CHANNELS: u64 = 1_190_000_000_000_020_000;
/// The first member it makes, and who `add_messages` writes as.
pub const BIG_MEMBERS: u64 = 1_190_000_000_100_000_000;
const BIG_BANS: u64 = 1_190_000_000_900_000_000;
/// Where `add_messages` starts.
const ADDED_MESSAGES: u64 = 1_200_000_000_100_000_000;

/// An answer that replaces the usual one.
#[derive(Debug, Clone)]
pub struct Scripted {
    /// Any path starting with this.
    pub route: String,
    /// On this call to it, counted from 1.
    pub nth: u64,
    /// And on every call after.
    pub always: bool,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Scripted {
    pub fn new(route: &str, nth: u64, status: u16, headers: &[(&str, &str)], body: &str) -> Self {
        Scripted {
            route: route.to_string(),
            nth,
            always: false,
            status,
            headers: headers
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect(),
            body: body.as_bytes().to_vec(),
        }
    }

    pub fn always(mut self) -> Self {
        self.always = true;
        self
    }
}

#[derive(Default)]
struct State {
    v2: bool,
    requests: u64,
    non_gets: u64,
    posted: Vec<Vec<u8>>,
    nonces: HashSet<String>,
    asked: Vec<String>,
    per_route: HashMap<String, u64>,
    script: Vec<Scripted>,
    added: HashMap<u64, Vec<Value>>,
    denied: HashMap<u64, u64>,
    indexing: HashSet<String>,
}

/// How many members and bans `big` answers for, made as they are asked for.
#[derive(Clone, Copy)]
struct Big {
    members: u64,
    bans: u64,
}

pub struct Mock {
    files: BTreeMap<String, Vec<u8>>,
    big: Option<Big>,
    state: Mutex<State>,
}

fn id_of(value: &Value) -> u64 {
    value["id"]
        .as_str()
        .or(value["user"]["id"].as_str())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn json_resp(status: u16, value: &Value) -> Resp {
    Resp {
        status,
        headers: Vec::new(),
        body: value.to_string().into_bytes(),
    }
}

fn not_found() -> Resp {
    json_resp(404, &json!({ "message": "404: Not Found", "code": 0 }))
}

/// `limit` rows after `after`, ascending by id, as Discord pages members and bans.
fn page_up(mut rows: Vec<Value>, after: u64, limit: usize) -> Vec<Value> {
    rows.retain(|r| id_of(r) > after);
    rows.sort_by_key(id_of);
    rows.truncate(limit);
    rows
}

impl Mock {
    pub fn new(files: BTreeMap<String, Vec<u8>>) -> Self {
        Mock {
            files,
            big: None,
            state: Mutex::default(),
        }
    }

    /// A server of any size with nothing committed for it: thousands of rows are made here,
    /// and members and bans only as they are asked for, so a million costs nothing.
    pub fn big(members: u64, bans: u64, roles: u64, channels: u64) -> Self {
        let id = |n: u64| n.to_string();
        let basics: u64 = (1 << 10) | (1 << 11) | (1 << 16) | (1 << 20) | (1 << 21);
        let mut role_rows = vec![
            json!({ "id": id(BIG_GUILD), "name": "@everyone", "permissions": id(basics), "position": 0 }),
            json!({ "id": id(BIG_MANAGED_ROLE), "name": "Importer", "permissions": "8",
                    "position": 1, "managed": true }),
        ];
        let mut counts = serde_json::Map::new();
        for i in 0..roles {
            role_rows.push(
                json!({ "id": id(BIG_ROLES + i), "name": format!("Role {i}"),
                                   "permissions": "0", "position": i + 2 }),
            );
            counts.insert(id(BIG_ROLES + i), json!(i + 1));
        }
        let channel_rows: Vec<Value> = (0..channels)
            .map(|i| {
                json!({ "id": id(BIG_CHANNELS + i), "type": 0, "name": format!("channel-{i}"),
                        "position": i, "permission_overwrites": [] })
            })
            .collect();
        let mut files = BTreeMap::new();
        let mut file = |name: &str, value: Value| {
            files.insert(name.to_string(), value.to_string().into_bytes());
        };
        file(
            "me.json",
            json!({ "id": id(BIG_BOT), "username": "importer", "bot": true }),
        );
        file(
            "app.json",
            json!({ "id": id(BIG_BOT), "name": "Importer", "flags": (1 << 15) | (1 << 19) }),
        );
        file(
            "guilds.json",
            json!([{ "id": id(BIG_GUILD), "name": "Big", "permissions": "8" }]),
        );
        file(
            "guild.json",
            json!({ "id": id(BIG_GUILD), "name": "Big", "owner_id": id(BIG_MEMBERS),
                    "approximate_member_count": members,
                    "approximate_presence_count": members / 4, "mfa_level": 0 }),
        );
        file(
            "bot-member.json",
            json!({ "user": { "id": id(BIG_BOT), "username": "importer", "bot": true },
                    "roles": [id(BIG_MANAGED_ROLE)] }),
        );
        file("roles.json", Value::Array(role_rows));
        file("role-counts.json", Value::Object(counts));
        file("channels.json", Value::Array(channel_rows));
        Mock {
            files,
            big: Some(Big { members, bans }),
            state: Mutex::default(),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Everything from now on is what a delta sees: `v2/` over the rest.
    pub fn use_v2(&self) {
        self.state().v2 = true;
    }

    pub fn script(&self, rule: Scripted) {
        self.state().script.push(rule);
    }

    /// `rate-script.json`, whose rules say which calls answer 429, 403 or 500.
    pub fn use_rate_script(&self) {
        let script: Value = self
            .files
            .get("rate-script.json")
            .and_then(|b| serde_json::from_slice(b).ok())
            .unwrap_or_default();
        for rule in script["rules"].as_array().into_iter().flatten() {
            let headers: Vec<(String, String)> = rule["headers"]
                .as_object()
                .into_iter()
                .flatten()
                .map(|(n, v)| (n.clone(), v.as_str().unwrap_or_default().to_string()))
                .collect();
            self.script(Scripted {
                route: rule["route"].as_str().unwrap_or_default().to_string(),
                nth: rule["nth"].as_u64().unwrap_or(1),
                always: rule["always"].as_bool().unwrap_or(false),
                status: rule["status"].as_u64().unwrap_or(500) as u16,
                headers,
                body: rule["body"].to_string().into_bytes(),
            });
        }
    }

    /// `count` more messages in `channel`, of `body_bytes` each, by one member: what the
    /// fixture would be silly to hold by hand. Newer than anything else it has.
    pub fn add_messages(&self, channel: u64, count: u64, body_bytes: usize) {
        let mut state = self.state();
        let rows = state.added.entry(channel).or_default();
        let first = ADDED_MESSAGES + rows.len() as u64;
        rows.extend((0..count).map(|i| {
            json!({ "id": (first + i).to_string(), "type": 0,
                    "author": { "id": BIG_MEMBERS.to_string(), "username": "member0" },
                    "content": "x".repeat(body_bytes) })
        }));
    }

    /// From now on `/channels` says `@everyone` is denied these on `channel`, as it would once
    /// someone has closed it. 0 lifts it.
    pub fn deny_everyone(&self, channel: u64, bits: u64) {
        self.state().denied.insert(channel, bits);
    }

    /// Every request so far.
    pub fn requests(&self) -> u64 {
        self.state().requests
    }

    /// Requests that were not a GET: only the move post may be one.
    pub fn non_gets(&self) -> u64 {
        self.state().non_gets
    }

    /// What was posted. A repeat of a nonce posts nothing, as `enforce_nonce` says.
    pub fn posted(&self) -> Vec<Vec<u8>> {
        self.state().posted.clone()
    }

    /// Every path asked, in order.
    pub fn asked(&self) -> Vec<String> {
        self.state().asked.clone()
    }

    fn file(&self, name: &str, v2: bool) -> Option<&[u8]> {
        if v2 {
            if let Some(bytes) = self.files.get(&format!("v2/{name}")) {
                return Some(bytes);
            }
        }
        self.files.get(name).map(Vec::as_slice)
    }

    fn answer_file(&self, name: &str, v2: bool) -> Resp {
        match self.file(name, v2) {
            Some(bytes) => Resp {
                status: 200,
                headers: Vec::new(),
                body: bytes.to_vec(),
            },
            None => not_found(),
        }
    }

    /// The JSON arrays of all files starting so, with `v2/`'s on top. Keyed by id: a row
    /// in a later file replaces one with its id.
    fn rows_of(&self, prefix: &str, key: Option<&str>, v2: bool) -> Vec<Value> {
        let mut rows: BTreeMap<u64, Value> = BTreeMap::new();
        let mut take = |bytes: &[u8]| {
            let value: Value = serde_json::from_slice(bytes).unwrap_or_default();
            let list = match key {
                Some(key) => value[key].clone(),
                None => value,
            };
            for row in list.as_array().into_iter().flatten() {
                rows.insert(id_of(row), row.clone());
            }
        };
        for (name, bytes) in self.files.range(prefix.to_string()..) {
            if !name.starts_with(prefix) {
                break;
            }
            take(bytes);
        }
        if v2 {
            let prefix = format!("v2/{prefix}");
            for (name, bytes) in self.files.range(prefix.clone()..) {
                if !name.starts_with(&prefix) {
                    break;
                }
                take(bytes);
            }
        }
        rows.into_values().collect()
    }

    /// One person, as `/guilds/{g}/members/{id}` has them: the bot's own file, a row of the
    /// list, or the 404 of someone who is not in the server.
    fn member(&self, id: &str, v2: bool) -> Resp {
        let bot = self
            .file("me.json", v2)
            .and_then(|b| serde_json::from_slice::<Value>(b).ok());
        if bot.is_some_and(|me| me["id"] == id) {
            return self.answer_file("bot-member.json", v2);
        }
        let id: u64 = id.parse().unwrap_or(0);
        let big = self
            .big
            .is_some_and(|b| (BIG_MEMBERS..BIG_MEMBERS + b.members).contains(&id));
        if big {
            let row = json!({ "user": { "id": id.to_string(), "username": format!("m{id}") },
                              "roles": [] });
            return json_resp(200, &row);
        }
        match self
            .rows_of("members-", None, v2)
            .iter()
            .find(|r| id_of(r) == id)
        {
            Some(row) => json_resp(200, row),
            None => not_found(),
        }
    }

    fn messages_of(&self, channel: u64, state: &State) -> Vec<Value> {
        let mut rows = self.rows_of(&format!("messages-{channel}-"), None, state.v2);
        rows.extend(state.added.get(&channel).into_iter().flatten().cloned());
        rows.sort_by_key(id_of);
        rows
    }

    fn answer(&self, req: &Req) -> Resp {
        let path = req
            .url
            .strip_prefix(BASE)
            .unwrap_or_else(|| panic!("the stand-in answers Discord's API only: {}", req.url));
        let mut state = self.state();
        state.requests += 1;
        state.asked.push(path.to_string());
        if req.method != Method::Get {
            state.non_gets += 1;
        }
        // In order, so a test can line up one answer after another on a route
        let rules: Vec<usize> = (0..state.script.len())
            .filter(|i| path.starts_with(&state.script[*i].route))
            .collect();
        let routes: HashSet<String> = rules
            .iter()
            .map(|i| state.script[*i].route.clone())
            .collect();
        for route in routes {
            *state.per_route.entry(route).or_insert(0) += 1;
        }
        for i in rules {
            let rule = &state.script[i];
            let call = state.per_route[&rule.route];
            if call == rule.nth || (rule.always && call >= rule.nth) {
                return Resp {
                    status: rule.status,
                    headers: rule.headers.clone(),
                    body: rule.body.clone(),
                };
            }
        }
        if !req.auth {
            return json_resp(401, &json!({ "message": "401: Unauthorized", "code": 0 }));
        }
        let mut resp = self.route(req, path, &mut state);
        if (200..300).contains(&resp.status) {
            // Room left, as most answers say. The route's name stands for Discord's hash
            let shape = path.split('?').next().unwrap_or(path);
            resp.headers.extend(
                [
                    ("x-ratelimit-limit", "5".to_string()),
                    ("x-ratelimit-remaining", "4".to_string()),
                    ("x-ratelimit-reset-after", "1.0".to_string()),
                    ("x-ratelimit-bucket", shape.to_string()),
                ]
                .map(|(n, v)| (n.to_string(), v)),
            );
        }
        resp
    }

    fn route(&self, req: &Req, path: &str, state: &mut State) -> Resp {
        let (route, query) = path.split_once('?').unwrap_or((path, ""));
        let query: HashMap<&str, &str> =
            query.split('&').filter_map(|p| p.split_once('=')).collect();
        let after = || {
            query
                .get("after")
                .and_then(|a| a.parse().ok())
                .unwrap_or(0u64)
        };
        let limit = |most: usize| {
            query
                .get("limit")
                .and_then(|l| l.parse().ok())
                .unwrap_or(most)
                .min(most)
        };
        let parts: Vec<&str> = route.trim_start_matches('/').split('/').collect();
        if req.method != Method::Get {
            // The move post, and nothing else: no other write exists
            return match (req.method, parts.as_slice()) {
                (Method::Post, ["channels", _, "messages"]) => self.post(req, state),
                _ => panic!("a write to {path}"),
            };
        }
        let v2 = state.v2;
        match parts.as_slice() {
            ["users", "@me"] => self.answer_file("me.json", v2),
            ["users", "@me", "guilds"] => self.answer_file("guilds.json", v2),
            ["applications", "@me"] => self.answer_file("app.json", v2),
            ["guilds", _] => self.answer_file("guild.json", v2),
            ["guilds", _, "members", id] => self.member(id, v2),
            ["guilds", _, "channels"] => self.channels(state),
            ["guilds", _, "roles"] => self.answer_file("roles.json", v2),
            ["guilds", _, "roles", "member-counts"] => self.answer_file("role-counts.json", v2),
            ["guilds", _, "emojis"] => self.answer_file("emojis.json", v2),
            ["guilds", _, "stickers"] => self.answer_file("stickers.json", v2),
            ["guilds", _, "threads", "active"] => self.answer_file("threads-active.json", v2),
            ["guilds", _, "members"] => {
                let rows = match self.big {
                    Some(big) => big_rows(BIG_MEMBERS, big.members, after(), limit(1000), |id| {
                        json!({ "user": { "id": id.to_string(), "username": format!("m{id}") },
                                "roles": [], "joined_at": "2024-01-02T03:04:05.000000+00:00" })
                    }),
                    None => page_up(self.rows_of("members-", None, v2), after(), limit(1000)),
                };
                json_resp(200, &Value::Array(rows))
            }
            ["guilds", _, "bans"] => {
                let rows = match self.big {
                    Some(big) => big_rows(BIG_BANS, big.bans, after(), limit(1000), |id| {
                        json!({ "user": { "id": id.to_string(), "username": format!("b{id}") },
                                "reason": "made up" })
                    }),
                    None => page_up(self.rows_of("bans-", None, v2), after(), limit(1000)),
                };
                json_resp(200, &Value::Array(rows))
            }
            ["guilds", _, "messages", "search"] => self.search(&query, state),
            ["channels", channel, "threads", "archived", "public"] => {
                let mut rows =
                    self.rows_of(&format!("threads-archived-{channel}"), Some("threads"), v2);
                let stamp = |t: &Value| t["thread_metadata"]["archive_timestamp"].clone();
                let text = |t: &Value| stamp(t).as_str().unwrap_or_default().to_string();
                if let Some(before) = query.get("before") {
                    assert!(!before.contains('+'), "a raw + in a query is a space");
                    let before = before.replace("%2B", "+");
                    rows.retain(|t| text(t) < before);
                }
                rows.sort_by_key(|t| std::cmp::Reverse(text(t)));
                let has_more = rows.len() > limit(100);
                rows.truncate(limit(100));
                json_resp(
                    200,
                    &json!({ "threads": rows, "members": [], "has_more": has_more }),
                )
            }
            ["channels", channel, "messages"] => {
                let Ok(channel) = channel.parse() else {
                    return not_found();
                };
                let all = self.messages_of(channel, state);
                if all.is_empty() && !self.knows_channel(channel, v2) {
                    return not_found();
                }
                // `limit` right after `after`, or the newest. Newest first in the page,
                // whichever: that is the docs' one word on the order
                let mut rows = match query.get("after") {
                    Some(_) => page_up(all, after(), limit(100)),
                    None => {
                        let skip = all.len().saturating_sub(limit(100));
                        all[skip..].to_vec()
                    }
                };
                rows.reverse();
                json_resp(200, &Value::Array(rows))
            }
            _ => not_found(),
        }
    }

    /// `channels.json`, each channel's last message what `add_messages` made it, as Discord's
    /// would be: a resume goes by it, and past a stale one it would stop reading. And each
    /// channel's rules what `deny_everyone` made them.
    fn channels(&self, state: &State) -> Resp {
        let mut resp = self.answer_file("channels.json", state.v2);
        if state.added.is_empty() && state.denied.is_empty() {
            return resp;
        }
        let guild = self
            .file("guild.json", state.v2)
            .and_then(|b| serde_json::from_slice::<Value>(b).ok())
            .unwrap_or_default()["id"]
            .clone();
        let mut list: Value = serde_json::from_slice(&resp.body).unwrap_or_default();
        for channel in list.as_array_mut().into_iter().flatten() {
            if let Some(last) = state.added.get(&id_of(channel)).and_then(|m| m.last()) {
                channel["last_message_id"] = last["id"].clone();
            }
            if let Some(bits) = state.denied.get(&id_of(channel)).filter(|b| **b != 0) {
                let rules = channel["permission_overwrites"].as_array_mut();
                let rules = rules.expect("every channel in the files has its rules");
                rules.retain(|r| r["id"] != guild);
                rules.push(json!({ "id": guild, "type": 0, "allow": "0",
                                   "deny": bits.to_string() }));
            }
        }
        resp.body = list.to_string().into_bytes();
        resp
    }

    fn knows_channel(&self, channel: u64, v2: bool) -> bool {
        let is = |c: &Value| id_of(c) == channel;
        let listed = |name: &str| {
            self.file(name, v2)
                .and_then(|b| serde_json::from_slice::<Value>(b).ok())
                .is_some_and(|v| {
                    let rows = v.get("threads").unwrap_or(&v);
                    rows.as_array().is_some_and(|rows| rows.iter().any(is))
                })
        };
        listed("channels.json")
            || listed("threads-active.json")
            || self
                .rows_of("threads-archived-", Some("threads"), v2)
                .iter()
                .any(is)
    }

    fn search(&self, query: &HashMap<&str, &str>, state: &mut State) -> Resp {
        let channel = query.get("channel_id").copied().unwrap_or_default();
        let script: Value = self
            .file("search.json", state.v2)
            .and_then(|b| serde_json::from_slice(b).ok())
            .unwrap_or_default();
        let said = &script[channel];
        if said["indexing"].as_bool() == Some(true) && state.indexing.insert(channel.to_string()) {
            return json_resp(
                202,
                &json!({ "message": "Index not yet available. Try again later", "code": 110000,
                         "documents_indexed": 0, "retry_after": said["retry_after"] }),
            );
        }
        let all = channel
            .parse()
            .map(|c| self.messages_of(c, state))
            .unwrap_or_default();
        let total = said
            .get("total_results")
            .and_then(Value::as_u64)
            .unwrap_or(all.len() as u64);
        let newest: Vec<Value> = all.last().cloned().into_iter().collect();
        json_resp(
            200,
            &json!({ "doing_deep_historical_index": false, "total_results": total,
                     "messages": [newest], "threads": [], "members": [] }),
        )
    }

    fn post(&self, req: &Req, state: &mut State) -> Resp {
        let body = req.body.clone().unwrap_or_default();
        let sent: Value = serde_json::from_slice(&body).unwrap_or_default();
        let nonce = sent["nonce"].as_str().unwrap_or_default().to_string();
        if sent["enforce_nonce"] != json!(true) || nonce.is_empty() || state.nonces.insert(nonce) {
            state.posted.push(body);
        }
        json_resp(
            200,
            &json!({ "id": "1", "type": 0, "content": sent["content"] }),
        )
    }
}

fn big_rows(
    base: u64,
    count: u64,
    after: u64,
    limit: usize,
    row: impl Fn(u64) -> Value,
) -> Vec<Value> {
    let first = after.saturating_add(1).max(base);
    let end = base + count;
    (first..end).take(limit).map(row).collect()
}

impl Transport for Mock {
    fn request(&self, req: Req) -> impl Future<Output = Result<Resp, String>> + Send {
        let resp = self.answer(&req);
        async move { Ok(resp) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{Api, RateGate};
    use crate::model::{Ban, Member, Message};

    async fn get(mock: &Mock, path: &str) -> Value {
        let resp = mock
            .request(Req {
                method: Method::Get,
                url: format!("{BASE}{path}"),
                auth: true,
                body: None,
            })
            .await
            .unwrap();
        serde_json::from_slice(&resp.body).unwrap_or_default()
    }

    #[tokio::test]
    async fn big_pages_members_and_bans_without_holding_them() {
        let mock = Mock::big(5000, 2500, 3, 3);
        let api = Api::with_gate(mock, RateGate::new(7));
        let mut count = 0;
        let mut after = 0;
        loop {
            let page: Vec<Member> = api
                .get(&format!("/guilds/1/members?limit=1000&after={after}"))
                .await
                .unwrap();
            let Some(last) = page.last() else { break };
            assert!(page.len() <= 1000);
            count += page.len();
            after = last.user.as_ref().unwrap().id;
        }
        assert_eq!(count, 5000);
        let bans: Vec<Ban> = api.get("/guilds/1/bans?limit=1000").await.unwrap();
        assert_eq!(bans.len(), 1000);
        let rest: Vec<Ban> = api
            .get(&format!(
                "/guilds/1/bans?limit=1000&after={}",
                bans[999].user.id
            ))
            .await
            .unwrap();
        assert_eq!(rest.len(), 1000);
        assert_ne!(rest[0].user.id, bans[999].user.id);
        // A million is no more work to set up
        let huge = Mock::big(1_000_000, 0, 1, 1);
        let last = get(
            &huge,
            &format!("/guilds/1/members?after={}", BIG_MEMBERS + 999_998),
        )
        .await;
        assert_eq!(last.as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_page_is_newest_first_and_starts_right_after_after() {
        let mock = Mock::big(0, 0, 1, 1);
        mock.add_messages(5, 250, 1);
        let api = Api::with_gate(mock, RateGate::new(7));
        let first: Vec<Message> = api
            .get("/channels/5/messages?limit=100&after=0")
            .await
            .unwrap();
        assert_eq!(first.len(), 100);
        assert!(first[0].id > first[99].id, "newest first");
        // The 100 right after: the oldest of all
        assert_eq!(first[99].id, ADDED_MESSAGES);
        let cursor = first[0].id;
        let next: Vec<Message> = api
            .get(&format!("/channels/5/messages?limit=100&after={cursor}"))
            .await
            .unwrap();
        assert_eq!(next[99].id, cursor + 1);
        // With no `after`, the newest
        let newest: Vec<Message> = api.get("/channels/5/messages?limit=10").await.unwrap();
        assert_eq!(newest[0].id, ADDED_MESSAGES + 249);
    }

    #[tokio::test]
    async fn added_messages_move_the_channels_last_message() {
        let mock = Mock::big(0, 0, 1, 2);
        let last_of = |list: Value, id: u64| {
            let rows = list.as_array().unwrap().clone();
            let row = rows.into_iter().find(|c| id_of(c) == id).unwrap();
            row["last_message_id"].as_str().map(str::to_string)
        };
        let list = get(&mock, "/guilds/1/channels").await;
        assert_eq!(last_of(list, BIG_CHANNELS), None);
        mock.add_messages(BIG_CHANNELS, 3, 1);
        let list = get(&mock, "/guilds/1/channels").await;
        let want = (ADDED_MESSAGES + 2).to_string();
        assert_eq!(last_of(list.clone(), BIG_CHANNELS), Some(want));
        // The control: its neighbour is what it was
        assert_eq!(last_of(list, BIG_CHANNELS + 1), None);
    }

    #[tokio::test]
    async fn an_unknown_channel_or_route_is_a_404() {
        let mock = Mock::big(0, 0, 1, 1);
        let answer = |path: String| {
            mock.answer(&Req {
                method: Method::Get,
                url: format!("{BASE}{path}"),
                auth: true,
                body: None,
            })
        };
        assert_eq!(answer("/channels/5/messages".into()).status, 404);
        assert_eq!(answer("/nothing".into()).status, 404);
        // A real channel with nothing in it is an empty page
        let channel = BIG_CHANNELS;
        assert_eq!(answer(format!("/channels/{channel}/messages")).status, 200);
    }

    #[test]
    #[should_panic(expected = "API only")]
    fn it_answers_no_other_host() {
        Mock::big(0, 0, 0, 0).answer(&Req {
            method: Method::Get,
            url: "https://example.net/x".into(),
            auth: true,
            body: None,
        });
    }

    #[test]
    #[should_panic(expected = "a write to")]
    fn no_write_but_the_post_exists() {
        Mock::big(0, 0, 0, 0).answer(&Req {
            method: Method::Post,
            url: format!("{BASE}/guilds/1/bans/5"),
            auth: true,
            body: None,
        });
    }

    #[tokio::test]
    async fn no_token_gets_nothing() {
        let mock = Mock::big(1, 0, 0, 0);
        let resp = mock
            .request(Req {
                method: Method::Get,
                url: format!("{BASE}/users/@me"),
                auth: false,
                body: None,
            })
            .await
            .unwrap();
        assert_eq!(resp.status, 401);
    }

    #[tokio::test]
    async fn a_script_answers_its_call_and_no_other() {
        let mock = Mock::big(1, 0, 0, 0);
        mock.script(Scripted::new(
            "/users/@me",
            2,
            429,
            &[("retry-after", "1")],
            "{}",
        ));
        let status = |mock: &Mock| {
            mock.answer(&Req {
                method: Method::Get,
                url: format!("{BASE}/users/@me"),
                auth: true,
                body: None,
            })
            .status
        };
        assert_eq!(status(&mock), 200);
        assert_eq!(status(&mock), 429);
        assert_eq!(status(&mock), 200);
        assert_eq!(mock.requests(), 3);
    }
}
