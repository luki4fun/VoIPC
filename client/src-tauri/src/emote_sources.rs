//! One-click emote imports, in the desktop app: a Discord server's emojis or
//! stickers (through a bot of the admin's that is in it), a 7TV emote set, a
//! Twitch channel's BetterTTV emotes. The page cannot fetch these itself (the
//! browser's CORS), and should not: here only fixed hosts are asked, over
//! HTTPS, with no redirects, small caps and short timeouts. A bot token goes
//! to discord.com in one header and is kept nowhere.
//!
//! What comes back is a pack as `read_emote_pack` gives one: the importer
//! sanitizes, names and adds each file like any other it was given. A pack's
//! title is a 7TV set's public name; a Discord server's name is never filled
//! in, so the relay is not told where else its admin is.

use serde_json::Value;

/// Hosts these imports may ask, and no other.
pub(crate) const HOSTS: &[&str] = &[
    "discord.com",
    "cdn.discordapp.com",
    "media.discordapp.net",
    "7tv.io",
    "cdn.7tv.app",
    "api.betterttv.net",
    "cdn.betterttv.net",
];

/// One picture to fetch: the file name it is imported under, and where.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Item {
    pub name: String,
    pub url: String,
}

/// What a source lists: its title, what to fetch, and what is passed over
/// (with why).
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Listing {
    pub title: Option<String>,
    pub items: Vec<Item>,
    pub skipped: Vec<(String, String)>,
}

fn digits(s: &str) -> bool {
    !s.is_empty() && s.len() <= 20 && s.bytes().all(|c| c.is_ascii_digit())
}

fn plain_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 40 && s.bytes().all(|c| c.is_ascii_alphanumeric())
}

/// A Discord server's `/emojis` (or with `stickers`, `/stickers`) answer.
pub(crate) fn discord_listing(json: &Value, stickers: bool) -> Listing {
    let mut out = Listing::default();
    for v in json
        .as_array()
        .into_iter()
        .flatten()
        .take(voipc_protocol::types::MAX_EMOTES)
    {
        let (Some(id), Some(name)) = (v["id"].as_str(), v["name"].as_str()) else {
            continue;
        };
        if !digits(id) {
            continue;
        }
        if stickers {
            // 1 PNG, 2 APNG, 3 Lottie, 4 GIF
            let ext = match v["format_type"].as_u64() {
                Some(1) | Some(2) => "png",
                Some(4) => "gif",
                _ => {
                    out.skipped
                        .push((name.to_owned(), "a Lottie sticker is not supported".into()));
                    continue;
                }
            };
            out.items.push(Item {
                name: format!("{name}.{ext}"),
                url: format!("https://media.discordapp.net/stickers/{id}.{ext}?size=320"),
            });
        } else {
            let ext = if v["animated"].as_bool() == Some(true) {
                "gif"
            } else {
                "png"
            };
            out.items.push(Item {
                name: format!("{name}.{ext}"),
                url: format!("https://cdn.discordapp.com/emojis/{id}.{ext}?size=128"),
            });
        }
    }
    out
}

/// A 7TV emote set (`/v3/emote-sets/<id>`): each emote's 2x file, WebP first.
pub(crate) fn seventv_listing(json: &Value) -> Listing {
    let mut out = Listing {
        title: json["name"].as_str().map(str::to_owned),
        ..Listing::default()
    };
    for e in json["emotes"]
        .as_array()
        .into_iter()
        .flatten()
        .take(voipc_protocol::types::MAX_EMOTES)
    {
        let Some(name) = e["name"].as_str() else {
            continue;
        };
        let host = &e["data"]["host"];
        let Some(base) = host["url"]
            .as_str()
            .and_then(|u| u.strip_prefix("//cdn.7tv.app/emote/"))
        else {
            continue;
        };
        if !plain_id(base) {
            continue;
        }
        let files: Vec<&str> = host["files"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|f| f["name"].as_str())
            .collect();
        let Some(file) = ["2x.webp", "2x.gif", "2x.png", "1x.webp"]
            .into_iter()
            .find(|f| files.contains(f))
        else {
            out.skipped
                .push((name.to_owned(), "no file 7TV offers is read here".into()));
            continue;
        };
        let ext = file.rsplit('.').next().unwrap_or("webp");
        out.items.push(Item {
            name: format!("{name}.{ext}"),
            url: format!("https://cdn.7tv.app/emote/{base}/{file}"),
        });
    }
    out
}

/// A Twitch channel's BetterTTV emotes (`/3/cached/users/twitch/<id>`).
pub(crate) fn bttv_listing(json: &Value) -> Listing {
    let mut out = Listing::default();
    let all = json["channelEmotes"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(json["sharedEmotes"].as_array().into_iter().flatten());
    for e in all.take(voipc_protocol::types::MAX_EMOTES) {
        let (Some(id), Some(code)) = (e["id"].as_str(), e["code"].as_str()) else {
            continue;
        };
        if !plain_id(id) {
            continue;
        }
        let ext = e["imageType"]
            .as_str()
            .filter(|t| matches!(*t, "png" | "gif" | "webp"))
            .unwrap_or("png");
        out.items.push(Item {
            name: format!("{code}.{ext}"),
            url: format!("https://cdn.betterttv.net/emote/{id}/2x"),
        });
    }
    out
}

/// What a 7TV address names.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SevenTv {
    /// An emote set (`7tv.app/emote-sets/<id>`, or the id alone).
    Set,
    /// One emote (`7tv.app/emotes/<id>`).
    Emote,
    /// A user (`7tv.app/users/<id>`): their set in use.
    User,
}

/// The id a 7TV address ends with (or the id itself), and what it names.
pub(crate) fn seventv_id(input: &str) -> Option<(String, SevenTv)> {
    let path = input.trim().split(['?', '#']).next()?.trim_end_matches('/');
    let (rest, id) = path.rsplit_once('/').unwrap_or(("", path));
    let what = if rest.ends_with("/emotes") {
        SevenTv::Emote
    } else if rest.ends_with("/users") {
        SevenTv::User
    } else {
        SevenTv::Set
    };
    plain_id(id).then(|| (id.to_owned(), what))
}

/// The set a 7TV user (`/v3/users/<id>`) has in use: their Twitch one, else
/// any platform's.
pub(crate) fn seventv_user_set(json: &Value) -> Option<String> {
    let sets = json["connections"].as_array()?;
    fn of(c: &Value) -> Option<&str> {
        c["emote_set_id"].as_str().filter(|id| plain_id(id))
    }
    sets.iter()
        .find(|c| c["platform"] == "TWITCH")
        .and_then(of)
        .or_else(|| sets.iter().find_map(of))
        .map(str::to_owned)
}

/// Fetch `source`'s pictures: "discord" (`id` a server id, `token` its
/// bot's), "7tv" (a set's address or id), "bttv" (a Twitch user id). Answered
/// as `read_emote_pack` answers, with what was passed over in the head too.
#[tauri::command]
pub async fn fetch_emote_source(
    source: String,
    id: String,
    token: Option<String>,
    stickers: bool,
) -> Result<tauri::ipc::Response, String> {
    #[cfg(target_os = "android")]
    {
        let _ = (source, id, token, stickers);
        Err("this import is in the desktop app".into())
    }
    #[cfg(not(target_os = "android"))]
    {
        desktop::fetch(&source, &id, token, stickers)
            .await
            .map(tauri::ipc::Response::new)
    }
}

#[cfg(not(target_os = "android"))]
mod desktop {
    use std::time::Duration;

    use super::*;

    const MAX_JSON: usize = 2 << 20;
    const MAX_IMAGE: usize = 8 << 20;
    const TIMEOUT: Duration = Duration::from_secs(10);

    fn client() -> Result<reqwest::Client, String> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .timeout(TIMEOUT)
            .user_agent(concat!("VoIPC/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| e.to_string())
    }

    async fn get(
        c: &reqwest::Client,
        url: &str,
        auth: Option<&str>,
        cap: usize,
    ) -> Result<Vec<u8>, String> {
        let u = reqwest::Url::parse(url).map_err(|_| "not an address".to_string())?;
        if u.scheme() != "https" || !u.host_str().is_some_and(|h| HOSTS.contains(&h)) {
            return Err("not a host this import asks".into());
        }
        let mut req = c.get(u);
        if let Some(a) = auth {
            // Sensitive: never printed by reqwest's or hyper's own logging
            let mut value = reqwest::header::HeaderValue::from_str(a)
                .map_err(|_| "a token is one line of plain characters".to_string())?;
            value.set_sensitive(true);
            req = req.header(reqwest::header::AUTHORIZATION, value);
        }
        let mut res = req.send().await.map_err(|e| e.without_url().to_string())?;
        let status = res.status();
        if !status.is_success() {
            return Err(match status.as_u16() {
                401 | 403 => "refused: check the token, and that the bot is in that server".into(),
                404 => "not found: check the id".into(),
                429 => "asked too often: try again in a minute".into(),
                n => format!("answered {n}"),
            });
        }
        if res.content_length().is_some_and(|n| n > cap as u64) {
            return Err("too big".into());
        }
        let mut out = Vec::new();
        while let Some(chunk) = res.chunk().await.map_err(|e| e.without_url().to_string())? {
            out.extend_from_slice(&chunk);
            if out.len() > cap {
                return Err("too big".into());
            }
        }
        Ok(out)
    }

    pub(super) async fn fetch(
        source: &str,
        id: &str,
        token: Option<String>,
        stickers: bool,
    ) -> Result<Vec<u8>, String> {
        let c = client()?;
        let json = |b: Vec<u8>| {
            serde_json::from_slice::<Value>(&b)
                .map_err(|_| "an answer that is not JSON".to_string())
        };
        let mut listing = match source {
            "discord" => {
                let id = id.trim();
                if !digits(id) {
                    return Err("a Discord server id is a number (Developer Mode, right-click the server, Copy Server ID)".into());
                }
                let token = token
                    .as_deref()
                    .map(str::trim)
                    .filter(|t| !t.is_empty())
                    .ok_or("a bot token is needed")?;
                let auth = format!("Bot {token}");
                let what = if stickers { "stickers" } else { "emojis" };
                let url = format!("https://discord.com/api/v10/guilds/{id}/{what}");
                discord_listing(
                    &json(get(&c, &url, Some(&auth), MAX_JSON).await?)?,
                    stickers,
                )
            }
            "7tv" => {
                let (id, what) = seventv_id(id)
                    .ok_or("a 7TV emote's, emote set's or user's address, or a set's id")?;
                // A user's address: the set they use
                let id = if what == SevenTv::User {
                    let user = json(
                        get(&c, &format!("https://7tv.io/v3/users/{id}"), None, MAX_JSON).await?,
                    )?;
                    seventv_user_set(&user).ok_or("that 7TV user has no emote set in use")?
                } else {
                    id
                };
                if what == SevenTv::Emote {
                    let e = json(
                        get(
                            &c,
                            &format!("https://7tv.io/v3/emotes/{id}"),
                            None,
                            MAX_JSON,
                        )
                        .await?,
                    )?;
                    // One emote reads as a set of one: a set holds each as `data`
                    seventv_listing(
                        &serde_json::json!({ "emotes": [{ "name": e["name"], "data": e }] }),
                    )
                } else {
                    seventv_listing(&json(
                        get(
                            &c,
                            &format!("https://7tv.io/v3/emote-sets/{id}"),
                            None,
                            MAX_JSON,
                        )
                        .await?,
                    )?)
                }
            }
            "bttv" => {
                let id = id.trim();
                if !digits(id) {
                    return Err("a Twitch user id is a number".into());
                }
                bttv_listing(&json(
                    get(
                        &c,
                        &format!("https://api.betterttv.net/3/cached/users/twitch/{id}"),
                        None,
                        MAX_JSON,
                    )
                    .await?,
                )?)
            }
            _ => return Err("no such source".into()),
        };
        // Four at a time: a CDN is quick, and nothing here is in a hurry. At
        // most as much as a .zip may unpack to; the rest is named, not fetched
        const MAX_TOTAL: usize = 200 << 20;
        const FULL: &str = "past what one import takes: fetch the rest again after adding these";
        let mut files: Vec<(String, Vec<u8>)> = Vec::new();
        let mut total = 0;
        for chunk in listing.items.chunks(4) {
            let got = if total < MAX_TOTAL {
                futures_join(&c, chunk).await
            } else {
                chunk.iter().map(|_| Err(FULL.to_string())).collect()
            };
            for (item, r) in chunk.iter().zip(got) {
                match r {
                    Ok(b) if total + b.len() <= MAX_TOTAL => {
                        total += b.len();
                        files.push((item.name.clone(), b));
                    }
                    Ok(_) => listing.skipped.push((item.name.clone(), FULL.into())),
                    Err(e) => listing.skipped.push((item.name.clone(), e)),
                }
            }
        }
        let head = serde_json::json!({
            "title": listing.title,
            "entries": files.iter().map(|(n, b)| serde_json::json!({ "name": n, "len": b.len() })).collect::<Vec<_>>(),
            "skipped": listing.skipped.iter().map(|(n, w)| serde_json::json!({ "name": n, "why": w })).collect::<Vec<_>>(),
        })
        .to_string();
        // Each file let go once it is in the answer: one copy at a time, not two
        let mut out = Vec::with_capacity(4 + head.len() + total);
        out.extend_from_slice(&(head.len() as u32).to_le_bytes());
        out.extend_from_slice(head.as_bytes());
        for (_, b) in files {
            out.extend_from_slice(&b);
        }
        Ok(out)
    }

    async fn futures_join(c: &reqwest::Client, items: &[Item]) -> Vec<Result<Vec<u8>, String>> {
        let mut set = tokio::task::JoinSet::new();
        for (i, item) in items.iter().enumerate() {
            let (c, url) = (c.clone(), item.url.clone());
            set.spawn(async move { (i, get(&c, &url, None, MAX_IMAGE).await) });
        }
        let mut out: Vec<Result<Vec<u8>, String>> =
            items.iter().map(|_| Err("not fetched".into())).collect();
        // A task that failed leaves its "not fetched"; the others still count
        while let Some(done) = set.join_next().await {
            if let Ok((i, r)) = done {
                out[i] = r;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discord_emojis_and_stickers() {
        let emojis = serde_json::json!([
            { "id": "123456789012345678", "name": "pog", "animated": false },
            { "id": "223456789012345678", "name": "dance", "animated": true },
            { "id": "../../x", "name": "evil" },
        ]);
        let l = discord_listing(&emojis, false);
        assert_eq!(
            l.items,
            [
                Item {
                    name: "pog.png".into(),
                    url: "https://cdn.discordapp.com/emojis/123456789012345678.png?size=128".into()
                },
                Item {
                    name: "dance.gif".into(),
                    url: "https://cdn.discordapp.com/emojis/223456789012345678.gif?size=128".into()
                },
            ]
        );
        let stickers = serde_json::json!([
            { "id": "1", "name": "wave", "format_type": 2 },
            { "id": "2", "name": "lottie", "format_type": 3 },
            { "id": "3", "name": "spin", "format_type": 4 },
        ]);
        let l = discord_listing(&stickers, true);
        assert_eq!(
            l.items.iter().map(|i| i.name.as_str()).collect::<Vec<_>>(),
            ["wave.png", "spin.gif"]
        );
        assert_eq!(
            l.skipped,
            [(
                "lottie".to_string(),
                "a Lottie sticker is not supported".to_string()
            )]
        );
        assert!(
            l.title.is_none(),
            "a Discord server's name is never filled in"
        );
    }

    #[test]
    fn a_7tv_set_takes_each_emotes_2x_file_webp_first() {
        let set = serde_json::json!({ "name": "Halloween", "emotes": [
            { "name": "boo", "data": { "host": { "url": "//cdn.7tv.app/emote/01ABC", "files": [{ "name": "1x.webp" }, { "name": "2x.avif" }, { "name": "2x.webp" }] } } },
            { "name": "gifonly", "data": { "host": { "url": "//cdn.7tv.app/emote/01DEF", "files": [{ "name": "2x.gif" }] } } },
            { "name": "elsewhere", "data": { "host": { "url": "//evil.example/emote/01", "files": [{ "name": "2x.webp" }] } } },
            { "name": "avif", "data": { "host": { "url": "//cdn.7tv.app/emote/01GHI", "files": [{ "name": "2x.avif" }] } } },
        ]});
        let l = seventv_listing(&set);
        assert_eq!(l.title.as_deref(), Some("Halloween"));
        assert_eq!(
            l.items,
            [
                Item {
                    name: "boo.webp".into(),
                    url: "https://cdn.7tv.app/emote/01ABC/2x.webp".into()
                },
                Item {
                    name: "gifonly.gif".into(),
                    url: "https://cdn.7tv.app/emote/01DEF/2x.gif".into()
                },
            ]
        );
        assert_eq!(l.skipped.len(), 1);
        let set = |id: &str| Some((id.to_owned(), SevenTv::Set));
        assert_eq!(
            seventv_id("https://7tv.app/emote-sets/01HKQT8EWR000ESSWF3625XCS4/"),
            set("01HKQT8EWR000ESSWF3625XCS4")
        );
        assert_eq!(
            seventv_id("https://7tv.app/emote-sets/01ABC?x=../y"),
            set("01ABC"),
            "a query is no part of the id"
        );
        assert_eq!(seventv_id("01ABC#frag"), set("01ABC"));
        assert_eq!(
            seventv_id("01 ABC"),
            None,
            "only letters and digits go into a path"
        );
        assert_eq!(
            seventv_id("https://7tv.app/emotes/01F5VW2TKR0003RCV2Z6JBHCST"),
            Some(("01F5VW2TKR0003RCV2Z6JBHCST".to_owned(), SevenTv::Emote)),
            "one emote's address"
        );
        assert_eq!(
            seventv_id("https://7tv.app/users/01FE9DRF000009TR6M9N941CYW"),
            Some(("01FE9DRF000009TR6M9N941CYW".to_owned(), SevenTv::User)),
            "a user's address"
        );
        // A user, as /v3/users/<id> answered (2026-10-30, trimmed): the Twitch set
        let user = serde_json::json!({
            "id": "01FE9DRF000009TR6M9N941CYW",
            "connections": [
                { "platform": "KICK", "emote_set_id": "01KICKSET" },
                { "platform": "TWITCH", "emote_set_id": "01J9MMS2R800036CR40E1041ED" },
            ],
        });
        assert_eq!(
            seventv_user_set(&user).as_deref(),
            Some("01J9MMS2R800036CR40E1041ED")
        );
        let kick_only = serde_json::json!({ "connections": [{ "platform": "KICK", "emote_set_id": "01KICKSET" }] });
        assert_eq!(seventv_user_set(&kick_only).as_deref(), Some("01KICKSET"));
        let bad = serde_json::json!({ "connections": [{ "platform": "TWITCH", "emote_set_id": "../x" }] });
        assert_eq!(seventv_user_set(&bad), None, "only an id goes into a path");
        // One emote, as 7TV's /v3/emotes/<id> answers, reads as a set of one
        let one = serde_json::json!({ "name": "catKISS", "host": { "url": "//cdn.7tv.app/emote/01F5VW2TKR0003RCV2Z6JBHCST", "files": [{ "name": "2x.webp" }, { "name": "2x.gif" }] } });
        let l = seventv_listing(
            &serde_json::json!({ "emotes": [{ "name": one["name"], "data": one }] }),
        );
        assert_eq!(
            l.items,
            [Item {
                name: "catKISS.webp".into(),
                url: "https://cdn.7tv.app/emote/01F5VW2TKR0003RCV2Z6JBHCST/2x.webp".into()
            }]
        );
    }

    #[test]
    fn bttv_channel_and_shared_emotes() {
        let user = serde_json::json!({ "channelEmotes": [{ "id": "54fa8f1401e468494b85b537", "code": ":tf:", "imageType": "png" }],
            "sharedEmotes": [{ "id": "5f1b0186cf6d2144653d2970", "code": "catJAM", "imageType": "gif" }, { "id": "x/../y", "code": "bad", "imageType": "png" }] });
        let l = bttv_listing(&user);
        assert_eq!(
            l.items,
            [
                Item {
                    name: ":tf:.png".into(),
                    url: "https://cdn.betterttv.net/emote/54fa8f1401e468494b85b537/2x".into()
                },
                Item {
                    name: "catJAM.gif".into(),
                    url: "https://cdn.betterttv.net/emote/5f1b0186cf6d2144653d2970/2x".into()
                },
            ]
        );
    }

    #[test]
    fn every_address_made_here_is_on_an_allowed_host() {
        let all = [
            discord_listing(&serde_json::json!([{ "id": "1", "name": "a" }]), false),
            discord_listing(
                &serde_json::json!([{ "id": "1", "name": "a", "format_type": 1 }]),
                true,
            ),
            seventv_listing(
                &serde_json::json!({ "emotes": [{ "name": "a", "data": { "host": { "url": "//cdn.7tv.app/emote/1", "files": [{ "name": "2x.webp" }] } } }] }),
            ),
            bttv_listing(&serde_json::json!({ "channelEmotes": [{ "id": "1", "code": "a" }] })),
        ];
        for l in all {
            for i in l.items {
                let host = i
                    .url
                    .strip_prefix("https://")
                    .and_then(|r| r.split('/').next())
                    .unwrap();
                assert!(HOSTS.contains(&host), "{}", i.url);
            }
        }
    }
}
