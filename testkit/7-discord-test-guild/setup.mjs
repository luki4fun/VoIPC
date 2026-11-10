#!/usr/bin/env node
// Fills an empty Discord server with everything the VoIPC importer reads, for a real move test.
// Read README.md in this folder first. Node 18 or newer, no packages.
//
//   DISCORD_BOT_TOKEN=... node testkit/7-discord-test-guild/setup.mjs            invite the bot, then build
//   node testkit/7-discord-test-guild/setup.mjs members --mod <id> --vip <id> --plain <id> [--ban <id>]
//   node testkit/7-discord-test-guild/setup.mjs change                            the changes before run 2
//   node testkit/7-discord-test-guild/setup.mjs status
//
// Options: --guild <id>   which server (else: the one the bot is invited to now)
//          --token-file <path>   read the token from a file instead of DISCORD_BOT_TOKEN
//          --bulk <n>     messages in #bulk (default 300)
//          --no-community   do not turn on Community (no announcement, stage, forum or media channels then)
//          --images <dir>   only write the generated pictures to <dir> and stop (offline check)
//
// The token goes to discord.com only. It is never printed, logged or written anywhere. The state
// file (ids, webhook URLs) goes to target/discord-test-guild/<server id>.json, mode 0600: the
// webhook URLs in it can post into the test server, so delete it with the server.

import { readFileSync, writeFileSync, mkdirSync, existsSync, chmodSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { deflateSync } from 'node:zlib';
import { spawn } from 'node:child_process';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '../..');
const API = 'https://discord.com/api/v10';
const MARKER = 'voipc-test-guild';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- arguments ----------
const argv = process.argv.slice(2);
const cmd = argv[0] && !argv[0].startsWith('--') ? argv.shift() : 'build';
const opt = (name, fallback = null) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? argv[i + 1] : fallback;
};
const flag = (name) => argv.includes(`--${name}`);
if (flag('help') || cmd === 'help') {
  console.log(readFileSync(fileURLToPath(import.meta.url), 'utf8').split('\n').slice(1, 20).join('\n'));
  process.exit(0);
}
const BULK = Number(opt('bulk', '300'));

// ---------- Discord permission bits (crates/voipc-protocol/src/discord.rs) ----------
const B = (n) => 1n << BigInt(n);
const P = {
  KICK: B(1), BAN: B(2), ADMIN: B(3), MANAGE_CHANNELS: B(4), MANAGE_GUILD: B(5), ADD_REACTIONS: B(6),
  AUDIT_LOG: B(7), PRIORITY_SPEAKER: B(8), STREAM: B(9), VIEW: B(10), SEND: B(11), MANAGE_MESSAGES: B(13),
  HISTORY: B(16), MENTION_EVERYONE: B(17), INSIGHTS: B(19), CONNECT: B(20), SPEAK: B(21), MUTE: B(22),
  DEAFEN: B(23), MOVE: B(24), NICKNAMES: B(27), ROLES: B(28), WEBHOOKS: B(29), EXPRESSIONS: B(30),
  EVENTS: B(33), THREADS: B(34), MODERATE: B(40), CREATE_EXPRESSIONS: B(43), PIN: B(51), BYPASS_SLOW: B(52),
};
const bits = (...xs) => xs.reduce((a, b) => a | b, 0n);

// ---------- pictures, made here so nothing is downloaded ----------
const CRC = new Int32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c;
});
function crc32(buf) {
  let c = -1;
  for (const b of buf) c = CRC[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}
function chunk(type, data) {
  const out = Buffer.alloc(12 + data.length);
  out.writeUInt32BE(data.length, 0);
  out.write(type, 4, 'latin1');
  data.copy(out, 8);
  out.writeUInt32BE(crc32(out.subarray(4, 8 + data.length)), 8 + data.length);
  return out;
}
const u32 = (...ns) => Buffer.concat(ns.map((n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; }));
function rgbaRows(w, h, px) {
  const raw = Buffer.alloc((w * 4 + 1) * h);
  for (let y = 0; y < h; y++) {
    raw[y * (w * 4 + 1)] = 0;
    for (let x = 0; x < w; x++) {
      const [r, g, b, a] = px(x, y);
      raw.set([r, g, b, a], y * (w * 4 + 1) + 1 + x * 4);
    }
  }
  return deflateSync(raw, { level: 9 });
}
const PNG_SIG = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
const ihdr = (w, h) => chunk('IHDR', Buffer.concat([u32(w, h), Buffer.from([8, 6, 0, 0, 0])]));
function png(w, h, px) {
  return Buffer.concat([PNG_SIG, ihdr(w, h), chunk('IDAT', rgbaRows(w, h, px)), chunk('IEND', Buffer.alloc(0))]);
}
function apng(w, h, frames, delayCs = 25) {
  const parts = [PNG_SIG, ihdr(w, h), chunk('acTL', u32(frames.length, 0))];
  let seq = 0;
  frames.forEach((px, i) => {
    const fctl = Buffer.concat([u32(seq++, w, h, 0, 0), Buffer.from([0, delayCs, 0, 100, 0, 0])]);
    parts.push(chunk('fcTL', fctl));
    const data = rgbaRows(w, h, px);
    parts.push(i === 0 ? chunk('IDAT', data) : chunk('fdAT', Buffer.concat([u32(seq++), data])));
  });
  parts.push(chunk('IEND', Buffer.alloc(0)));
  return Buffer.concat(parts);
}
// GIF with 8-bit codes and a clear code every 100 pixels: never compressed, always valid.
function gif(w, h, frames, palette, delayCs = 20) {
  const head = Buffer.from('GIF89a', 'latin1');
  const lsd = Buffer.from([w & 255, w >> 8, h & 255, h >> 8, 0xe6, 0, 0]); // 128-colour table
  const table = Buffer.alloc(128 * 3);
  palette.forEach(([r, g, b], i) => table.set([r, g, b], i * 3));
  const loop = Buffer.from([0x21, 0xff, 0x0b, ...Buffer.from('NETSCAPE2.0', 'latin1'), 3, 1, 0, 0, 0]);
  const parts = [head, lsd, table, loop];
  for (const idx of frames) {
    parts.push(Buffer.from([0x21, 0xf9, 4, 0x04, delayCs & 255, delayCs >> 8, 0, 0]));
    parts.push(Buffer.from([0x2c, 0, 0, 0, 0, w & 255, w >> 8, h & 255, h >> 8, 0]));
    const codes = [];
    let run = 0;
    codes.push(128);
    for (let y = 0; y < h; y++) {
      for (let x = 0; x < w; x++) {
        if (run === 100) { codes.push(128); run = 0; }
        codes.push(idx(x, y) & 127);
        run++;
      }
    }
    codes.push(129);
    const data = Buffer.from(codes);
    const blocks = [Buffer.from([7])];
    for (let i = 0; i < data.length; i += 255) {
      const part = data.subarray(i, i + 255);
      blocks.push(Buffer.from([part.length]), part);
    }
    blocks.push(Buffer.from([0]));
    parts.push(...blocks);
  }
  parts.push(Buffer.from([0x3b]));
  return Buffer.concat(parts);
}
const disc = (w, h, [r, g, b], stripe = 0) => (x, y) => {
  const dx = x - w / 2, dy = y - h / 2, R = Math.min(w, h) * 0.45;
  if (dx * dx + dy * dy > R * R) return [0, 0, 0, 0];
  return (x + y + stripe) % 24 < 6 ? [255, 255, 255, 255] : [r, g, b, 255];
};
const PALETTE = [[0, 0, 0], [255, 255, 255], [230, 60, 60], [60, 160, 230], [250, 200, 40], [120, 200, 90]];
const gifFrames = (w, h, n) => Array.from({ length: n }, (_, f) => (x, y) => {
  const dx = x - w / 2, dy = y - h / 2, R = Math.min(w, h) * 0.45;
  if (dx * dx + dy * dy > R * R) return 1;
  return 2 + ((Math.floor((x + y) / (w / 8)) + f) % 4);
});
const IMAGES = {
  wave: () => png(128, 128, disc(128, 128, [60, 160, 230])),
  heart: () => png(128, 128, disc(128, 128, [230, 60, 60], 3)),
  caps: () => png(128, 128, disc(128, 128, [120, 200, 90], 7)),
  vip: () => png(128, 128, disc(128, 128, [212, 175, 55], 11)),
  spin: () => gif(128, 128, gifFrames(128, 128, 4), PALETTE),
  blink: () => gif(128, 128, gifFrames(128, 128, 2), PALETTE, 50),
  stickerPng: () => png(320, 320, disc(320, 320, [155, 89, 182])),
  stickerApng: () => apng(320, 320, [0, 8, 16].map((s) => disc(320, 320, [26, 188, 156], s))),
  stickerGif: () => gif(320, 320, gifFrames(320, 320, 3), PALETTE),
  attachment: () => png(64, 64, disc(64, 64, [230, 126, 34])),
};
if (opt('images')) {
  const dir = resolve(opt('images'));
  mkdirSync(dir, { recursive: true });
  for (const [name, make] of Object.entries(IMAGES)) {
    const data = make();
    const ext = data.subarray(0, 3).toString('latin1') === 'GIF' ? 'gif' : 'png';
    writeFileSync(join(dir, `${name}.${ext}`), data);
    console.log(`${name}.${ext}  ${data.length} bytes`);
  }
  process.exit(0);
}
const dataUri = (buf) => `data:image/${buf.subarray(0, 3).toString('latin1') === 'GIF' ? 'gif' : 'png'};base64,${buf.toString('base64')}`;

// ---------- the token ----------
async function readToken() {
  if (opt('token-file')) return readFileSync(opt('token-file'), 'utf8').trim();
  if (process.env.DISCORD_BOT_TOKEN) return process.env.DISCORD_BOT_TOKEN.trim();
  if (!process.stdin.isTTY) throw new Error('set DISCORD_BOT_TOKEN or pass --token-file');
  process.stdout.write('Bot token (not shown): ');
  return await new Promise((done) => {
    let s = '';
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.on('data', function on(d) {
      for (const c of d.toString('utf8')) {
        if (c === '\r' || c === '\n') {
          process.stdin.setRawMode(false); process.stdin.pause(); process.stdin.off('data', on);
          process.stdout.write('\n');
          return done(s.trim());
        }
        if (c === '\u0003') process.exit(130);
        if (c === '\u007f') s = s.slice(0, -1); else s += c;
      }
    });
  });
}

// ---------- REST, with Discord's rate limits ----------
let TOKEN = '';
const nextAt = new Map();
let lastCall = 0;
class ApiError extends Error {
  constructor(method, path, status, body) {
    super(`${method} ${path.replace(/\/webhooks\/(\d+)\/[^/?]+/, '/webhooks/$1/…')} → ${status} ${JSON.stringify(body).slice(0, 300)}`);
    this.status = status;
    this.body = body;
  }
}
function routeKey(method, path) {
  return method + ' ' + path.replace(/\/webhooks\/(\d+)\/[^/?]+/, '/webhooks/$1/t')
    .replace(/\/(messages|reactions|members|bans|roles|emojis|stickers|threads|pins)\/[^/?]+/g, '/$1/:id')
    .replace(/\?.*$/, '');
}
async function api(method, path, body, { files, auth = true, reason } = {}) {
  const key = routeKey(method, path);
  for (let attempt = 0; ; attempt++) {
    const wait = Math.max((nextAt.get(key) ?? 0) - Date.now(), lastCall + 25 - Date.now());
    if (wait > 0) await sleep(wait);
    lastCall = Date.now();
    const headers = { 'User-Agent': 'DiscordBot (https://github.com/luki4fun/VoIPC, 1) voipc-test-guild' };
    if (auth) headers.Authorization = `Bot ${TOKEN}`;
    if (reason) headers['X-Audit-Log-Reason'] = encodeURIComponent(reason);
    const init = { method, headers };
    if (files) {
      const fd = new FormData();
      if (body !== undefined) fd.append('payload_json', JSON.stringify(body));
      files.forEach((f, i) => fd.append(f.field ?? `files[${i}]`, new Blob([f.data], { type: f.type }), f.name));
      for (const [k, v] of Object.entries(files.fields ?? {})) fd.append(k, v);
      init.body = fd;
    } else if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    let res;
    try {
      res = await fetch(API + path, init);
    } catch (e) {
      if (attempt < 5) { await sleep(1000 * 2 ** attempt); continue; }
      throw e;
    }
    if (res.headers.get('x-ratelimit-remaining') === '0') {
      nextAt.set(key, Date.now() + Number(res.headers.get('x-ratelimit-reset-after') ?? 1) * 1000 + 50);
    }
    if (res.status === 429) {
      const j = await res.json().catch(() => ({}));
      await sleep((j.retry_after ?? 1) * 1000 + 100);
      continue;
    }
    if (res.status >= 500 && attempt < 5) { await sleep(1000 * 2 ** attempt); continue; }
    if (res.status === 204) return null;
    const text = await res.text();
    let json;
    try { json = JSON.parse(text); } catch { json = text; }
    if (!res.ok) throw new ApiError(method, path, res.status, json);
    return json;
  }
}

// ---------- state ----------
let STATE_PATH = '';
let S = null;
function loadState(guildId) {
  const dir = join(REPO, 'target', 'discord-test-guild');
  mkdirSync(dir, { recursive: true });
  STATE_PATH = join(dir, `${guildId}.json`);
  S = existsSync(STATE_PATH) ? JSON.parse(readFileSync(STATE_PATH, 'utf8'))
    : { guild: guildId, roles: {}, channels: {}, webhooks: {}, emojis: {}, stickers: {}, msgs: {}, threads: {}, done: {}, skipped: [] };
}
function save() {
  writeFileSync(STATE_PATH, JSON.stringify(S, null, 2), { mode: 0o600 });
  chmodSync(STATE_PATH, 0o600);
}
async function step(name, fn) {
  if (S.done[name]) { console.log(`  ✓ ${name} (done before)`); return; }
  process.stdout.write(`  … ${name}\n`);
  await fn();
  S.done[name] = true;
  save();
}
async function maybe(label, fn) {
  try { return await fn(); } catch (e) {
    console.log(`    ! skipped: ${label}: ${e.message}`);
    S.skipped.push(`${label}: ${e.message}`);
    save();
    return null;
  }
}

// ---------- the server ----------
const PERSONAS = ['Ada', 'Bob.Builder', 'bob_builder', 'Çağla Ünal', '🦊 Fox', '[admin]* tricky',
  'A very long display name that goes on and on, longer than a name here may be'];
const CROWD = Array.from({ length: 17 }, (_, i) => `crowd-${String(i + 1).padStart(2, '0')}`);
const ROLES = [
  // key, name, permissions, colour, hoist, mentionable
  ['admin', 'Admin', P.ADMIN, 0xe74c3c, true, false],
  ['mod', 'Moderator', bits(P.KICK, P.BAN, P.MANAGE_MESSAGES, P.MODERATE, P.AUDIT_LOG, P.MUTE), 0x3498db, true, true],
  ['keeper', 'Role Keeper', bits(P.ROLES, P.NICKNAMES), 0x1abc9c, false, false],
  ['artist', 'Emote Artist', bits(P.EXPRESSIONS, P.CREATE_EXPRESSIONS), 0x9b59b6, false, false],
  ['host', 'Event Host', bits(P.EVENTS, P.THREADS, P.PIN, P.MOVE, P.MANAGE_GUILD, P.BYPASS_SLOW, P.WEBHOOKS), 0xe67e22, false, false],
  ['announcer', 'Announcer', bits(P.MENTION_EVERYONE, P.MANAGE_CHANNELS), 0xf1c40f, false, true],
  ['vip', 'VIP', 0n, 0xd4af37, true, true],
  ['members', 'Members', 0n, 0x95a5a6, false, false],
  ['muted', 'Muted', 0n, 0x2c3e50, false, false],
  ['unicode', 'Ünïcødé ✨ Rôle', 0n, 0xff69b4, false, false],
  ['dot', 'Gold.Star', 0n, 0xffd700, false, false],
  ['underscore', 'Gold_Star', 0n, 0xdaa520, false, false],
  ['long', 'A role name of a hundred characters, which is the most Discord allows for a role name, padded out...', 0n, 0x7f8c8d, false, false],
  ['nocolour', 'No Colour', 0n, 0, false, false],
  ...CROWD.map((n) => [n, n, 0n, 0, false, false]),
];

function channelSpec(ownerId) {
  const ow = (who, allow = [], deny = []) => ({ who, allow: bits(...allow), deny: bits(...deny) });
  const staff = [ow('everyone', [], [P.VIEW]), ow('mod', [P.VIEW]), ow('admin', [P.VIEW])];
  return [
    // key, name, type, parent, extras
    ['cat_info', '📢 Info', 4, null, {}],
    ['cat_chat', '💬 Chat', 4, null, {}],
    ['cat_staff', '🔒 Staff', 4, null, { ow: staff }],
    ['cat_voice', '🎮 Voice', 4, null, {}],
    ['cat_archive', '📦 Archive', 4, null, {}],
    ['rules', 'rules', 0, 'cat_info', { topic: 'Rules channel (Community needs one).' }],
    ['welcome', 'welcome', 0, 'cat_info', { topic: `${MARKER}: made by testkit/7-discord-test-guild/setup.mjs` }],
    ['announcements', 'announcements', 5, 'cat_info', { topic: 'An announcement channel: comes as an announce channel.', community: true }],
    ['general', 'general', 0, 'cat_chat', { topic: 'Mentions, replies, pins, reactions, files, polls, stickers, embeds.', ow: [ow('muted', [], [P.SEND, P.ADD_REACTIONS])] }],
    ['offtopic', 'off-topic', 0, 'cat_chat', { topic: 'Slow mode 30 s.', slow: 30, ow: [ow('muted', [], [P.SEND])] }],
    ['nsfw', 'nsfw-test', 0, 'cat_chat', { topic: 'Age-restricted on Discord.', nsfw: true }],
    ['emotes', 'emote-test', 0, 'cat_chat', { topic: 'Custom emoji in text and in reactions.' }],
    ['bulk', 'bulk', 0, 'cat_chat', { topic: `${BULK} numbered messages: more than one page of Discord's 100.` }],
    ['threads', 'threads-test', 0, 'cat_chat', { topic: 'Public, archived, locked and private threads.' }],
    ['links', 'links-and-embeds', 0, 'cat_chat', { topic: 'Links, embeds, suppressed embeds.' }],
    ['modchat', 'mod-chat', 0, 'cat_staff', { topic: 'Private by its category.', ow: staff }],
    ['modlog', 'mod-log', 0, 'cat_staff', { topic: 'Admins only.', ow: [ow('everyone', [], [P.VIEW]), ow('admin', [P.VIEW])] }],
    ['lounge', 'Lounge', 2, 'cat_voice', { limit: 5 }],
    ['streamers', 'Streamers', 2, 'cat_voice', { ow: [ow('everyone', [], [P.STREAM]), ow('vip', [P.STREAM])] }],
    ['stage', 'Town Hall', 13, 'cat_voice', { community: true }],
    ['afk', 'AFK', 2, 'cat_voice', {}],
    ['forum', 'old-forum', 15, 'cat_archive', { topic: 'A forum: posts become threads in the archive pane.', tags: ['question', 'idea', 'solved'] }],
    ['media', 'media', 16, 'cat_archive', { topic: 'A media channel.', community: true }],
    ['general2', 'general', 0, 'cat_archive', { topic: 'A second channel named general.' }],
    ['nocat', 'no-category', 0, null, { topic: 'Outside any category.' }],
    ['histclosed', 'history-closed', 0, null, { topic: '@everyone may not read the history.', ow: [ow('everyone', [], [P.HISTORY])] }],
    ['vip', 'vip-lounge', 0, null, { topic: 'Private: VIP only.', ow: [ow('everyone', [], [P.VIEW]), ow('vip', [P.VIEW])] }],
    ['hidmuted', 'hidden-from-muted', 0, null, { topic: 'One role denied viewing.', ow: [ow('muted', [], [P.VIEW])] }],
    ['memberow', 'member-overwrite', 0, null, { topic: 'A rule for one person (the owner).', ow: [ow(`@${ownerId}`, [P.SEND, P.ADD_REACTIONS])] }],
    ['readonly', 'read-only', 0, null, { topic: 'Only Announcer may write.', ow: [ow('everyone', [], [P.SEND]), ow('announcer', [P.SEND])] }],
    ['manyroles', 'many-roles', 0, null, { topic: '17 roles may view: more than one gate holds.', ow: [ow('everyone', [], [P.VIEW]), ...CROWD.map((c) => ow(c, [P.VIEW]))] }],
    ['leaveout', 'leave-me-out', 0, null, { topic: 'Leave this one out in the wizard.' }],
    ['msgsoff', 'messages-off', 0, null, { topic: 'Turn its messages off in the wizard.' }],
    ['weird', 'über-straße_💬', 0, null, { topic: 'A name with umlauts and an emoji.' }],
  ];
}

let GUILD = null;
let BOT = null;
const R = (k) => (k === 'everyone' ? GUILD.id : S.roles[k]);
const C = (k) => S.channels[k];

async function overwrites(list) {
  return list.map(({ who, allow, deny }) => who.startsWith('@')
    ? { id: who.slice(1), type: 1, allow: String(allow), deny: String(deny) }
    : { id: R(who), type: 0, allow: String(allow), deny: String(deny) });
}

async function buildRoles() {
  const have = await api('GET', `/guilds/${GUILD.id}/roles`);
  for (const [key, name, perms, color, hoist, mentionable] of ROLES) {
    const found = have.find((r) => r.name === name && !r.managed);
    if (found) { S.roles[key] = found.id; continue; }
    const r = await api('POST', `/guilds/${GUILD.id}/roles`, { name, permissions: String(perms), color, hoist, mentionable });
    S.roles[key] = r.id;
    save();
  }
}

async function enableCommunity() {
  if (GUILD.features.includes('COMMUNITY')) return;
  await api('PATCH', `/guilds/${GUILD.id}`, {
    verification_level: Math.max(1, GUILD.verification_level),
    explicit_content_filter: 2,
    rules_channel_id: C('rules'),
    public_updates_channel_id: C('modlog'),
    features: [...GUILD.features, 'COMMUNITY'],
  });
  GUILD = await api('GET', `/guilds/${GUILD.id}`);
}

async function buildChannels(spec, { community }) {
  const have = await api('GET', `/guilds/${GUILD.id}/channels`);
  const make = async ([key, name, type, parent, x]) => {
    if (S.channels[key]) return;
    const found = have.find((c) => c.name === name && c.type === type && (c.parent_id ?? null) === (parent ? C(parent) : null));
    if (found) { S.channels[key] = found.id; return; }
    if (x.community && !community) { console.log(`    - ${name}: needs Community, left out`); return; }
    const body = { name, type };
    if (parent) body.parent_id = C(parent);
    if (x.topic) body.topic = x.topic;
    if (x.nsfw) body.nsfw = true;
    if (x.slow) body.rate_limit_per_user = x.slow;
    if (x.limit) body.user_limit = x.limit;
    if (x.ow) body.permission_overwrites = await overwrites(x.ow);
    if (x.tags) body.available_tags = x.tags.map((t) => ({ name: t }));
    const c = await maybe(`channel ${name}`, () => api('POST', `/guilds/${GUILD.id}/channels`, body));
    if (c) { S.channels[key] = c.id; save(); }
  };
  // Rules and the updates channel first: Community needs both.
  for (const k of ['cat_info', 'cat_staff', 'rules', 'modlog']) await make(spec.find((s) => s[0] === k));
  if (community) await maybe('Community', enableCommunity);
  community = GUILD.features.includes('COMMUNITY');
  for (const s of spec) await make(s);
}

async function hook(chKey) {
  if (S.webhooks[chKey]) return S.webhooks[chKey];
  const w = await api('POST', `/channels/${C(chKey)}/webhooks`, { name: 'voipc-test' });
  S.webhooks[chKey] = { id: w.id, token: w.token };
  save();
  return S.webhooks[chKey];
}

// A post by a persona (a webhook), or by the bot. Returns the message id.
async function say(chKey, who, content, { thread, threadName, tags, mentions } = {}) {
  const w = await hook(chKey);
  const q = new URLSearchParams({ wait: 'true' });
  if (thread) q.set('thread_id', thread);
  const body = { content, username: who, allowed_mentions: mentions ?? { parse: [] } };
  if (threadName) { body.thread_name = threadName; if (tags) body.applied_tags = tags; }
  const m = await api('POST', `/webhooks/${w.id}/${w.token}?${q}`, body, { auth: false });
  return m;
}
async function bot(chId, body, files) {
  return api('POST', `/channels/${chId}/messages`, { allowed_mentions: { parse: [] }, ...body }, files ? { files } : {});
}
function keep(key, m) { if (m) { S.msgs[key] = { ch: m.channel_id, id: m.id }; save(); } return m; }
async function react(ch, id, emoji) {
  return maybe(`reaction ${emoji}`, () => api('PUT', `/channels/${ch}/messages/${id}/reactions/${encodeURIComponent(emoji)}/@me`));
}
async function pin(ch, id) {
  return maybe('pin', async () => {
    try { return await api('PUT', `/channels/${ch}/messages/pins/${id}`); } catch (e) {
      if (e.status === 404) return api('PUT', `/channels/${ch}/pins/${id}`);
      throw e;
    }
  });
}
const rot = (i) => PERSONAS[i % PERSONAS.length];

async function buildEmotes() {
  const have = await api('GET', `/guilds/${GUILD.id}/emojis`);
  const list = [['vt_wave', 'wave'], ['vt_heart', 'heart'], ['VT_Caps', 'caps'], ['vt_vip_only', 'vip', ['vip']],
    ['vt_spin', 'spin'], ['vt_blink', 'blink']];
  for (const [name, img, roles] of list) {
    const found = have.find((e) => e.name === name);
    if (found) { S.emojis[name] = { id: found.id, animated: found.animated }; continue; }
    const e = await maybe(`emoji ${name}`, () => api('POST', `/guilds/${GUILD.id}/emojis`,
      { name, image: dataUri(IMAGES[img]()), roles: (roles ?? []).map(R) }));
    if (e) { S.emojis[name] = { id: e.id, animated: e.animated }; save(); }
  }
  const stickers = await api('GET', `/guilds/${GUILD.id}/stickers`);
  for (const [name, img, type] of [['vt-sticker-png', 'stickerPng', 'image/png'], ['vt-sticker-apng', 'stickerApng', 'image/png'], ['vt-sticker-gif', 'stickerGif', 'image/gif']]) {
    const found = stickers.find((s) => s.name === name);
    if (found) { S.stickers[name] = found.id; continue; }
    const files = [{ field: 'file', name: `${name}.${type === 'image/gif' ? 'gif' : 'png'}`, type, data: IMAGES[img]() }];
    files.fields = { name, description: `Test sticker ${name}`, tags: 'smile' };
    const s = await maybe(`sticker ${name}`, () => api('POST', `/guilds/${GUILD.id}/stickers`, undefined, { files }));
    if (s) { S.stickers[name] = s.id; save(); }
  }
}
const emo = (name) => { const e = S.emojis[name]; return e ? `<${e.animated ? 'a' : ''}:${name}:${e.id}>` : `:${name}:`; };
const emoReact = (name) => { const e = S.emojis[name]; return e ? `${name}:${e.id}` : null; };

const HOSTILE = [
  '<img src=x onerror=alert(1)> must show as text',
  '<script>alert("imported")</script> must show as text',
  '[click me](javascript:alert(1)) must not run',
  '![picture](https://example.com/x.png) a markdown picture',
  '```\n@everyone inside a code block\n<@&123>\n```',
  'Right-to-left override: abc‮dcba, zero width: ad​min',
  'A word with no spaces: ' + 'x'.repeat(500),
  'Unknown ones: <@999999999999999999> <@&999999999999999999> <#999999999999999999>',
  'Search traps: *star* [bracket] %percent% _under_ \\backslash',
];

async function buildMessages(ownerId) {
  const G = C('general');
  await step('messages #general', async () => {
    const g1 = keep('g1', await say('general', 'Ada', 'Hello everyone! This server is a test copy for the VoIPC move. 👋'));
    await say('general', 'Bob.Builder', 'Hi Ada. **Bold**, *italic*, __underline__, ~~strike~~, ||spoiler||, `inline code`, > not a quote here');
    await say('general', 'bob_builder', 'Bob.Builder and bob_builder clean to the same name here: which one keeps it?');
    const g4 = keep('g4', await say('general', 'Çağla Ünal', 'Ünïcødé names and text: Grüße, こんにちは, مرحبا, 🎉'));
    keep('g5', await bot(G, { content: 'A reply by the bot to Ada\'s first post.', message_reference: { message_id: g1.id, fail_if_not_exists: false } }));
    keep('g6', await say('general', '🦊 Fox', `Mentions: <@${ownerId}> (the owner), <@&${R('mod')}> (a role), <#${C('offtopic')}> (a channel).`,
      { mentions: { parse: [], users: [ownerId], roles: [R('mod')] } }));
    keep('g7', await bot(G, { content: '@everyone this one pings everyone, once, so the mention comes as a real one.', allowed_mentions: { parse: ['everyone'] } }));
    await say('general', 'Ada', '@here written as text, without a ping.');
    const g9 = keep('g9', await bot(G, { content: '', embeds: [{ title: 'An embed with no text beside it', description: 'Its title is what comes. **Markdown** and a [link](https://example.com).', color: 0x3498db }] }));
    keep('g10', await maybe('poll', () => bot(G, { poll: { question: { text: 'Does the poll question come over?' }, answers: [{ poll_media: { text: 'Yes' } }, { poll_media: { text: 'No' } }], duration: 24, allow_multiselect: false } })));
    if (S.stickers['vt-sticker-png']) keep('g11', await maybe('sticker post', () => bot(G, { sticker_ids: [S.stickers['vt-sticker-png']] })));
    const g12 = keep('g12', await bot(G, { content: 'Two files: their names come, the files do not.', attachments: [{ id: 0, filename: 'Ünïcode notes (1).txt' }, { id: 1, filename: 'picture.png' }] },
      [{ name: 'Ünïcode notes (1).txt', type: 'text/plain', data: Buffer.from('hello from the test guild\n') }, { name: 'picture.png', type: 'image/png', data: IMAGES.attachment() }]));
    for (const h of HOSTILE) await say('general', '[admin]* tricky', h);
    await bot(G, { content: ('The longest message Discord allows, 2000 characters. ' + 'Lorem ipsum dolor sit amet. '.repeat(80)).slice(0, 2000) });
    const g15 = keep('g15', await say('general', 'Ada', '🔥🔥🔥'));
    keep('g16', await say('general', 'Bob.Builder', emo('vt_wave')));
    const e = keep('g17', await bot(G, { content: 'Before the edit.' }));
    await api('PATCH', `/channels/${G}/messages/${e.id}`, { content: 'After the edit: only this text comes, Discord keeps no edit history for the bot.' });
    const gone = await bot(G, { content: 'Deleted on Discord before any run: must not come.' });
    await api('DELETE', `/channels/${G}/messages/${gone.id}`);
    await say('general', '🦊 Fox', '<t:1700000000:F> and <t:1700000000:R> are Discord timestamps.');
    await say('general', PERSONAS[6], 'My name is longer than a name here may be.');
    for (const m of [g1, g9, g12]) if (m) await pin(G, m.id);
    for (const r of ['👍', '❤️', '😂', emoReact('vt_wave'), emoReact('vt_spin')]) if (r) await react(G, g1.id, r);
    await react(G, g4.id, '🎉');
    const many = ['😀', '😃', '😄', '😁', '😆', '😅', '🤣', '😊', '😇', '🙂', '🙃', '😉', '😌', '😍', '🥰', '😘', '😗', '😙', '😚', '😋'];
    for (const r of many) await react(G, g15.id, r);
  });
  await step('messages #announcements', async () => {
    if (!C('announcements')) return;
    const a1 = keep('a1', await bot(C('announcements'), { content: 'Announcement one: version 1.11 is out.' }));
    await maybe('crosspost', () => api('POST', `/channels/${C('announcements')}/messages/${a1.id}/crosspost`));
    await say('announcements', 'Ada', 'Announcement two, by a webhook.');
    const t = await maybe('announcement thread', () => api('POST', `/channels/${C('announcements')}/messages/${a1.id}/threads`, { name: 'Talk about announcement one', auto_archive_duration: 1440 }));
    if (t) { S.threads.ann = t.id; await say('announcements', 'Bob.Builder', 'A reply in an announcement thread.', { thread: t.id }); }
    await maybe('forward', () => bot(G, { message_reference: { type: 1, message_id: a1.id, channel_id: C('announcements'), guild_id: GUILD.id } }));
  });
  await step('messages #threads-test', async () => {
    const T = C('threads');
    const t0 = await say('threads', 'Ada', 'Thread starter: the replies are in the thread below.');
    const t1 = await api('POST', `/channels/${T}/messages/${t0.id}/threads`, { name: 'Public thread from a message', auto_archive_duration: 1440 });
    S.threads.t1 = t1.id;
    for (let i = 0; i < 10; i++) await say('threads', rot(i), `Thread reply ${i + 1} of 10.`, { thread: t1.id });
    const t2 = await api('POST', `/channels/${T}/threads`, { name: 'A thread with no starter message', type: 11, auto_archive_duration: 1440 });
    S.threads.t2 = t2.id;
    for (let i = 0; i < 3; i++) await say('threads', rot(i + 2), `No-starter thread, post ${i + 1}.`, { thread: t2.id });
    const t3 = await api('POST', `/channels/${T}/threads`, { name: 'Archived and locked thread', type: 11, auto_archive_duration: 60 });
    S.threads.t3 = t3.id;
    for (let i = 0; i < 3; i++) await say('threads', rot(i + 4), `Archived thread, post ${i + 1}.`, { thread: t3.id });
    await api('PATCH', `/channels/${t3.id}`, { archived: true, locked: true });
    const t4 = await maybe('private thread', () => api('POST', `/channels/${T}/threads`, { name: 'Private thread: never moves', type: 12, invitable: false }));
    if (t4) { S.threads.t4 = t4.id; await bot(t4.id, { content: 'In a private thread: this must not come.' }); }
    const long = 'A thread title of a hundred characters, the longest Discord allows for a thread name, padded out ...'.slice(0, 100);
    const t5 = await api('POST', `/channels/${T}/threads`, { name: long, type: 11, auto_archive_duration: 1440 });
    await say('threads', 'Ada', 'Under the longest title.', { thread: t5.id });
    const t6s = await say('threads', 'Bob.Builder', 'This starter is deleted after its thread opens.');
    const t6 = await api('POST', `/channels/${T}/messages/${t6s.id}/threads`, { name: 'Thread whose starter was deleted', auto_archive_duration: 1440 });
    for (let i = 0; i < 2; i++) await say('threads', rot(i), `Reply ${i + 1} under a deleted starter.`, { thread: t6.id });
    await api('DELETE', `/channels/${T}/messages/${t6s.id}`);
  });
  await step('messages #old-forum', async () => {
    if (!C('forum')) return;
    const f = await api('GET', `/channels/${C('forum')}`);
    const tag = (n) => f.available_tags?.find((t) => t.name === n)?.id;
    const post = async (title, tags, lines) => {
      const m = await say('forum', lines[0][0], lines[0][1], { threadName: title, tags: tags.map(tag).filter(Boolean) });
      for (const [who, text] of lines.slice(1)) await say('forum', who, text, { thread: m.channel_id });
      return m.channel_id;
    };
    await post('How do I join voice?', ['question'], [['Ada', 'Where is the voice button?'], ['Bob.Builder', 'Bottom left.'], ['Ada', 'Found it, thanks.'], ['🦊 Fox', 'Tagged solved? No, tags do not come.']]);
    await post('Idea: dark mode', ['idea'], [['Çağla Ünal', 'Could we have a darker theme?'], ['Ada', '+1']]);
    const old = await post('An old forum post, archived', ['solved'], [['Bob.Builder', 'This post is archived.']]);
    await maybe('archive forum post', () => api('PATCH', `/channels/${old}`, { archived: true }));
  });
  await step(`messages #bulk (${BULK})`, async () => {
    // Webhook and bot by turns: Discord holds webhooks to about 30 posts a minute per channel.
    for (let i = 1; i <= BULK; i++) {
      const text = `bulk ${String(i).padStart(4, '0')} of ${BULK}`;
      if (i % 2) await say('bulk', rot(i), text); else await bot(C('bulk'), { content: text });
      if (i % 50 === 0) process.stdout.write(`    ${i}/${BULK}\n`);
    }
  });
  await step('messages, the other channels', async () => {
    for (let i = 0; i < 5; i++) await say('offtopic', rot(i), `Off-topic post ${i + 1}.`);
    await say('nsfw', 'Ada', 'A post in an age-restricted channel.');
    await say('nsfw', 'Bob.Builder', 'Second post there.');
    const em = await say('emotes', 'Ada', `Every custom emoji: ${Object.keys(S.emojis).map(emo).join(' ')}`);
    for (const n of Object.keys(S.emojis)) { const r = emoReact(n); if (r) await react(C('emotes'), em.id, r); }
    await say('links', 'Ada', 'https://example.com gets an embed from Discord.');
    await bot(C('links'), { content: 'https://example.org with its embed suppressed.', flags: 4 });
    await say('links', 'Bob.Builder', '<https://example.net> in angle brackets: no embed.');
    await bot(C('links'), { content: 'An embed with fields.', embeds: [{ title: 'Fields', fields: [{ name: 'One', value: '1', inline: true }, { name: 'Two', value: '2', inline: true }] }] });
    for (let i = 0; i < 4; i++) await say('modchat', rot(i), `Staff-only post ${i + 1}: must stay behind a gate.`);
    await say('modlog', 'Ada', 'Admins-only post.');
    for (let i = 0; i < 3; i++) await say('vip', rot(i), `VIP-only post ${i + 1}.`);
    for (let i = 0; i < 3; i++) await say('histclosed', rot(i), `History-closed post ${i + 1}: its messages start off.`);
    await say('hidmuted', 'Ada', 'Hidden from @Muted only.');
    await say('memberow', 'Ada', 'This channel has a rule for one person.');
    await bot(C('readonly'), { content: 'Read-only for @everyone; Announcer may write.' });
    await say('manyroles', 'Ada', 'Seventeen roles may read this.');
    for (let i = 0; i < 2; i++) await say('leaveout', rot(i), `Leave-me-out post ${i + 1}: must not come when left out.`);
    for (let i = 0; i < 5; i++) await say('msgsoff', rot(i), `Messages-off post ${i + 1}: the channel comes, this does not.`);
    await say('weird', 'Çağla Ünal', 'A post in über-straße_💬.');
    await say('nocat', 'Ada', 'A post outside any category.');
    await say('general2', 'Ada', 'A post in the second #general.');
    await maybe('text in a voice channel', () => bot(C('lounge'), { content: 'Text chat inside a voice channel.' }));
    await bot(C('welcome'), { content: '', embeds: [{ title: 'Welcome', description: 'This server was made by setup.mjs for a VoIPC move test.' }] });
    await bot(C('rules'), { content: '# Rules\n1. Be kind.\n2. This is a test server.\n- a list\n- of points' });
  });
}

async function buildExtras() {
  await maybe('scheduled event', () => api('POST', `/guilds/${GUILD.id}/scheduled-events`, {
    name: 'An event that does not move', privacy_level: 2, entity_type: 3,
    scheduled_start_time: new Date(Date.now() + 7 * 864e5).toISOString(),
    scheduled_end_time: new Date(Date.now() + 7 * 864e5 + 36e5).toISOString(),
    entity_metadata: { location: 'Nowhere' },
  }));
  await maybe('automod rule', () => api('POST', `/guilds/${GUILD.id}/auto-moderation/rules`, {
    name: 'A rule that does not move', event_type: 1, trigger_type: 1,
    trigger_metadata: { keyword_filter: ['forbiddenword'] }, actions: [{ type: 1 }], enabled: true,
  }));
}

async function invite() {
  if (S.invite) return S.invite;
  const inv = await api('POST', `/channels/${C('welcome')}/invites`, { max_age: 7 * 86400, max_uses: 0, unique: true });
  S.invite = `https://discord.gg/${inv.code}`;
  save();
  return S.invite;
}

// ---------- finding the server, inviting the bot ----------
function openUrl(url) {
  const [c, a] = process.platform === 'darwin' ? ['open', [url]] : process.platform === 'win32' ? ['cmd', ['/c', 'start', '', url]] : ['xdg-open', [url]];
  try { spawn(c, a, { detached: true, stdio: 'ignore' }).on('error', () => {}).unref(); } catch {}
}
async function checkApp() {
  const app = await api('GET', '/applications/@me');
  BOT = await api('GET', '/users/@me');
  const f = BigInt(app.flags ?? 0);
  const has = (m) => (f & m) !== 0n;
  const problems = [];
  if (!has(B(14) | B(15))) problems.push('Server Members Intent is off (Bot tab)');
  if (!has(B(18) | B(19))) problems.push('Message Content Intent is off (Bot tab)');
  console.log(`Application "${app.name}" (${app.id}), bot ${BOT.username}.`);
  if (app.bot_public) console.log('  note: Public Bot is on; MOVING.md says turn it off.');
  if (problems.length) {
    console.log(`  ✗ ${problems.join('; ')}.\n  Turn them on at https://discord.com/developers/applications/${app.id}/bot, then run this again.`);
    process.exit(1);
  }
  return app;
}
async function findGuild(app) {
  const want = opt('guild');
  let guilds = await api('GET', '/users/@me/guilds');
  if (want && guilds.some((g) => g.id === want)) return want;
  if (!want) {
    const ours = guilds.filter((g) => existsSync(join(REPO, 'target', 'discord-test-guild', `${g.id}.json`)));
    if (ours.length === 1) return ours[0].id;
    if (ours.length > 1) { console.log(`Several test servers: pass --guild (${ours.map((g) => `${g.id} "${g.name}"`).join(', ')}).`); process.exit(1); }
    if (cmd !== 'build') { console.log('No test server known here: run the build first, or pass --guild <id>.'); process.exit(1); }
    console.log('(If the bot is already in the test server, stop this and pass --guild <server id>.)');
  }
  const url = `https://discord.com/oauth2/authorize?client_id=${app.id}&scope=bot&permissions=8&integration_type=0`
    + (want ? `&guild_id=${want}&disable_guild_select=true` : '');
  console.log(`\nInvite the bot to your EMPTY test server (Administrator, as MOVING.md asks):\n\n  ${url}\n`);
  openUrl(url);
  const before = new Set(guilds.map((g) => g.id));
  const end = Date.now() + 15 * 60e3;
  process.stdout.write('Waiting for the bot to join');
  while (Date.now() < end) {
    await sleep(3000);
    process.stdout.write('.');
    guilds = await api('GET', '/users/@me/guilds');
    const hit = want ? guilds.find((g) => g.id === want) : guilds.find((g) => !before.has(g.id));
    if (hit) { console.log(` joined "${hit.name}".`); return hit.id; }
  }
  console.log('\nGave up after 15 minutes.');
  process.exit(1);
}
async function checkEmpty() {
  const channels = await api('GET', `/guilds/${GUILD.id}/channels`);
  const ours = existsSync(STATE_PATH) || channels.some((c) => (c.topic ?? '').includes(MARKER));
  if (ours) return;
  const roles = await api('GET', `/guilds/${GUILD.id}/roles`);
  const members = GUILD.approximate_member_count ?? 0;
  const plain = roles.filter((r) => !r.managed && r.id !== GUILD.id).length;
  if (channels.length > 6 || plain > 0 || members > 5) {
    console.log(`"${GUILD.name}" is not empty (${channels.length} channels, ${plain} roles, ${members} members) and was not made by this script. Refusing.`);
    process.exit(1);
  }
}

// ---------- commands ----------
async function build() {
  const app = await checkApp();
  const id = await findGuild(app);
  GUILD = await api('GET', `/guilds/${id}?with_counts=true`);
  loadState(id);
  await checkEmpty();
  console.log(`\nBuilding "${GUILD.name}" (${GUILD.id}). State: ${STATE_PATH}`);
  const ownerId = GUILD.owner_id;
  await step('roles', buildRoles);
  await step('channels', () => buildChannels(channelSpec(ownerId), { community: !flag('no-community') }));
  await step('emoji and stickers', buildEmotes);
  await buildMessages(ownerId);
  await step('event and automod rule', buildExtras);
  await step('owner roles', async () => {
    for (const k of ['announcer', 'unicode']) await maybe(`owner role ${k}`, () => api('PUT', `/guilds/${GUILD.id}/members/${ownerId}/roles/${R(k)}`));
  });
  const link = await invite();
  console.log(`\nDone. Skipped: ${S.skipped.length ? '\n  ' + S.skipped.join('\n  ') : 'nothing'}`);
  console.log(`\nInvite link for your second (and third) Discord account, valid 7 days:\n\n  ${link}\n`);
  console.log('Next: README.md, "Before run 1": the hand-written posts and `setup.mjs members`.');
}

async function members() {
  const app = await checkApp();
  const id = await findGuild(app);
  GUILD = await api('GET', `/guilds/${id}`);
  loadState(id);
  const give = async (user, keys, nick) => {
    for (const k of keys) await maybe(`role ${k} to ${user}`, () => api('PUT', `/guilds/${GUILD.id}/members/${user}/roles/${R(k)}`));
    if (nick) await maybe(`nick for ${user}`, () => api('PATCH', `/guilds/${GUILD.id}/members/${user}`, { nick }));
  };
  if (opt('mod')) await give(opt('mod'), ['mod', 'vip', 'members', 'dot', 'unicode', 'host', 'artist'], 'Mod.Nick');
  if (opt('vip')) await give(opt('vip'), ['vip', 'members', 'underscore', ...CROWD]);
  if (opt('plain')) await give(opt('plain'), ['members']);
  if (opt('ban')) {
    await maybe('ban', () => api('PUT', `/guilds/${GUILD.id}/bans/${opt('ban')}`, { delete_message_seconds: 0 }, { reason: 'voipc move test' }));
    S.banned = opt('ban');
    save();
  }
  const list = await api('GET', `/guilds/${GUILD.id}/members?limit=1000`);
  console.log(`Members now: ${list.map((m) => `${m.user.username}${m.user.bot ? ' (bot)' : ''} [${m.roles.length} roles]`).join(', ')}`);
}

async function change() {
  const app = await checkApp();
  const id = await findGuild(app);
  GUILD = await api('GET', `/guilds/${id}`);
  loadState(id);
  console.log(`Changes for run 2 in "${GUILD.name}".`);
  await step('change: new posts', async () => {
    for (let i = 1; i <= 10; i++) await say('general', rot(i), `after run 1: new post ${i} of 10`);
    for (let i = 1; i <= 10; i++) await say('bulk', rot(i), `after run 1: bulk extra ${i} of 10`);
    if (S.threads.t1) await say('threads', 'Ada', 'after run 1: a new reply in the public thread', { thread: S.threads.t1 });
  });
  await step('change: new channels', async () => {
    const pub = await api('POST', `/guilds/${GUILD.id}/channels`, { name: 'new-after-run-1', type: 0, topic: 'Made after run 1: starts on.' });
    S.channels.newpub = pub.id;
    for (let i = 1; i <= 3; i++) await say('newpub', rot(i), `new channel post ${i}`);
    const priv = await api('POST', `/guilds/${GUILD.id}/channels`, { name: 'new-private-after-run-1', type: 0, permission_overwrites: await overwrites([{ who: 'everyone', allow: 0n, deny: P.VIEW }, { who: 'vip', allow: P.VIEW, deny: 0n }]) });
    S.channels.newpriv = priv.id;
    await say('newpriv', 'Ada', 'new private channel post: starts off');
  });
  await step('change: off-topic closed on Discord', async () => {
    await api('PUT', `/channels/${C('offtopic')}/permissions/${GUILD.id}`, { type: 0, allow: '0', deny: String(P.VIEW) });
  });
  await step('change: edits and deletes', async () => {
    if (S.msgs.g17) await api('PATCH', `/channels/${S.msgs.g17.ch}/messages/${S.msgs.g17.id}`, { content: 'Edited again after run 1: the copy here keeps the old text.' });
    if (S.msgs.g7) await maybe('delete g7', () => api('DELETE', `/channels/${S.msgs.g7.ch}/messages/${S.msgs.g7.id}`));
  });
  await step('change: renames and roles', async () => {
    await api('PATCH', `/channels/${C('emotes')}`, { name: 'emotes-renamed-on-discord' });
    await api('PATCH', `/guilds/${GUILD.id}/roles/${R('mod')}`, { permissions: String(bits(P.KICK, P.BAN, P.MANAGE_MESSAGES, P.MODERATE, P.AUDIT_LOG, P.MUTE, P.MANAGE_CHANNELS)), color: 0x2ecc71 });
    await api('PATCH', `/guilds/${GUILD.id}/roles/${R('nocolour')}`, { name: 'Renamed on Discord' });
  });
  await step('change: new emoji', async () => {
    const e = await maybe('emoji vt_new', () => api('POST', `/guilds/${GUILD.id}/emojis`, { name: 'vt_new', image: dataUri(png(128, 128, disc(128, 128, [46, 204, 113], 5))) }));
    if (e) S.emojis.vt_new = { id: e.id, animated: false };
  });
  await step('change: unban', async () => {
    if (S.banned) await maybe('unban', () => api('DELETE', `/guilds/${GUILD.id}/bans/${S.banned}`));
  });
  console.log(`Done. Skipped: ${S.skipped.length ? '\n  ' + S.skipped.join('\n  ') : 'nothing'}`);
}

async function status() {
  const app = await checkApp();
  const id = await findGuild(app);
  GUILD = await api('GET', `/guilds/${id}?with_counts=true`);
  loadState(id);
  const [channels, roles, emojis, stickers, bans] = await Promise.all([
    api('GET', `/guilds/${id}/channels`), api('GET', `/guilds/${id}/roles`), api('GET', `/guilds/${id}/emojis`),
    api('GET', `/guilds/${id}/stickers`), api('GET', `/guilds/${id}/bans`),
  ]);
  console.log(`"${GUILD.name}" ${id}: ${channels.length} channels, ${roles.length} roles, ${emojis.length} emoji, ${stickers.length} stickers, ${bans.length} bans, about ${GUILD.approximate_member_count} members. Community: ${GUILD.features.includes('COMMUNITY')}.`);
  console.log(`Steps done: ${Object.keys(S.done).join(', ') || 'none'}.`);
  if (S.invite) console.log(`Invite: ${S.invite}`);
}

TOKEN = await readToken();
if (!/^[\w-]+\.[\w-]+\.[\w-]+$/.test(TOKEN)) { console.log('That does not look like a bot token.'); process.exit(1); }
try {
  await ({ build, members, change, status }[cmd] ?? (() => { console.log(`unknown command ${cmd}`); process.exit(2); }))();
} catch (e) {
  console.error(`\nStopped: ${e.message}\nRun the same command again: finished steps are skipped.`);
  process.exit(1);
}
