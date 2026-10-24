# 0.12.0 browser data (upgrade fixtures)

`voipc.settings.json` is what a browser that ran VoIPC 0.12.0 keeps under the localStorage key
`voipc.settings`. It was written on 2026-10-23 by **0.12.0's own `client/src/web/backend/config.ts`**
(`49bf256`), never by a later version, and is never regenerated. test-ui.mjs section 18 seeds it
into a fresh origin and checks that this version loads it as it is.

## How it was made

0.12.0's `config.ts`, bundled with this esbuild command:

    esbuild src/web/backend/config.ts --bundle --format=esm --platform=node \
      --define:__WEB__=true '--define:import.meta.env={}'

It was then run in node with a fake `localStorage`:

```js
// Runs 0.12.0's own web config module (bundled) against a fake localStorage
// and prints what it stores under voipc.settings.
const store = new Map();
globalThis.localStorage = {
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => store.set(k, String(v)),
  removeItem: (k) => store.delete(k),
};
globalThis.location = { hostname: 'voice.example.org', port: '9987', protocol: 'https:', host: 'voice.example.org:9987' };
const cfg = await import(process.argv[2]);
cfg.updateConfig((c) => Object.assign(c, {
  volume: 0.8,
  voice_mode: 'vad',
  vad_threshold_db: -42.5,
  last_username: 'luki',
  saved_servers: [{ name: 'Home', host: 'voice.example.org', port: 9987, username: 'luki', accept_self_signed: false, account: true }],
  ui_prefs: { layout: 'modern', zoom: 1.1 },
}));
process.stdout.write(JSON.stringify(JSON.parse(store.get('voipc.settings')), null, 2) + '\n');
```

The JSON was pretty-printed for review; it holds the same data `config.ts` stored.
