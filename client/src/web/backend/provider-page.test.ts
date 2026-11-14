import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const { NOT_A_PROVIDERS_PAGE, openProviderPage } = await import("./provider-page.ts");

test("a page that is no provider's is not opened", () => {
  const opened: string[] = [];
  const ok = (url: string) => url.startsWith("https://discord.com/oauth2/authorize?");
  assert.throws(() => openProviderPage("https://evil.example/", ok, (u) => opened.push(u)), (e) => e === NOT_A_PROVIDERS_PAGE);
  assert.deepEqual(opened, []);
  openProviderPage("https://discord.com/oauth2/authorize?x=1", ok, (u) => opened.push(u));
  assert.deepEqual(opened, ["https://discord.com/oauth2/authorize?x=1"], "the control");
});

test("the backend's command opens a page through it, with the real check", () => {
  const commands = readFileSync(new URL("./commands.ts", import.meta.url), "utf8");
  const handler = commands.slice(commands.indexOf("account_open_page:"), commands.indexOf("account_provider_answer:"));
  assert.match(handler, /openProviderPage\(page, \(u\) => wasm\(\)\.providerPageOk\(u\)/);
  assert.doesNotMatch(handler, /window\.open\(page/, "and opens nothing on its own");
});
