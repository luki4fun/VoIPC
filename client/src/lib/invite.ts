// Invite links: https://<host>:<port>/#channel=<name>[&password=<pw>]
//
// The server hosts the web client on its TLS port, so the link opens the web
// client directly; the desktop connect dialog accepts the same URL. Everything
// after '#' stays in the browser — a fragment is never sent to the server and
// never shows up in its logs. Channels are named, not numbered: ids change
// across server restarts, names of persistent channels do not.

import type { PendingInvite } from "./stores/connection.js";

export function buildInviteLink(
  host: string,
  port: number,
  channel: string,
  password: string | null,
): string {
  const h = host.includes(":") ? `[${host}]` : host;
  let link = `https://${h}:${port}/#channel=${encodeURIComponent(channel)}`;
  if (password) link += `&password=${encodeURIComponent(password)}`;
  return link;
}

/** The fragment ("channel=x&password=y", leading '#' optional) → invite, or null. */
export function parseInviteFragment(fragment: string): PendingInvite | null {
  const params = new URLSearchParams(fragment.replace(/^#/, ""));
  const channel = params.get("channel")?.trim();
  if (!channel) return null;
  return { channel, password: params.get("password") || null };
}

/** A full invite URL → server + invite, or null if it is not one. */
export function parseInviteLink(
  link: string,
): { host: string; port: number; invite: PendingInvite } | null {
  let url: URL;
  try {
    url = new URL(link.trim());
  } catch {
    return null;
  }
  if (url.protocol !== "https:") return null;
  const invite = parseInviteFragment(url.hash);
  if (!invite) return null;
  return {
    host: url.hostname.replace(/^\[|\]$/g, ""),
    port: url.port ? Number(url.port) : 443,
    invite,
  };
}

/**
 * "host", "host:port" or "[v6::addr]:port"; the port defaults to `port`. The
 * one address parser of the front end and the browser backend: null for a
 * bare IPv6 address without brackets, an empty host, or a junk port.
 */
export function parseHostPort(value: string, port = 9987): { host: string; port: number } | null {
  const bracketed = value.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (bracketed) return withPort(bracketed[1], bracketed[2] ?? null, port);
  const parts = value.split(":");
  if (parts.length === 1) return parts[0] ? { host: parts[0], port } : null;
  if (parts.length === 2 && parts[0]) return withPort(parts[0], parts[1], port);
  return null;
}

function withPort(host: string, typed: string | null, port: number): { host: string; port: number } | null {
  if (typed === null) return { host, port };
  const n = Number(typed);
  return /^\d+$/.test(typed) && n >= 1 && n <= 65535 ? { host, port: n } : null;
}

/** "host:port" / "[v6]:port" as kept in the serverAddress store → parts. */
export function splitAddress(address: string): { host: string; port: number } {
  return parseHostPort(address) ?? { host: address.replace(/^\[|\]$/g, ""), port: 9987 };
}
