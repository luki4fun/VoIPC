// The admin panel's state for accounts, groups, invites and channel gates
// (1.7), and the one way to ask: `adminOp`, an `AccountRequest::Admin`. Its
// answers arrive as `account-reply`, which admin-ui.ts files into these.
//
// A leaf: channel-ui.ts reads it for a channel's gate, and admin-ui.ts
// imports connect.ts, which imports channel-ui.ts.

import { get } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";

import { serverAddress } from "./connection.js";
import { scoped } from "./scoped.js";
import type { AdminOp, AdminUser, AuditRow, ChannelGate, GroupInfo, InviteInfo, InviteLinkInfo, ModRow } from "../types.js";

export interface UserPage {
  search: string;
  offset: number;
  total: number;
  users: AdminUser[];
}
export interface UserDetail {
  user: AdminUser;
  groups: string[];
  audit: AuditRow[];
}
export interface MemberPage {
  name: string;
  offset: number;
  total: number;
  users: AdminUser[];
}
export interface GateView {
  channel_id: number;
  gate: ChannelGate;
  groups: string[];
}
export interface ModLogView {
  rows: ModRow[];
  more: boolean;
  keep_days: number;
}

export const adminUsers = scoped<UserPage | null>(() => null);
export const adminUser = scoped<UserDetail | null>(() => null);
export const adminGroups = scoped<GroupInfo[] | null>(() => null);
export const adminMembers = scoped<MemberPage | null>(() => null);
export const adminInvites = scoped<InviteInfo[] | null>(() => null);
/** A new invite's code, shown once. */
export const inviteCode = scoped<string | null>(() => null);
/** Reusable invite links, and a new one's code: shown once. */
export const adminInviteLinks = scoped<InviteLinkInfo[] | null>(() => null);
export const inviteLinkCode = scoped<string | null>(() => null);
export const adminGate = scoped<GateView | null>(() => null);
export const adminModLog = scoped<ModLogView | null>(() => null);
/** The last refusal, shown in the panel rather than as a toast. */
export const adminError = scoped<string | null>(() => null);
/** The step waiting for a code (`StepUp`). */
export const stepUp = scoped<AdminOp | null>(() => null);

export const isRemoval = (op: AdminOp | null): boolean => typeof op === "object" && !!op && "RemovePosts" in op;

/** Why a step asks for a code, wherever the question is put. */
export function stepUpSays(op: AdminOp | null): string {
  return isRemoval(op) ? "What this server keeps of their posts goes for good." : "This hands out power.";
}

/** The step sent last, per server: the one a `StepUp` is about (the relay
 *  answers a connection's requests in order). */
export const lastOp = new Map<string, AdminOp>();

/**
 * A moderator's own word for the log that they hid a message or showed it again.
 * Not through `adminOp`: it asks for no code, and a `StepUp` still waiting would
 * answer for this one (`lastOp`).
 */
export function modNote(server: string, channelId: number, target: string, message: string, on: boolean): void {
  const op: AdminOp = { ModNote: { channel_id: channelId, target, message, on } };
  invoke("account_request", { server, request: { Admin: { op, code: null } } }).catch((e: unknown) =>
    console.warn("a moderation note did not go:", e),
  );
}

export async function adminOp(op: AdminOp, code: string | null = null, server = get(serverAddress)): Promise<void> {
  lastOp.set(server, op);
  adminError.of(server).set(null);
  try {
    await invoke("account_request", { server, request: { Admin: { op, code } } });
  } catch (e) {
    adminError.of(server).set(String(e));
  }
}

