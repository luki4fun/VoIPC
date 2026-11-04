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
import type { AdminOp, AdminUser, AuditRow, ChannelGate, GroupInfo, InviteInfo, InviteLinkInfo } from "../types.js";

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
/** The last refusal, shown in the panel rather than as a toast. */
export const adminError = scoped<string | null>(() => null);
/** The step waiting for a code (`StepUp`). */
export const stepUp = scoped<AdminOp | null>(() => null);

/** The step sent last, per server: the one a `StepUp` is about (the relay
 *  answers a connection's requests in order). */
export const lastOp = new Map<string, AdminOp>();

export async function adminOp(op: AdminOp, code: string | null = null, server = get(serverAddress)): Promise<void> {
  lastOp.set(server, op);
  adminError.of(server).set(null);
  try {
    await invoke("account_request", { server, request: { Admin: { op, code } } });
  } catch (e) {
    adminError.of(server).set(String(e));
  }
}

