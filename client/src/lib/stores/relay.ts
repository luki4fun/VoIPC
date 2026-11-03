import { scoped } from "./scoped";

/** A relay of an older protocol than this app's (`relay-version`, 1.6): the
 *  one it speaks and the VoIPC it runs. Null where it speaks ours. */
export interface OlderRelay {
  protocol: number;
  version: string;
}

export const olderRelay = scoped<OlderRelay | null>(() => null);
