// One confirmation for everything that destroys or weakens something: clearing
// chat history, resetting settings, trusting a certificate that changed.
//
// These used to be judged one screen at a time — deleting an account needed
// DELETE typed out, while clearing every server's chat history was one click
// and then said "cleared" whether it worked or not. A caller now awaits
// `confirmAction`, and ConfirmDialog.svelte (mounted once, in App.svelte)
// asks, naming exactly what goes.

import { writable } from "svelte/store";

export interface ConfirmRequest {
  title: string;
  /** What happens, in plain words: what is lost, where, and for whom. */
  body: string;
  /** Extra lines under the body, e.g. the old and the new fingerprint. */
  details?: string[];
  /** The button that goes ahead: a verb, "Clear history", never "OK". */
  confirm: string;
  cancel?: string;
  /** Red for destroying; the accent for a risky-but-not-destructive yes. */
  danger?: boolean;
  /** A box to tick with the answer ("Don't ask again for this server"),
   *  unticked at first; `confirmChoice` hands back how it was left. */
  option?: string;
}

interface Pending extends ConfirmRequest {
  resolve: (ok: boolean, option: boolean) => void;
}

export const pendingConfirm = writable<Pending | null>(null);

/** Ask; true when the person goes ahead. One question at a time: a second
 *  ask while one is open answers the first with "no". */
export function confirmAction(request: ConfirmRequest): Promise<boolean> {
  return new Promise((resolve) => {
    pendingConfirm.update((open) => {
      open?.resolve(false, false);
      return { ...request, resolve: (ok) => resolve(ok) };
    });
  });
}

/** `confirmAction` with its `option` box: the answer, and whether the box
 *  was ticked. */
export function confirmChoice(request: ConfirmRequest & { option: string }): Promise<{ ok: boolean; option: boolean }> {
  return new Promise((resolve) => {
    pendingConfirm.update((open) => {
      open?.resolve(false, false);
      return { ...request, resolve: (ok, option) => resolve({ ok, option }) };
    });
  });
}

/** The dialog's answer, and its box where it has one. */
export function answerConfirm(ok: boolean, option = false): void {
  pendingConfirm.update((open) => {
    open?.resolve(ok, option);
    return null;
  });
}
