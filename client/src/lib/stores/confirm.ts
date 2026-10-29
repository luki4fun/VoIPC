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
}

interface Pending extends ConfirmRequest {
  resolve: (ok: boolean) => void;
}

export const pendingConfirm = writable<Pending | null>(null);

/** Ask; true when the person goes ahead. One question at a time: a second
 *  ask while one is open answers the first with "no". */
export function confirmAction(request: ConfirmRequest): Promise<boolean> {
  return new Promise((resolve) => {
    pendingConfirm.update((open) => {
      open?.resolve(false);
      return { ...request, resolve };
    });
  });
}

/** The dialog's answer. */
export function answerConfirm(ok: boolean): void {
  pendingConfirm.update((open) => {
    open?.resolve(ok);
    return null;
  });
}
