// Web replacement for @tauri-apps/api/core: invoke() runs the command in the
// TypeScript backend instead of the Rust process.

import { dispatch } from "../backend/commands";

/**
 * Like Tauri's: `args` is the arguments, or the raw body of a command that
 * reads its request (send_file), whose other arguments are in `headers`.
 */
export async function invoke<T>(
  cmd: string,
  args?: Record<string, unknown> | Uint8Array | ArrayBuffer | number[],
  options?: { headers?: Record<string, string> },
): Promise<T> {
  const raw =
    args instanceof Uint8Array
      ? args
      : args instanceof ArrayBuffer
        ? new Uint8Array(args)
        : Array.isArray(args)
          ? Uint8Array.from(args)
          : null;
  const call = raw ? { body: raw, headers: options?.headers ?? {} } : (args as Record<string, unknown> | undefined);
  return (await dispatch(cmd, call ?? {})) as T;
}

// A test build's modified client (test-ui.mjs): a command as the components send it, past
// what they check first, such as the composer's 16 KiB, to see what a reader keeps of it
if (__SELFTEST__) (window as unknown as { __voipc_invoke: unknown }).__voipc_invoke = invoke;

/**
 * The apps' own URI schemes (the share view's frame queue, native-view.ts) have no page to
 * serve them here: the browser decodes a share itself and never pulls from one.
 */
export function convertFileSrc(path: string, protocol = "asset"): string {
  throw new Error(`${protocol}://${path}: not in the browser`);
}
