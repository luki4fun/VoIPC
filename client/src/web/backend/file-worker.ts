// One seal or one open for files.ts, in a worker of its own: the main thread
// keeps sending voice meanwhile. The page ends the worker afterwards, and the
// wasm memory a big file grew (some 190 MiB for 64 MiB) goes with it.

import { initSync, openFile, sealFile } from "../../lib/wasm/voipc_web.js";
import { checkOpenInput, checkSealInput } from "./wasm";

self.onmessage = (e: MessageEvent) => {
  const job = e.data;
  try {
    // The page compiled the module once; instantiating it here is cheap
    initSync({ module: job.module });
    if (job.op === "seal") {
      checkSealInput(job.plain);
      const sealed = sealFile(job.plain, job.compress);
      self.postMessage({ ok: sealed }, { transfer: [sealed.blob.buffer] });
    } else {
      // A blob the page gave up (`give`) goes back to it with the file
      const blob: Uint8Array = job.give ?? job.blob;
      checkOpenInput(job.size, blob);
      const plain = openFile(job.hash, job.key, job.size, job.z, blob);
      const back = job.give ? [plain.buffer, blob.buffer] : [plain.buffer];
      self.postMessage({ ok: { plain, blob: job.give ? blob : undefined } }, { transfer: back });
    }
  } catch (err) {
    // An Error's name is a FileErrorName (wasm.ts)
    const e = err as Error;
    self.postMessage({ error: { name: e?.name ?? "Error", message: e?.message ?? String(err) } });
  }
};
