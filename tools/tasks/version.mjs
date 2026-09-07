// Propagate (or verify) the workspace version across the files that repeat it.
import { ok, syncVersion } from '../lib.mjs';

export default function version(_task, args) {
  const check = args.includes('--check');
  const v = syncVersion({ check });
  ok(check ? `all version fields match Cargo.toml (${v})` : `version ${v} synced`);
}
