// Headless two-browser end-to-end test of the web client.
//
// This one stays a bash script. Unlike the build scripts it has no PowerShell
// twin and duplicates nothing, so there is no consolidation to win here — and
// it is 140 lines of openssl certificate minting, NSS profile setup via
// certutil and headless browser wrangling that would only get longer, not
// clearer, in Node.
import { fail, run, which } from '../lib.mjs';

export default function testWeb(_task, args) {
  if (process.platform === 'win32') fail('the web end-to-end test only runs on Linux.');
  if (!which('bash')) fail('bash is required to run test-web.sh');
  run('bash', ['test-web.sh', ...args]);
}
