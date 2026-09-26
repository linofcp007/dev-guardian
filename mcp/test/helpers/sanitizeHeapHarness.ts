/**
 * Child-process harness for `rawReport.test.ts`'s heap check.
 *
 * Runs under `node --max-old-space-size=<MB> --import tsx` as its OWN
 * process, because what is under test is a FATAL heap exhaustion: V8 aborts
 * the process, nothing can catch it, and inside the MCP server it would take
 * the whole server down mid-`verify_live`. Only a separate process with a
 * small heap can watch that happen and report it as a test failure.
 *
 *   argv: <k>   — the number of long, non-overlapping findings
 *
 * Prints `ok <k> <leaked>` and exits 0 when the sanitizer finished.
 */
import { sanitizeGitleaksReport } from '../../src/secrets/verify/rawReport.js';
import { longSecretReport, longValue } from './longSecretReport.js';

const k = Number(process.argv[2]);
if (!Number.isInteger(k) || k <= 0) {
  process.stderr.write('usage: sanitizeHeapHarness <k>\n');
  process.exit(2);
}

const out = sanitizeGitleaksReport(longSecretReport(k), () => false);
if (out === null) {
  process.stderr.write('sanitizer returned null\n');
  process.exit(3);
}
let leaked = 0;
for (let n = 0; n < k; n += 1) if (out.text.includes(longValue(n).slice(40, 120))) leaked += 1;
process.stdout.write(`ok ${k} ${leaked}\n`);
