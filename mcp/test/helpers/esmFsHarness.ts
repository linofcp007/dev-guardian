/**
 * Child-process harness for `esmFsImports.test.ts`.
 *
 * Runs under plain `node --import tsx` — real, UNBUNDLED ES modules, the way
 * `tsx` and the per-file `dist/` the CLI loads run them. That is the whole
 * point: vitest's module runner hands every module a CommonJS `require`, so a
 * stray `require('node:fs')` inside ESM cannot fail under vitest, while it
 * throws `require is not defined` everywhere else except the esbuild bundle.
 *
 *   argv: <tool-name> <json-input>
 *
 * Prints the tool's result as one JSON line on stdout.
 */
import { GuardianDatabase } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import '../../src/tools/wpVulnCheck.js';
import '../../src/tools/depsUpdatePlan.js';
import '../../src/tools/observabilitySetup.js';

const [name, rawInput] = process.argv.slice(2);
const tool = TOOLS.find((t) => t.name === name);
if (!tool || rawInput === undefined) {
  process.stderr.write(`usage: esmFsHarness <tool> <json-input> (unknown tool: ${name ?? ''})\n`);
  process.exit(2);
}
const db = new GuardianDatabase(':memory:');
runMigrations(db);
const result = await tool.handler(JSON.parse(rawInput) as Record<string, unknown>, {
  storage: new Storage(db),
  shell: null,
  scriptsDir: process.cwd(),
  progressNotifier: { send: () => {} },
});
process.stdout.write(`${JSON.stringify(result)}\n`);
