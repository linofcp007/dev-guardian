/**
 * Review 3.6.1, finding 7: `suggest_fix` could echo a nearby secret.
 *
 * It withholds the source around a credential finding, but for any other
 * finding it returned up to ±200 lines raw — including a secret on a nearby
 * line that gitleaks had flagged, or one no scan had seen. Now every line of
 * the excerpt that a credential finding of the project's scans points at is
 * withheld, and the excerpt goes through the hooks' secret detector, which
 * replaces each line holding a detected secret (`redaction/scrubSecrets.ts`,
 * shared with the LLM scan's briefs); `redacted_lines` names them.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { PluginContext } from '../../src/context.js';
import { resolveProjectPath } from '../../src/platform/projectPath.js';
import { makeFinding } from '../../src/runners/scannerParsers/index.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { Storage } from '../../src/storage/index.js';
import { TOOLS } from '../../src/tools/index.js';
import type { Finding, ScanType } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

beforeAll(async () => {
  await import('../../src/tools/suggestFix.js');
});
afterAll(cleanupTempDirs);

// Built at run time, so no file of this repository holds a token-shaped string.
const GITHUB_TOKEN = ['ghp', '_', 'aB3dE5', 'fG7hJ9', 'kL1mN2', 'pQ4rS6', 'tU8vW0', 'xY2zA4'].join('');
/** No detector rule matches this one: only the gitleaks finding on its line says it is a secret. */
const FLAGGED_ONLY = ['Zx9', 'kQ2', 'rT7', 'wL4', 'pVb'].join('');

function source(): string {
  const lines = Array.from({ length: 30 }, (_, i) => `// line ${String(i + 1)}`);
  lines[4] = `const token = "${GITHUB_TOKEN}";`;
  lines[11] = `const dbPass = "${FLAGGED_ONLY}";`;
  lines[19] = 'db.query("SELECT * FROM t WHERE id = " + req.query.id);';
  return lines.join('\n');
}

function seedScan(storage: Storage, id: string, type: ScanType, project: string, findings: Finding[]): void {
  storage.scans.insert({ scan_id: id, scan_type: type, project_path: project, tree_hash: 'h' });
  storage.findings.bulkInsert(findings.map((f) => ({ ...f, scan_id: id })));
  storage.scans.finalize({ scan_id: id, status: 'completed', tools_run: [{ name: type === 'secrets' ? 'gitleaks' : 'semgrep', status: 'ok' }], missing_tools: [] });
}

async function suggest(contextLines: number): Promise<{
  surrounding_source: string | null;
  redacted_lines?: number[];
}> {
  const project = resolveProjectPath(makeTempDir('suggest-redact-')).path;
  mkdirSync(join(project, 'src'));
  writeFileSync(join(project, 'src', 'config.js'), source());
  const db = new Database(':memory:');
  runMigrations(db);
  const storage = new Storage(db);
  const ctx: PluginContext = { storage, shell: null, scriptsDir: '', progressNotifier: { send: () => {} } };
  seedScan(storage, 'SEC', 'secrets', project, [
    makeFinding({
      tool: 'gitleaks',
      rule_id: 'generic-api-key',
      severity: 'high',
      category: 'security',
      subcategory: 'secret',
      title: 'Generic API Key',
      file_path: 'src/config.js',
      line_start: 12,
      line_end: 12,
      snippet: 'rule=generic-api-key',
    }),
  ]);
  const sqli = makeFinding({
    tool: 'semgrep',
    rule_id: 'javascript.lang.security.sqli',
    severity: 'high',
    category: 'security',
    title: 'SQL injection',
    file_path: 'src/config.js',
    line_start: 20,
    line_end: 20,
  });
  seedScan(storage, 'SAST', 'sast', project, [sqli]);
  const tool = TOOLS.find((t) => t.name === 'suggest_fix');
  if (!tool) throw new Error('suggest_fix is not registered');
  const r = await tool.handler({ project_path: project, finding_fingerprint: sqli.fingerprint, context_lines: contextLines }, ctx);
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  return r as unknown as { surrounding_source: string | null; redacted_lines?: number[] };
}

describe('suggest_fix never quotes a secret near the finding back', () => {
  it('a secret a credential finding flagged, and one the detector sees, are withheld; the rest is quoted', async () => {
    const out = await suggest(20);
    const text = out.surrounding_source ?? '';
    expect(text).not.toContain(GITHUB_TOKEN);
    expect(text).not.toContain(FLAGGED_ONLY);
    // The finding's own line and its neighbours are still there to fix.
    expect(text).toContain('>>    20: db.query("SELECT * FROM t WHERE id = " + req.query.id);');
    expect(text).toContain('      19: // line 19');
    expect(text).toMatch(/ {5}5: .*‹github-token/);
    expect(text).toMatch(/ {4}12: .*‹redacted: a credential finding \(generic-api-key\)/);
    expect(out.redacted_lines).toEqual([5, 12]);
  });

  it('nothing to withhold: nothing is, and redacted_lines is empty', async () => {
    const out = await suggest(3);
    expect(out.surrounding_source).toContain('>>    20:');
    expect(out.redacted_lines).toEqual([]);
  });
});
