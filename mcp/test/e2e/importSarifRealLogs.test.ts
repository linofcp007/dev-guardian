/**
 * Real SARIF logs from Semgrep, CodeQL, Trivy and gitleaks through
 * `import_sarif` — the `sarif-import` feature's test plan T-21 (SC-001).
 *
 * The logs in `test/fixtures/sarif/real/` were produced by the tools
 * themselves (CodeQL's are its own action's published test data); how, with
 * which versions, and what was rewritten for portability is in that
 * directory's README. Each carries a quirk a synthetic log would not have
 * thought of:
 *
 *   - Semgrep 1.176 without `semgrep login`: every result's only fingerprint
 *     is the literal `matchBasedId/v1: "requires login"`, and the URIs use
 *     Windows separators under an undefined `%SRCROOT%`;
 *   - gitleaks with `--no-git`: every `partialFingerprints` value is "";
 *   - Trivy: `ROOTPATH` names a CI checkout that is not this project;
 *   - CodeQL: two runs in one log, `%SRCROOT%` with no base defined, a
 *     file-level result with no region, and an empty `partialFingerprints`.
 *
 * SC-001: each imports with 0 skipped, and every result that points into the
 * project is stored with its file — and its line, when it has one. Results are
 * matched to stored rows by (rule, file, line), so fingerprints every result
 * shares can never fold several results into one.
 */

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { freshPlugin, projectDir } from '../helpers/historySeed.js';
import { importOk, metaCounts, scanRow, writeSarif } from '../helpers/sarif.js';
import { cleanupTempDirs } from '../helpers/tempDir.js';

vi.setConfig({ testTimeout: 60_000 });

afterAll(cleanupTempDirs);
beforeAll(async () => {
  await import('../../src/registerAll.js');
});

const REAL = fileURLToPath(new URL('../fixtures/sarif/real/', import.meta.url));
// `.sarif.json`: the repository's .gitignore ignores `*.sarif` (scan output).
const LOGS = readdirSync(REAL).filter((f) => f.endsWith('.sarif.json')).sort();

interface RawResult {
  ruleId?: string;
  locations?: Array<{ physicalLocation?: { artifactLocation?: { uri?: string }; region?: { startLine?: number } } }>;
}
interface RawLog {
  runs: Array<{ tool: { driver: { name: string } }; results?: RawResult[] }>;
}

/** What a result of the log must become: `rule|file|line` (line empty when it has no region). */
function expectedKeys(results: readonly RawResult[]): string[] {
  const keys: string[] = [];
  for (const r of results) {
    const physical = r.locations?.[0]?.physicalLocation;
    const uri = physical?.artifactLocation?.uri;
    if (uri === undefined) continue;
    const file = decodeURIComponent(uri).replace(/\\/g, '/');
    keys.push(`${r.ruleId ?? ''}|${file}|${physical?.region?.startLine === undefined ? '' : String(physical.region.startLine)}`);
  }
  return [...new Set(keys)].sort();
}

describe('T-21 real logs of Semgrep, CodeQL, Trivy and gitleaks (SC-001)', () => {
  it('T-21 the fixtures hold a log of each of the four tools', () => {
    const tools = LOGS.map((f) => (JSON.parse(readFileSync(join(REAL, f), 'utf8')) as RawLog).runs.map((run) => run.tool.driver.name).join(','));
    const all = tools.join(',');
    for (const name of [/semgrep/i, /codeql|lgtm/i, /trivy/i, /gitleaks/i]) expect(all).toMatch(name);
  });

  it.each(LOGS)('T-21 %s: 0 skipped, and every result in the project stored with its file and line', async (name) => {
    const raw = JSON.parse(readFileSync(join(REAL, name), 'utf8')) as RawLog;
    const s = freshPlugin();
    const dir = projectDir('sarif-real-');
    const out = await importOk(s.plugin, dir, writeSarif(dir, `ci/${name.replace(/\.json$/, '')}`, readFileSync(join(REAL, name), 'utf8')));
    expect(out.runs).toHaveLength(raw.runs.length);
    raw.runs.forEach((run, i) => {
      const scanId = out.runs[i]?.scan_id ?? '';
      const scan = scanRow(s.plugin, scanId);
      expect(metaCounts(scan)['skipped'], `${name} run ${String(i)}`).toEqual([]);
      expect(scan.meta?.['source_tool']).toBe(run.tool.driver.name.trim());
      const stored = s.storage.findings
        .listByScan(scanId)
        .filter((f) => f.file_path !== undefined)
        .map((f) => `${f.rule_id ?? ''}|${f.file_path ?? ''}|${f.line_start === undefined ? '' : String(f.line_start)}`);
      expect([...new Set(stored)].sort(), `${name} run ${String(i)}: every located result kept its place`).toEqual(expectedKeys(run.results ?? []));
    });
  });
});
