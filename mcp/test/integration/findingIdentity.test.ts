/**
 * The reproductions behind line-independent finding identity, end to end.
 *
 * Every one of these was reproduced against the fingerprint alone, which
 * hashes `line_start`/`line_end`/the snippet: insert ONE line above a finding
 * and it became a different finding to every consumer —
 *
 *   - a suppression lapsed, and the finding came back as open;
 *   - the CI gate reported it as new (`newFindings after 1-line shift: 1`);
 *   - `diff_scans` / `regression_alert` saw one new + one resolved;
 *   - `create_fix_pr` judged an UNFIXED target "resolved" when an autofix
 *     above it moved it down a line (`judgeScan passed:true`).
 *
 * The scanner here is the real scan-tool factory and the real Semgrep parser,
 * fed the JSON modern Semgrep actually emits without `semgrep login` — real
 * line numbers, `extra.lines: "requires login"` — computed from files on disk,
 * so the identity has to come from the source text the way it does in the
 * field. `test/e2e/findingIdentityFixture.test.ts` repeats the core of this
 * with the real binary.
 */

import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { z } from 'zod';
import { buildBaseline, newFindings, parseBaseline, serialiseBaseline } from '../../src/ci/baseline.js';
import type { PluginContext } from '../../src/context.js';
import { judgeScan } from '../../src/fixpr/verify.js';
import { semgrepParser } from '../../src/runners/scannerParsers/semgrep.js';
import { trivyParser } from '../../src/runners/scannerParsers/trivy.js';
import { GuardianDatabase as Database } from '../../src/storage/db.js';
import { Storage } from '../../src/storage/index.js';
import { runMigrations } from '../../src/storage/migrations/runner.js';
import { TOOLS } from '../../src/tools/index.js';
import { makeScanTool, type ScannerInvocation } from '../../src/tools/scanToolFactory.js';
import type { Finding } from '../../src/types.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';
import { okResult } from '../helpers/toolResult.js';

beforeAll(async () => {
  await import('../../src/tools/suppressFinding.js');
  await import('../../src/tools/diffScans.js');
  await import('../../src/tools/regressionAlert.js');
});
afterAll(cleanupTempDirs);

function getTool(name: string) {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`Tool '${name}' not registered`);
  return t;
}

function makePlugin(): PluginContext {
  const db = new Database(':memory:');
  runMigrations(db);
  return {
    storage: new Storage(db),
    shell: { command: 'bash', args_prefix: [], needs_wsl_path_translate: false, label: 'fake' },
    scriptsDir: '.',
    progressNotifier: { send: () => {} },
  };
}

// ------------------------------------------------------------ the scanner

const RULE = 'javascript.lang.security.eval-detected';

/** Semgrep's JSON for every `eval(` line in the project's .js files — the
 *  shape 1.120+ emits without login: real positions, redacted text. */
function semgrepJson(projectPath: string): string {
  const results: unknown[] = [];
  for (const name of readdirSync(projectPath).filter((n) => n.endsWith('.js')).sort()) {
    const lines = readFileSync(join(projectPath, name), 'utf8').split(/\r?\n/);
    lines.forEach((text, i) => {
      if (!text.includes('eval(')) return;
      results.push({
        check_id: RULE,
        path: name,
        start: { line: i + 1, col: 1 },
        end: { line: i + 1, col: text.length + 1 },
        extra: {
          severity: 'ERROR',
          message: 'eval() on user input',
          lines: 'requires login',
          metadata: { category: 'security' },
        },
      });
    });
  }
  return JSON.stringify({ results, errors: [], paths: { scanned: ['x'] } });
}

const probeScan = makeScanTool({
  name: 'identity_probe_scan',
  scan_type: 'sast',
  category: 'security',
  description: '',
  inputSchema: { project_path: z.string().optional(), force: z.boolean().optional() },
  invoke: async (_input, ctx): Promise<ScannerInvocation> => ({
    outcome: 'completed',
    tools_run: [{ name: 'semgrep', status: 'ok' }],
    missing_tools: [],
    parser_inputs: [{ parser: semgrepParser, input: semgrepJson(ctx.projectPath) }],
    report_paths: [],
  }),
});

async function scan(plugin: PluginContext, projectPath: string): Promise<{ scan_id: string; findings: Finding[] }> {
  const r = okResult<{ scan_id: string }>(
    await probeScan.handler({ project_path: projectPath, force: true }, plugin),
  );
  return { scan_id: r.scan_id, findings: plugin.storage.findings.listByScan(r.scan_id) };
}

const APP = "const q = req.query.q;\neval(q);\nmodule.exports = {};\n";
/** What an edit (or an autofix) ABOVE the finding does: one more line. */
const APP_SHIFTED = "'use strict';\nconst q = req.query.q;\neval(q);\nmodule.exports = {};\n";

function projectWith(content: string): string {
  const dir = makeTempDir('finding-identity-int-');
  writeFileSync(join(dir, 'app.js'), content);
  return dir;
}

function onlyFinding(findings: readonly Finding[]): Finding {
  const [first, ...rest] = findings;
  if (first === undefined || rest.length > 0) throw new Error(`expected one finding, got ${findings.length}`);
  return first;
}

// ------------------------------------------------------------ the reproductions

describe('one line inserted above a finding', () => {
  it('persists an identity that survives the shift while the fingerprint does not', async () => {
    const plugin = makePlugin();
    const dir = projectWith(APP);
    const before = onlyFinding((await scan(plugin, dir)).findings);
    writeFileSync(join(dir, 'app.js'), APP_SHIFTED);
    const after = onlyFinding((await scan(plugin, dir)).findings);

    expect(after.line_start).toBe(before.line_start === undefined ? undefined : before.line_start + 1);
    expect(after.fingerprint).not.toBe(before.fingerprint);
    expect(after.identity).toMatch(/^[0-9a-f]{64}$/);
    expect(after.identity).toBe(before.identity);
  });

  it('keeps a suppression in force', async () => {
    const plugin = makePlugin();
    const dir = projectWith(APP);
    const first = onlyFinding((await scan(plugin, dir)).findings);
    okResult(
      await getTool('suppress_finding').handler(
        { finding_fingerprint: first.fingerprint, reason: 'reviewed: q is a constant' },
        plugin,
      ),
    );
    expect(plugin.storage.findings.listOpenForProject(dir)).toHaveLength(0);

    writeFileSync(join(dir, 'app.js'), APP_SHIFTED);
    await scan(plugin, dir);
    expect(plugin.storage.findings.listOpenForProject(dir)).toHaveLength(0);
  });

  it('is not new to the CI gate', async () => {
    const plugin = makePlugin();
    const dir = projectWith(APP);
    const baselineText = serialiseBaseline(
      buildBaseline((await scan(plugin, dir)).findings, null, '2026-09-25T00:00:00.000Z'),
    );
    writeFileSync(join(dir, 'app.js'), APP_SHIFTED);
    const current = (await scan(plugin, dir)).findings;

    const parsed = parseBaseline(baselineText);
    expect(parsed).not.toBeNull();
    expect(newFindings(current, parsed?.file ?? null)).toEqual([]);
  });

  it('is unchanged to diff_scans and regression_alert, not "new + resolved"', async () => {
    const plugin = makePlugin();
    const dir = projectWith(APP);
    const s1 = await scan(plugin, dir);
    writeFileSync(join(dir, 'app.js'), APP_SHIFTED);
    const s2 = await scan(plugin, dir);

    const diff = okResult<{ summary: { new: number; resolved: number; unchanged: number } }>(
      await getTool('diff_scans').handler({ from_scan_id: s1.scan_id, to_scan_id: s2.scan_id }, plugin),
    );
    expect(diff.summary).toEqual({ new: 0, resolved: 0, unchanged: 1, not_remeasured: 0, not_previously_measured: 0 });

    const alert = okResult<{
      new_findings_by_severity: Record<string, number>;
      resolved_findings_by_severity: Record<string, number>;
    }>(await getTool('regression_alert').handler({ project_path: dir }, plugin));
    expect(Object.values(alert.new_findings_by_severity).reduce((a, b) => a + b, 0)).toBe(0);
    expect(Object.values(alert.resolved_findings_by_severity).reduce((a, b) => a + b, 0)).toBe(0);
  });

  it('is still present to create_fix_pr\'s verification when an autofix above it only moved it', async () => {
    const plugin = makePlugin();
    const dir = projectWith(APP);
    const before = await scan(plugin, dir);
    const target = onlyFinding(before.findings);
    writeFileSync(join(dir, 'app.js'), APP_SHIFTED);
    const after = await scan(plugin, dir);

    const verdict = judgeScan([target.fingerprint], before, after);
    expect(verdict.still_present).toEqual([target.fingerprint]);
    expect(verdict.passed).toBe(false);
  });
});

describe('what must still read as a change', () => {
  it('a genuinely new instance of the rule is new, and a removed one is resolved', async () => {
    const plugin = makePlugin();
    const dir = projectWith(APP);
    const s1 = await scan(plugin, dir);
    writeFileSync(join(dir, 'app.js'), `${APP}eval(req.body.code);\n`);
    const s2 = await scan(plugin, dir);
    const d1 = okResult<{ summary: { new: number; resolved: number; unchanged: number } }>(
      await getTool('diff_scans').handler({ from_scan_id: s1.scan_id, to_scan_id: s2.scan_id }, plugin),
    );
    expect(d1.summary).toEqual({ new: 1, resolved: 0, unchanged: 1, not_remeasured: 0, not_previously_measured: 0 });

    writeFileSync(join(dir, 'app.js'), 'module.exports = {};\n');
    const s3 = await scan(plugin, dir);
    const d2 = okResult<{ summary: { new: number; resolved: number; unchanged: number } }>(
      await getTool('diff_scans').handler({ from_scan_id: s2.scan_id, to_scan_id: s3.scan_id }, plugin),
    );
    expect(d2.summary).toEqual({ new: 0, resolved: 2, unchanged: 0, not_remeasured: 0, not_previously_measured: 0 });
  });

  it('a target that was really fixed is resolved', async () => {
    const plugin = makePlugin();
    const dir = projectWith(APP);
    const before = await scan(plugin, dir);
    const target = onlyFinding(before.findings);
    writeFileSync(join(dir, 'app.js'), "'use strict';\nconst q = req.query.q;\nrun(q);\nmodule.exports = {};\n");
    const after = await scan(plugin, dir);
    const verdict = judgeScan([target.fingerprint], before, after);
    expect(verdict.resolved).toEqual([target.fingerprint]);
    expect(verdict.passed).toBe(true);
  });

  it('fixing one of two identical lines does not resolve the other', async () => {
    const plugin = makePlugin();
    const dir = projectWith('eval(q);\nnoop();\neval(q);\n');
    const before = await scan(plugin, dir);
    const target = before.findings.find((f) => f.line_start === 3);
    if (target === undefined) throw new Error('target expected');
    // The autofix removed the FIRST copy; the target's text is still in the
    // file, now as the only one (occurrence 0) — so a per-identity check
    // would call it gone. The design's rule: no finding with the same
    // (tool, rule, path, content) may remain.
    writeFileSync(join(dir, 'app.js'), 'noop();\neval(q);\n');
    const after = await scan(plugin, dir);
    const verdict = judgeScan([target.fingerprint], before, after);
    expect(verdict.still_present).toEqual([target.fingerprint]);
  });
});

describe('data written before identities existed', () => {
  it('a 2.0.x suppression (fingerprint only) adopts the identity at the next scan, then survives a shift', async () => {
    const plugin = makePlugin();
    const dir = projectWith(APP);
    const first = onlyFinding((await scan(plugin, dir)).findings);
    // Exactly the row 2.0.x's suppress_finding wrote.
    plugin.storage.suppressions.insert({ finding_fingerprint: first.fingerprint, reason: 'legacy' });

    await scan(plugin, dir); // same tree: same fingerprint, now with an identity to adopt
    expect(plugin.storage.suppressions.listAll()[0]?.finding_identity).toBe(first.identity);

    writeFileSync(join(dir, 'app.js'), APP_SHIFTED);
    await scan(plugin, dir);
    expect(plugin.storage.findings.listOpenForProject(dir)).toHaveLength(0);
  });

  it('diff_scans falls back to the fingerprint against a scan whose rows have no identity', async () => {
    const plugin = makePlugin();
    const dir = projectWith(APP);
    const current = await scan(plugin, dir);
    const f = onlyFinding(current.findings);

    // A scan as 2.0.x stored it: same finding, no identity column set.
    plugin.storage.scans.insert({ scan_id: '00000000-0000-4000-8000-000000000001', scan_type: 'sast', project_path: dir, tree_hash: 'old' });
    const { identity: _identity, content_key: _contentKey, ...legacy } = f;
    plugin.storage.findings.bulkInsert([{ ...legacy, scan_id: '00000000-0000-4000-8000-000000000001' }]);
    plugin.storage.scans.finalize({ scan_id: '00000000-0000-4000-8000-000000000001', status: 'completed', tools_run: [], missing_tools: [] });

    const diff = okResult<{ summary: { new: number; resolved: number; unchanged: number } }>(
      await getTool('diff_scans').handler(
        { from_scan_id: '00000000-0000-4000-8000-000000000001', to_scan_id: current.scan_id },
        plugin,
      ),
    );
    expect(diff.summary).toEqual({ new: 0, resolved: 0, unchanged: 1, not_remeasured: 0, not_previously_measured: 0 });
  });
});

describe('secret findings', () => {
  const secretScan = makeScanTool({
    name: 'identity_probe_secret',
    scan_type: 'secrets',
    category: 'security',
    description: '',
    inputSchema: { project_path: z.string().optional(), force: z.boolean().optional() },
    invoke: async (): Promise<ScannerInvocation> => ({
      outcome: 'completed',
      tools_run: [{ name: 'trivy', status: 'ok' }],
      missing_tools: [],
      parser_inputs: [
        {
          parser: trivyParser,
          input: JSON.stringify({
            Results: [
              { Target: 'cfg.js', Secrets: [{ RuleID: 'generic', Severity: 'HIGH', StartLine: 2, EndLine: 2 }] },
            ],
          }),
        },
      ],
      report_paths: [],
    }),
  });

  async function scanSecret(plugin: PluginContext, dir: string): Promise<{ response: string; stored: Finding }> {
    const r = okResult<Record<string, unknown>>(
      await secretScan.handler({ project_path: dir, force: true }, plugin),
    );
    const stored = onlyFinding(plugin.storage.findings.listByScan(String(r['scan_id'])));
    return { response: JSON.stringify(r), stored };
  }

  const sha = (text: string): string => createHash('sha256').update(text).digest('hex');
  const lineOf = (value: string): string => `connect("${value}");`;
  const value = (n: number): string => ['guessable', 'value', String(n)].join('-');

  it('never store or return the line, nor any hash of it — in the database or the committed baseline', async () => {
    const dir = makeTempDir('finding-identity-secret-');
    writeFileSync(join(dir, 'cfg.js'), `x;\n${lineOf(value(1))}\n`);
    const plugin = makePlugin();
    const { response, stored } = await scanSecret(plugin, dir);
    expect(stored.subcategory).toBe('secret');
    expect(stored.content_key).toMatch(/^[0-9a-f]{64}$/);

    const baselineFile = serialiseBaseline(buildBaseline([stored], null, '2026-09-25T00:00:00.000Z'));
    const row = JSON.stringify(stored);
    const line = lineOf(value(1));
    for (const text of [response, row, baselineFile]) {
      expect(text).not.toContain(value(1));
      for (const h of [sha(line), sha(`text\n${line}`), sha(`${line}\n`)]) expect(text).not.toContain(h);
    }
  });

  it('keep their identity when the secret VALUE changes, so the identity carries no information about it', async () => {
    const dir = makeTempDir('finding-identity-secret-');
    const plugin = makePlugin();
    writeFileSync(join(dir, 'cfg.js'), `x;\n${lineOf(value(1))}\n`);
    const a = (await scanSecret(plugin, dir)).stored;
    writeFileSync(join(dir, 'cfg.js'), `x;\n${lineOf(value(2))}\n`);
    const b = (await scanSecret(plugin, dir)).stored;
    expect(b.identity).toBe(a.identity);
    expect(b.content_key).toBe(a.content_key);
  });
});

describe('dependency targets in create_fix_pr\'s verification', () => {
  const trivyJson = (installed: string | null): string =>
    JSON.stringify({
      Results: [
        {
          Target: 'package-lock.json',
          Vulnerabilities:
            installed === null
              ? []
              : [
                  {
                    VulnerabilityID: 'CVE-2022-25883',
                    PkgName: 'semver',
                    InstalledVersion: installed,
                    FixedVersion: '7.5.2',
                    Severity: 'HIGH',
                    Title: 'semver ReDoS',
                  },
                ],
        },
      ],
    });

  function depScan(installed: string | null) {
    return makeScanTool({
      name: 'identity_probe_deps',
      scan_type: 'deps',
      category: 'security',
      description: '',
      inputSchema: { project_path: z.string().optional(), force: z.boolean().optional() },
      invoke: async (): Promise<ScannerInvocation> => ({
        outcome: 'completed',
        tools_run: [{ name: 'trivy', status: 'ok' }],
        missing_tools: [],
        parser_inputs: [{ parser: trivyParser, input: trivyJson(installed) }],
        report_paths: [],
      }),
    });
  }

  async function run(plugin: PluginContext, dir: string, installed: string | null) {
    const r = okResult<{ scan_id: string }>(
      await depScan(installed).handler({ project_path: dir, force: true }, plugin),
    );
    return { scan_id: r.scan_id, findings: plugin.storage.findings.listByScan(r.scan_id) };
  }

  it('an upgrade that is not enough leaves the CVE present, though its fingerprint changed', async () => {
    const plugin = makePlugin();
    const dir = makeTempDir('finding-identity-deps-');
    const before = await run(plugin, dir, '5.7.1');
    const target = onlyFinding(before.findings);
    const after = await run(plugin, dir, '7.5.1');
    expect(onlyFinding(after.findings).fingerprint).not.toBe(target.fingerprint);

    const verdict = judgeScan([target.fingerprint], before, after);
    expect(verdict.still_present).toEqual([target.fingerprint]);
    expect(verdict.passed).toBe(false);
  });

  it('an upgrade past the fix resolves it', async () => {
    const plugin = makePlugin();
    const dir = makeTempDir('finding-identity-deps-');
    const before = await run(plugin, dir, '5.7.1');
    const target = onlyFinding(before.findings);
    const after = await run(plugin, dir, null);
    expect(judgeScan([target.fingerprint], before, after)).toMatchObject({
      passed: true,
      resolved: [target.fingerprint],
    });
  });
});
