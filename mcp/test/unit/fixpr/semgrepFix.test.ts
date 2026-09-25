/**
 * `planSemgrepFix` — the rules a create_fix_pr Semgrep pass applies are the
 * target rules and nothing else (Task 11 item 4). The fix used to be
 * `semgrep --config auto --autofix`: every registry autofix, across the whole
 * tree, with metrics sent.
 *
 * The last test runs the REAL Semgrep (gated) on a file two autofixable rules
 * match, targeting one of them: only that rule's rewrite may happen.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { parse as parseYaml } from 'yaml';
import { applyGroup } from '../../../src/fixpr/apply.js';
import { checkIdMatches, disposeSemgrepFixPlan, planSemgrepFix } from '../../../src/fixpr/semgrepFix.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';
import { isInstalled } from '../../helpers/toolchain.js';

afterAll(cleanupTempDirs);

const SEMGREP_INSTALLED = await isInstalled('semgrep');
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

const TWO_RULES = [
  'rules:',
  '  - id: my-eval',
  '    pattern: eval($X)',
  '    message: no eval',
  '    languages: [javascript]',
  '    severity: ERROR',
  '    fix: safeEval($X)',
  '  - id: other-rule',
  '    pattern: console.log($X)',
  '    message: log',
  '    languages: [javascript]',
  '    severity: WARNING',
  '    fix: logger.info($X)',
  '',
].join('\n');

/** A rules file in a directory named `dirName`, and the check_id prefix
 *  Semgrep gives rules loaded from it (measured: the directory's dotted path). */
function rulesIn(dirName: string): { file: string; prefix: string } {
  const root = makeTempDir('semgrepfix-rules-');
  const dir = join(root, dirName);
  mkdirSync(dir, { recursive: true });
  const file = join(dir, 'r.yml');
  writeFileSync(file, TWO_RULES);
  return { file, prefix: `C.Users.someone.tmp.${dirName.replace(/[^A-Za-z0-9._-]/g, '')}` };
}

describe('checkIdMatches', () => {
  it('matches a local rule by the check_id Semgrep gives it (directory prefix + id), as measured', () => {
    const file = join('C:', 'tmp', 'my rules.d', 'sub', 'r.yml');
    expect(checkIdMatches('C.tmp.myrules.d.sub.my-eval', file, 'my-eval')).toBe(true);
    expect(checkIdMatches('my-eval', file, 'my-eval')).toBe(true);
    const dotDir = join('C:', 'proj', '.semgrep', 'x.yml');
    expect(checkIdMatches('C.proj..semgrep.my-eval', dotDir, 'my-eval')).toBe(true);
  });

  it('never takes a registry rule for a local rule that shares its last segment', () => {
    const file = join('C:', 'repo', 'configs', 'semgrep', 'bugfix-js.yml');
    expect(checkIdMatches('javascript.browser.security.eval-detected.eval-detected', file, 'eval-detected')).toBe(false);
    expect(checkIdMatches('C.repo.configs.semgrep.eval-detected', file, 'eval-detected')).toBe(true);
  });
});

describe('planSemgrepFix', () => {
  it('writes a filtered copy holding ONLY the target rules of a local file', () => {
    const { file, prefix } = rulesIn('rules');
    const r = planSemgrepFix([{ targets: [{ rule_id: `${prefix}.my-eval`, file_path: 'src/a.js' }], localConfigs: [file], registryAllowed: false }]);
    if (!r.ok) throw new Error(r.reason);
    expect(r.plan.configs).toHaveLength(1);
    const copy = r.plan.configs[0] ?? '';
    const doc = parseYaml(readFileSync(copy, 'utf8')) as { rules: Array<{ id: string }> };
    expect(doc.rules.map((x) => x.id)).toEqual(['my-eval']);
    expect(r.plan.files).toEqual(['src/a.js']);
    disposeSemgrepFixPlan(r.plan);
    expect(existsSync(r.plan.dir)).toBe(false);
  });

  it('applies a registry rule as r/<rule-id>, never --config auto', () => {
    const r = planSemgrepFix([{ targets: [{ rule_id: 'javascript.browser.security.eval-detected.eval-detected', file_path: 'a.js' }], localConfigs: [], registryAllowed: true }]);
    if (!r.ok) throw new Error(r.reason);
    expect(r.plan.configs).toEqual(['r/javascript.browser.security.eval-detected.eval-detected']);
    disposeSemgrepFixPlan(r.plan);
  });

  it('refuses a target that is in no local file when the originating scan was local-only', () => {
    const r = planSemgrepFix([{ targets: [{ rule_id: 'somewhere.else.rule', file_path: 'a.js' }], localConfigs: [], registryAllowed: false }]);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain('somewhere.else.rule');
  });

  it('keeps two packs that define the same id apart, one directory each', () => {
    const a = rulesIn('semgrep');
    const b = rulesIn('semgrep');
    const r = planSemgrepFix([
      { targets: [{ rule_id: `${a.prefix}.my-eval`, file_path: 'a.js' }], localConfigs: [a.file, b.file], registryAllowed: false },
    ]);
    if (!r.ok) throw new Error(r.reason);
    // Both files hold `my-eval` under a `semgrep` directory, so both match.
    expect(new Set(r.plan.configs.map((c) => join(c, '..'))).size).toBe(r.plan.configs.length);
    disposeSemgrepFixPlan(r.plan);
  });

  it('refuses a target with no file', () => {
    const r = planSemgrepFix([{ targets: [{ rule_id: 'x', file_path: '' }], localConfigs: [], registryAllowed: true }]);
    expect(r.ok).toBe(false);
  });
});

describe('the fix pass applies only the target rule (real Semgrep)', () => {
  it.skipIf(!SEMGREP_INSTALLED && !REQUIRE_SEMGREP)('rewrites what the target rule matches and leaves the other autofixable rule alone', async () => {
    const rulesRoot = makeTempDir('semgrepfix-real-rules-');
    const rules = join(rulesRoot, 'r.yml');
    writeFileSync(rules, TWO_RULES);
    const worktree = makeTempDir('semgrepfix-real-wt-');
    writeFileSync(join(worktree, 'a.js'), 'eval(a);\nconsole.log(b);\n');

    // The target's rule id is exactly what a scan with this config reports.
    const r = planSemgrepFix([{ targets: [{ rule_id: 'x.my-eval', file_path: 'a.js' }], localConfigs: [rules], registryAllowed: false }]);
    // `x.my-eval` does not end in the rules directory's name, so it is not
    // the local rule — use the id the way Semgrep really prefixes it instead.
    expect(r.ok).toBe(false);
    const segment = rulesRoot.split(/[\\/]/).pop()?.replace(/[^A-Za-z0-9._-]/g, '') ?? '';
    const real = planSemgrepFix([{ targets: [{ rule_id: `anything.${segment}.my-eval`, file_path: 'a.js' }], localConfigs: [rules], registryAllowed: false }]);
    if (!real.ok) throw new Error(real.reason);

    const applied = await applyGroup({
      group: {
        source: 'semgrep', key: 'semgrep', severity: 'high', hash: 'x',
        candidates: [{ source: 'semgrep', fingerprints: ['f'], severity: 'high', command: null, label: 'my-eval', rule_id: 'my-eval', file_path: 'a.js' }],
      },
      worktreePath: worktree,
      lockfileOnly: false,
      semgrepFix: real.plan,
      timeoutMs: 120_000,
    });
    disposeSemgrepFixPlan(real.plan);
    expect(applied.applied, JSON.stringify(applied.failure)).toBe(true);
    expect(readFileSync(join(worktree, 'a.js'), 'utf8')).toBe('safeEval(a);\nconsole.log(b);\n');
  }, 180_000);
});
