/**
 * Fix rounds 2 and 3: the id a local Semgrep rule's findings are stored
 * under. Semgrep prefixes a local rule's id with its file's directory,
 * dotted — relative to its working directory when the file lies under it,
 * the whole absolute path otherwise (`runners/semgrepRuleIds.ts`, measured on
 * 1.176.1 and read in its `rule_lang.py`) — and `rule_id` is hashed into both
 * the fingerprint and the identity.
 *
 *   - The plugin's own packs moved with every install: every bug_hunt / RGPD
 *     finding became new on each update. They are stored under the rule's own
 *     id, found from the plugin's root (round 2, and round 3's ruling).
 *   - A project's own rules keep the id from the project root, however
 *     Semgrep was run (review_pr runs from a temporary tree).
 *   - Any other rule file keeps Semgrep's own id: two files defining the same
 *     rule id stay two rules (round 3, I-2), and a project's `configs/semgrep/`
 *     is not the plugin's (M-3).
 *
 * Every path here is built with the host's conventions (round 3, I-3: the
 * suite runs on POSIX too), except the pure prefix cases, which are
 * Semgrep's string rule on both path shapes.
 */

import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { assignIdentities } from '../../src/fingerprint/findingIdentity.js';
import { semgrepParserFor } from '../../src/runners/scannerParsers/semgrep.js';
import { localRuleIdNormalizer, pluginPacksDir, semgrepConfigPrefix } from '../../src/runners/semgrepRuleIds.js';
import { runSemgrep, semgrepAvailable } from '../helpers/semgrep.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';
const AVAILABLE = semgrepAvailable();
// Two real Semgrep runs per test: well past vitest's 10 s default on a loaded machine.
const SEMGREP_TEST_TIMEOUT_MS = 180_000;

describe('the prefix Semgrep derives from a rule file path (measured on 1.176.1)', () => {
  it.each([
    [String.raw`C:\Users\ADMINI~1\AppData\cfg with space\v2.0.1\bugfix-js.yml`, 'C.Users.ADMINI1.AppData.cfgwithspace.v2.0.1'],
    ['C:/Users/ADMINI~1/AppData/cfg with space/v2.0.1/bugfix-js.yml', 'C.Users.ADMINI1.AppData.cfgwithspace.v2.0.1'],
    ['sub dir/my.rules~x/r.yml', 'subdir.my.rulesx'],
    ['.semgrep.yml', ''],
    ['rules/team.yml', 'rules'],
    ['.guardian/rules/r.yml', 'guardian.rules'],
    ['a b/.x/r.yml', 'ab..x'],
    // POSIX, by Semgrep's own code: `"/.home.runner…".lstrip("./")`.
    ['/home/runner/.claude/plugins/cache/dev-guardian/2.1.0/configs/semgrep/bugfix-js.yml', 'home.runner..claude.plugins.cache.dev-guardian.2.1.0.configs.semgrep'],
    // Python's `PureWindowsPath(…).parts`, as checked against pathlib itself.
    [String.raw`\\fileserver\share\rules\r.yml`, 'fileservershare.rules'],
    ['C:/x/./y/../z/r.yml', 'C.x.y....z'],
    [String.raw`\x\r.yml`, '.x'],
    ['/.hidden/r.yml', 'hidden'],
  ])('%s → %s', (path, prefix) => {
    expect(semgrepConfigPrefix(path)).toBe(prefix);
  });
});

describe('one stored id per rule', () => {
  const BASE = resolve('/work');
  const PROJECT = join(BASE, 'my app');
  const CACHE = join(BASE, 'home', '.claude', 'plugins', 'cache', 'market', 'dev-guardian');
  const PACKS_A = join(CACHE, '2.0.0', 'configs', 'semgrep');
  const PACKS_B = join(CACHE, '2.1.0', 'configs', 'semgrep');
  const INSTALL_A = join(PACKS_A, 'bugfix-js.yml');
  const INSTALL_B = join(PACKS_B, 'bugfix-js.yml');
  const TEAM = join(PROJECT, 'rules', 'team.yml');
  const ROOT = join(PROJECT, '.semgrep.yml');
  const abs = (file: string, id: string): string => `${semgrepConfigPrefix(file)}.${id}`;

  it("a plugin pack's rule is its own id, whichever install ran it", () => {
    expect(localRuleIdNormalizer(['auto', INSTALL_A], { projectPath: PROJECT, packsDir: PACKS_A })(abs(INSTALL_A, 'bugfix-js-x'))).toBe('bugfix-js-x');
    expect(localRuleIdNormalizer(['auto', INSTALL_B], { projectPath: PROJECT, packsDir: PACKS_B })(abs(INSTALL_B, 'bugfix-js-x'))).toBe('bugfix-js-x');
  });

  it('a project rule is its id from the project root, whether Semgrep ran from the project or from elsewhere', () => {
    const n = localRuleIdNormalizer(['auto', TEAM, ROOT], { projectPath: PROJECT, packsDir: PACKS_B });
    expect(n('rules.team-rule')).toBe('rules.team-rule');
    expect(n(abs(TEAM, 'team-rule'))).toBe('rules.team-rule');
    expect(n('root-rule')).toBe('root-rule');
    expect(n(abs(ROOT, 'root-rule'))).toBe('root-rule');
  });

  it("a project's own configs/semgrep/ is a project directory, not the plugin's packs (M-3)", () => {
    const own = join(PROJECT, 'configs', 'semgrep', 'team.yml');
    const n = localRuleIdNormalizer([own, ROOT], { projectPath: PROJECT, packsDir: PACKS_B });
    expect(n('configs.semgrep.team-eval')).toBe('configs.semgrep.team-eval');
    expect(n(abs(own, 'team-eval'))).toBe('configs.semgrep.team-eval');
    // …so it never collides with the root .semgrep.yml's rule of the same id.
    expect(n(abs(ROOT, 'team-eval'))).toBe('team-eval');
  });

  it('a rule file elsewhere keeps Semgrep\'s own id: two files, one rule id, two rules (I-2); another configs/semgrep likewise', () => {
    const team = join(BASE, 'opt', 'team');
    const js = join(team, 'js', 'no-eval.yml');
    const v2 = join(team, 'v2', 'no-eval.yml');
    const foreign = join(BASE, 'opt', 'configs', 'semgrep', 'x.yml');
    const n = localRuleIdNormalizer(['auto', js, v2, foreign], { projectPath: PROJECT, packsDir: PACKS_B });
    expect(n(abs(js, 'no-eval'))).toBe(abs(js, 'no-eval'));
    expect(n(abs(v2, 'no-eval'))).toBe(abs(v2, 'no-eval'));
    expect(abs(js, 'no-eval')).not.toBe(abs(v2, 'no-eval'));
    expect(n(abs(foreign, 'bugfix-js-x'))).toBe(abs(foreign, 'bugfix-js-x'));
  });

  it("the plugin's own repository: its packs are project files there, and keep the project's id", () => {
    const repo = join(BASE, 'src', 'dev-guardian');
    const packs = join(repo, 'configs', 'semgrep');
    const n = localRuleIdNormalizer([join(packs, 'bugfix-js.yml')], { projectPath: repo, packsDir: packs });
    expect(n('configs.semgrep.bugfix-js-x')).toBe('configs.semgrep.bugfix-js-x');
    expect(n(abs(join(packs, 'bugfix-js.yml'), 'bugfix-js-x'))).toBe('configs.semgrep.bugfix-js-x');
  });

  it("a relative config resolves against Semgrep's working directory, not the server's (M-5)", () => {
    const n = localRuleIdNormalizer(['rules/team.yml'], { projectPath: PROJECT, cwd: PROJECT, packsDir: PACKS_B });
    expect(n(abs(TEAM, 'team-rule'))).toBe('rules.team-rule');
    expect(n('rules.team-rule')).toBe('rules.team-rule');
  });

  it("a container's /src paths read the same on any host", () => {
    const n = localRuleIdNormalizer(['auto', '/src/rules/team.yml', '/src/.semgrep.yml'], { projectPath: '/src', cwd: '/src', packsDir: PACKS_B });
    expect(n('rules.team-rule')).toBe('rules.team-rule');
    expect(n('src.rules.team-rule')).toBe('rules.team-rule');
    expect(n('root-rule')).toBe('root-rule');
  });

  it('registry ids and configs this scan did not pass are left alone; the longest prefix wins', () => {
    const a = join(BASE, 'a', 'b', 'r.yml');
    const c = join(BASE, 'a', 'b', 'c', 'r.yml');
    const n = localRuleIdNormalizer([a, c, 'auto', 'p/php', 'https://example.com/rules.yml'], { projectPath: join(BASE, 'a'), packsDir: PACKS_B });
    expect(n(abs(c, 'x'))).toBe('b.c.x');
    expect(n(abs(a, 'x'))).toBe('b.x');
    expect(n('javascript.lang.security.audit.eval-detected')).toBe('javascript.lang.security.audit.eval-detected');
    expect(n('other.path.x')).toBe('other.path.x');
  });

  it('the parser stores the own id, so fingerprint and identity match across installs; registry ids are untouched', () => {
    const report = (checkId: string): string =>
      JSON.stringify({
        results: [
          { check_id: checkId, path: 'src/app.js', start: { line: 3 }, end: { line: 3 }, extra: { severity: 'ERROR', message: 'off by one', lines: 'for (i = 0; i <= a.length; i++)' } },
          { check_id: 'javascript.lang.security.audit.eval-detected', path: 'src/app.js', start: { line: 5 }, end: { line: 5 }, extra: { severity: 'WARNING', message: 'eval', lines: 'eval(x)' } },
        ],
        errors: [],
        paths: { scanned: ['src/app.js'] },
      });
    const idA = abs(INSTALL_A, 'bugfix-js-off-by-one');
    const idB = abs(INSTALL_B, 'bugfix-js-off-by-one');
    expect(idA).not.toBe(idB);
    const a = semgrepParserFor(['auto', INSTALL_A], { packsDir: PACKS_A }).parse(report(idA), { project_path: PROJECT }).findings;
    const b = semgrepParserFor(['auto', INSTALL_B], { packsDir: PACKS_B }).parse(report(idB), { project_path: PROJECT }).findings;
    expect(a.map((f) => f.rule_id)).toEqual(['bugfix-js-off-by-one', 'javascript.lang.security.audit.eval-detected']);
    expect(b.map((f) => f.rule_id)).toEqual(a.map((f) => f.rule_id));
    expect(b.map((f) => f.fingerprint)).toEqual(a.map((f) => f.fingerprint));
    const identities = (fs: typeof a) => assignIdentities(fs).map((f) => f.identity);
    expect(identities(b)).toEqual(identities(a));
  });

  it("the plugin's pack directory is the one bug_hunt and compliance_check load their packs from", () => {
    expect(resolve(dirname(pluginPacksDir()))).toBe(resolve(REPO_ROOT, 'configs'));
  });
});

describe('real Semgrep: one rule, one stored id, wherever it ran from', () => {
  it.runIf(REQUIRE_SEMGREP)('the toolchain must be usable when the flag is set', () => {
    expect(AVAILABLE, 'GUARDIAN_REQUIRE_SEMGREP=1 but semgrep is not usable').toBe(true);
  });

  const runReport = (args: string[], out: string, cwd?: string): string => {
    const r = runSemgrep([...args, '--metrics=off', '--json', '--quiet', '--output', out], cwd !== undefined ? { cwd } : {});
    expect(r.status === 0 || r.status === 1, r.stderr).toBe(true);
    return readFileSync(out, 'utf8');
  };
  const checkIds = (report: string): string[] => (JSON.parse(report) as { results: Array<{ check_id: string }> }).results.map((r) => r.check_id);

  it.skipIf(!AVAILABLE)('bugfix-js.yml in two plugin installs: rule ids, fingerprints and identities agree', () => {
    const project = makeTempDir('ruleid-proj-');
    writeFileSync(join(project, 'app.js'), 'const a = [1, 2];\nfor (let i = 0; i <= a.length; i++) { console.log(a[i]); }\n');
    const installs = [makeTempDir('ruleid install A~1 '), makeTempDir('ruleid-install-v2.0.1-')].map((root) => {
      const dir = join(root, 'plugins', 'cache', 'configs', 'semgrep');
      mkdirSync(dir, { recursive: true });
      const pack = join(dir, 'bugfix-js.yml');
      copyFileSync(join(REPO_ROOT, 'configs', 'semgrep', 'bugfix-js.yml'), pack);
      return { pack, dir };
    });
    const runs = installs.map(({ pack, dir }, i) => {
      const report = runReport(['--config', pack, join(project, 'app.js')], join(project, `out-${i}.json`));
      return { report, findings: semgrepParserFor([pack], { packsDir: dir }).parse(report, { project_path: project }).findings };
    });
    const [a, b] = runs;
    if (a === undefined || b === undefined) throw new Error('two runs expected');
    expect(a.findings.length).toBeGreaterThan(0);
    // The raw ids differ (they carry the two paths) …
    expect(checkIds(a.report)[0]).not.toBe(checkIds(b.report)[0]);
    // … the stored ones do not.
    expect(a.findings.map((f) => f.rule_id)).toEqual(b.findings.map((f) => f.rule_id));
    expect(a.findings.every((f) => !(f.rule_id ?? '').includes('.'))).toBe(true);
    expect(a.findings.map((f) => f.fingerprint)).toEqual(b.findings.map((f) => f.fingerprint));
  }, SEMGREP_TEST_TIMEOUT_MS);

  it.skipIf(!AVAILABLE)("a project's rule in a subdirectory: run from the project and from elsewhere, one stored id", () => {
    const project = makeTempDir('ruleid-own-');
    mkdirSync(join(project, 'rules'));
    writeFileSync(join(project, 'rules', 'team.yml'), 'rules:\n  - id: team-eval\n    languages: [javascript]\n    severity: ERROR\n    message: eval\n    pattern: eval($X)\n');
    writeFileSync(join(project, 'app.js'), 'eval(x);\n');
    const elsewhere = makeTempDir('ruleid-cwd-');
    const config = join(project, 'rules', 'team.yml');
    const runFrom = (cwd: string, i: number): { raw: string; stored: string | undefined } => {
      const report = runReport(['--config', config, join(project, 'app.js')], join(elsewhere, `own-${i}.json`), cwd);
      const stored = semgrepParserFor(['auto', config], { projectPath: project, cwd }).parse(report, { project_path: project }).findings[0]?.rule_id;
      return { raw: checkIds(report)[0] ?? '', stored };
    };
    const fromProject = runFrom(project, 0);
    const fromElsewhere = runFrom(elsewhere, 1);
    expect(fromProject.raw).toBe('rules.team-eval');
    expect(fromElsewhere.raw).not.toBe(fromProject.raw);
    expect(fromProject.stored).toBe('rules.team-eval');
    expect(fromElsewhere.stored).toBe('rules.team-eval');
  }, SEMGREP_TEST_TIMEOUT_MS);

  it.skipIf(!AVAILABLE)('two registered rule files outside the project, one rule id: two findings, two ids — as Semgrep names them (I-2)', () => {
    const project = makeTempDir('ruleid-i2-');
    writeFileSync(join(project, 'app.js'), 'eval(x);\n');
    const team = makeTempDir('ruleid-team-');
    const files = ['js', 'v2'].map((sub) => {
      mkdirSync(join(team, sub));
      const file = join(team, sub, 'no-eval.yml');
      writeFileSync(file, `rules:\n  - id: no-eval\n    languages: [javascript]\n    severity: ERROR\n    message: eval ${sub}\n    pattern: eval($X)\n`);
      return file;
    });
    const report = runReport([...files.flatMap((f) => ['--config', f]), join(project, 'app.js')], join(project, 'out.json'), project);
    const findings = semgrepParserFor(['auto', ...files], { projectPath: project }).parse(report, { project_path: project }).findings;
    const ids = findings.map((f) => f.rule_id ?? '').sort();
    expect(ids).toEqual(checkIds(report).sort());
    expect(new Set(ids).size).toBe(2);
    expect(new Set(findings.map((f) => f.fingerprint)).size).toBe(2);
  }, SEMGREP_TEST_TIMEOUT_MS);
});
