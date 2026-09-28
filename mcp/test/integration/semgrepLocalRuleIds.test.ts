/**
 * Fix round 2, item 4: a local rule's stored `rule_id` must not carry the
 * path of the machine it ran on. Semgrep prefixes a local rule's id with its
 * file's directory, dotted — relative to the working directory when the file
 * lies under it, the whole absolute path otherwise (`runners/semgrepRuleIds.ts`,
 * measured on 1.176.1 and read in its `rule_lang.py`) — and `rule_id` is
 * hashed into both the fingerprint and the identity. So every plugin update
 * (a new cache path) and every CI checkout gave every bugfix / RGPD finding a
 * new identity, and a project rule changed identity whenever Semgrep ran
 * from anywhere but the project (review_pr's temporary tree): baselines
 * stopped matching, suppressions stopped applying.
 *
 * The pure half runs everywhere; the real-Semgrep half runs a pack from two
 * install paths, and a project rule from the project and from elsewhere, and
 * checks each pair is one finding.
 */

import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { assignIdentities } from '../../src/fingerprint/findingIdentity.js';
import { semgrepParserFor } from '../../src/runners/scannerParsers/semgrep.js';
import { localRuleIdNormalizer, semgrepConfigPrefix, storedLocalRuleId } from '../../src/runners/semgrepRuleIds.js';
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

describe('one canonical id per rule', () => {
  const INSTALL_A = String.raw`C:\Users\dev\.claude\plugins\cache\dev-guardian\2.0.0\configs\semgrep\bugfix-js.yml`;
  const INSTALL_B = '/home/runner/work/_tools/dev-guardian/configs/semgrep/bugfix-js.yml';
  const PROJECT = String.raw`C:\work\my app`;
  const TEAM = String.raw`C:\work\my app\rules\team.yml`;
  const ROOT = String.raw`C:\work\my app\.semgrep.yml`;

  it('a plugin pack rule is its own id, from any install and from inside the plugin repo itself', () => {
    const a = localRuleIdNormalizer(['auto', INSTALL_A], PROJECT);
    const b = localRuleIdNormalizer(['auto', INSTALL_B], PROJECT);
    expect(a(`${semgrepConfigPrefix(INSTALL_A)}.bugfix-js-off-by-one`)).toBe('bugfix-js-off-by-one');
    expect(b(`${semgrepConfigPrefix(INSTALL_B)}.bugfix-js-off-by-one`)).toBe('bugfix-js-off-by-one');
    // Dogfooding: the packs under the project, reported from the project root.
    const repo = String.raw`C:\src\dev-guardian`;
    const own = localRuleIdNormalizer([String.raw`C:\src\dev-guardian\configs\semgrep\bugfix-js.yml`], repo);
    expect(own('configs.semgrep.bugfix-js-off-by-one')).toBe('bugfix-js-off-by-one');
    expect(own('C.src.dev-guardian.configs.semgrep.bugfix-js-off-by-one')).toBe('bugfix-js-off-by-one');
  });

  it("a project rule is its id from the project root, whether Semgrep ran from the project or from elsewhere", () => {
    const n = localRuleIdNormalizer(['auto', TEAM, ROOT], PROJECT);
    expect(n('rules.team-rule')).toBe('rules.team-rule'); // cwd = the project
    expect(n('C.work.myapp.rules.team-rule')).toBe('rules.team-rule'); // cwd elsewhere (review_pr)
    expect(n('root-rule')).toBe('root-rule');
    expect(n('C.work.myapp.root-rule')).toBe('root-rule');
  });

  it('registry ids and configs this scan did not pass are left alone; the longest prefix wins', () => {
    const n = localRuleIdNormalizer(['/a/b/r.yml', '/a/b/c/r.yml', 'auto', 'p/php', 'https://example.com/rules.yml']);
    expect(n('a.b.c.x')).toBe('x');
    expect(n('a.b.x')).toBe('x');
    expect(n('javascript.lang.security.audit.eval-detected')).toBe('javascript.lang.security.audit.eval-detected');
    expect(n('other.path.x')).toBe('other.path.x');
  });

  it('a rule DIRECTORY keeps the subdirectory a rule file sits in', () => {
    const n = localRuleIdNormalizer(['/opt/rules'], '/work/p');
    expect(n('opt.rules.sub.x')).toBe('sub.x');
    const inside = localRuleIdNormalizer(['/work/p/policy'], '/work/p');
    expect(inside('work.p.policy.sub.x')).toBe('policy.sub.x');
  });

  const report = (checkId: string): string =>
    JSON.stringify({
      results: [
        {
          check_id: checkId,
          path: 'src/app.js',
          start: { line: 3 },
          end: { line: 3 },
          extra: { severity: 'ERROR', message: 'off by one', lines: 'for (i = 0; i <= a.length; i++)' },
        },
        {
          check_id: 'javascript.lang.security.audit.eval-detected',
          path: 'src/app.js',
          start: { line: 5 },
          end: { line: 5 },
          extra: { severity: 'WARNING', message: 'eval', lines: 'eval(x)' },
        },
      ],
      errors: [],
      paths: { scanned: ['src/app.js'] },
    });

  it('the parser stores the canonical id, so fingerprint and identity match across installs; registry ids are untouched', () => {
    const idA = `${semgrepConfigPrefix(INSTALL_A)}.bugfix-js-off-by-one`;
    const idB = `${semgrepConfigPrefix(INSTALL_B)}.bugfix-js-off-by-one`;
    expect(idA).not.toBe(idB);
    const a = semgrepParserFor(['auto', INSTALL_A], '/p').parse(report(idA), { project_path: '/p' }).findings;
    const b = semgrepParserFor(['auto', INSTALL_B], '/p').parse(report(idB), { project_path: '/p' }).findings;
    expect(a.map((f) => f.rule_id)).toEqual(['bugfix-js-off-by-one', 'javascript.lang.security.audit.eval-detected']);
    expect(b.map((f) => f.rule_id)).toEqual(a.map((f) => f.rule_id));
    expect(b.map((f) => f.fingerprint)).toEqual(a.map((f) => f.fingerprint));
    const identities = (fs: typeof a) => assignIdentities(fs).map((f) => f.identity);
    expect(identities(b)).toEqual(identities(a));
  });

  it('a stored path-prefixed id is recognised as a plugin pack or a project rule; anything else is left alone', () => {
    expect(storedLocalRuleId('C.Users.dev..claude.plugins.cache.dev-guardian.2.0.0.configs.semgrep.bugfix-js-off-by-one', '/p')).toBe('bugfix-js-off-by-one');
    expect(storedLocalRuleId('configs.semgrep.bugfix-js-off-by-one', '/p')).toBe('bugfix-js-off-by-one');
    expect(storedLocalRuleId('home.runner.proj.my-rule', '/home/runner/proj')).toBe('my-rule');
    expect(storedLocalRuleId('home.runner.proj.rules.my-rule', '/home/runner/proj')).toBe('rules.my-rule');
    expect(storedLocalRuleId('home.runner.proj..guardian.rules.my-rule', '/home/runner/proj')).toBe('guardian.rules.my-rule');
    expect(storedLocalRuleId('C.work.myapp.rules.team-rule', PROJECT)).toBe('rules.team-rule');
    // Already canonical, or a registry id.
    expect(storedLocalRuleId('rules.team-rule', PROJECT)).toBeNull();
    expect(storedLocalRuleId('javascript.lang.security.audit.eval-detected', '/p')).toBeNull();
    // A one-component project path could be a registry namespace: only a dotless rest.
    expect(storedLocalRuleId('python.lang.security.audit.eval', '/python')).toBeNull();
    expect(storedLocalRuleId('python.my-rule', '/python')).toBe('my-rule');
  });
});

describe('real Semgrep: one rule, one stored id, wherever it ran from', () => {
  it.runIf(REQUIRE_SEMGREP)('the toolchain must be usable when the flag is set', () => {
    expect(AVAILABLE, 'GUARDIAN_REQUIRE_SEMGREP=1 but semgrep is not usable').toBe(true);
  });

  it.skipIf(!AVAILABLE)('bugfix-js.yml copied to two install paths: rule ids, fingerprints and identities agree', () => {
    const project = makeTempDir('ruleid-proj-');
    writeFileSync(join(project, 'app.js'), 'const a = [1, 2];\nfor (let i = 0; i <= a.length; i++) { console.log(a[i]); }\n');
    const installs = [makeTempDir('ruleid install A~1 '), makeTempDir('ruleid-install-v2.0.1-')].map((root) => {
      const dir = join(root, 'plugins', 'cache', 'configs', 'semgrep');
      mkdirSync(dir, { recursive: true });
      const pack = join(dir, 'bugfix-js.yml');
      copyFileSync(join(REPO_ROOT, 'configs', 'semgrep', 'bugfix-js.yml'), pack);
      return pack;
    });
    const runs = installs.map((pack, i) => {
      const out = join(project, `out-${i}.json`);
      const r = runSemgrep(['--config', pack, '--metrics=off', '--json', '--quiet', '--output', out, join(project, 'app.js')]);
      expect(r.status === 0 || r.status === 1, r.stderr).toBe(true);
      return { pack, out };
    });
    const parsed = runs.map(({ pack, out }) =>
      semgrepParserFor([pack], project).parse(readFileSync(out, 'utf8'), { project_path: project }).findings,
    );
    const [a, b] = parsed;
    if (a === undefined || b === undefined) throw new Error('two runs expected');
    expect(a.length).toBeGreaterThan(0);
    // The raw ids differ (they carry the two paths) …
    const rawIds = runs.map(({ out }) => (JSON.parse(readFileSync(out, 'utf8')) as { results: Array<{ check_id: string }> }).results[0]?.check_id);
    expect(rawIds[0]).not.toBe(rawIds[1]);
    // … the stored ones do not.
    expect(a.map((f) => f.rule_id)).toEqual(b.map((f) => f.rule_id));
    expect(a.every((f) => !(f.rule_id ?? '').includes('.'))).toBe(true);
    expect(a.map((f) => f.fingerprint)).toEqual(b.map((f) => f.fingerprint));
  }, SEMGREP_TEST_TIMEOUT_MS);

  it.skipIf(!AVAILABLE)("a project's rule in a subdirectory: run from the project and from elsewhere, one stored id", () => {
    const project = makeTempDir('ruleid-own-');
    mkdirSync(join(project, 'rules'));
    writeFileSync(
      join(project, 'rules', 'team.yml'),
      'rules:\n  - id: team-eval\n    languages: [javascript]\n    severity: ERROR\n    message: eval\n    pattern: eval($X)\n',
    );
    writeFileSync(join(project, 'app.js'), 'eval(x);\n');
    const elsewhere = makeTempDir('ruleid-cwd-');
    const config = join(project, 'rules', 'team.yml');
    const runFrom = (cwd: string, i: number): { raw: string; stored: string | undefined } => {
      const out = join(elsewhere, `own-${i}.json`);
      const r = runSemgrep(['--config', config, '--metrics=off', '--json', '--quiet', '--output', out, join(project, 'app.js')], { cwd });
      expect(r.status === 0 || r.status === 1, r.stderr).toBe(true);
      const text = readFileSync(out, 'utf8');
      const raw = (JSON.parse(text) as { results: Array<{ check_id: string }> }).results[0]?.check_id ?? '';
      const stored = semgrepParserFor(['auto', config], project).parse(text, { project_path: project }).findings[0]?.rule_id;
      return { raw, stored };
    };
    const fromProject = runFrom(project, 0);
    const fromElsewhere = runFrom(elsewhere, 1);
    expect(fromProject.raw).toBe('rules.team-eval');
    expect(fromElsewhere.raw).not.toBe(fromProject.raw);
    expect(fromProject.stored).toBe('rules.team-eval');
    expect(fromElsewhere.stored).toBe('rules.team-eval');
  }, SEMGREP_TEST_TIMEOUT_MS);
});
