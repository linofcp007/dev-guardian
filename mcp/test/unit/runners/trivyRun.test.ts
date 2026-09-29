/**
 * `runners/trivyRun.ts` — every Trivy spawn runs in a directory this scan
 * created, with `--config` pointing at an empty file, so the scanned
 * repository's own `trivy.yaml` is never read; its `.trivyignore` is passed
 * explicitly, and named. See the module comment for the reproduction.
 *
 * The last test holds the rule for the whole tree: a Trivy spawn anywhere in
 * `src/` outside the helper fails it.
 */

import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/runners/processRunner.js', () => ({ runProcess: vi.fn() }));
vi.mock('execa', () => ({ execa: vi.fn() }));

import { execa } from 'execa';
import { runProcess } from '../../../src/runners/processRunner.js';
import {
  honouredNote,
  judgeTrivyFs,
  NEUTRAL_TRIVY_CONFIG,
  repoSuppressionFrom,
  resetTrivyVersionCache,
  runTrivy,
  suppressionNote,
  trivyArgv,
  withHonoured,
} from '../../../src/runners/trivyRun.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const mockedRun = vi.mocked(runProcess);

beforeEach(() => {
  mockedRun.mockReset();
  mockedRun.mockResolvedValue({ outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false });
  // No version known unless a test says so: the flags are then withheld.
  vi.mocked(execa).mockReset();
  vi.mocked(execa).mockRejectedValue(new Error('no trivy here'));
  resetTrivyVersionCache();
});

describe('trivyArgv', () => {
  it('puts --config before the target, and the target last', () => {
    expect(trivyArgv({ args: ['fs', '--scanners', 'vuln', '--quiet'], target: '/p' }, '/r/cfg.yaml', null)).toEqual([
      'fs',
      '--scanners',
      'vuln',
      '--quiet',
      '--config',
      '/r/cfg.yaml',
      '/p',
    ]);
  });

  it('adds --ignorefile when the project has a .trivyignore', () => {
    expect(trivyArgv({ args: ['config'], target: '/p' }, '/r/cfg.yaml', '/p/.trivyignore')).toEqual([
      'config',
      '--config',
      '/r/cfg.yaml',
      '--ignorefile',
      '/p/.trivyignore',
      '/p',
    ]);
  });
});

describe('runTrivy', () => {
  it('runs in the work directory, never the project, with an empty config it wrote there', async () => {
    const project = makeTempDir('trivy-run-project-');
    const work = makeTempDir('trivy-run-work-');
    writeFileSync(join(project, 'trivy.yaml'), 'severity:\n  - UNKNOWN\n');
    const r = await runTrivy({ args: ['fs', '--format', 'json'], target: project, workDir: work, ignoreFrom: project });

    expect(mockedRun).toHaveBeenCalledTimes(1);
    const call = mockedRun.mock.calls[0]?.[0];
    expect(call?.command).toBe('trivy');
    expect(call?.cwd).toBe(work);
    const config = join(work, NEUTRAL_TRIVY_CONFIG);
    expect(call?.args).toEqual(['fs', '--format', 'json', '--config', config, project]);
    // Comments only: YAML with no key, which Trivy reads as no configuration.
    const text = readFileSync(config, 'utf8');
    expect(text.split('\n').every((l) => l === '' || l.startsWith('#'))).toBe(true);
    expect(r.honoured).toEqual([]);
  });

  it("passes the project's .trivyignore explicitly and names it", async () => {
    const project = makeTempDir('trivy-run-project-');
    const work = makeTempDir('trivy-run-work-');
    writeFileSync(join(project, '.trivyignore'), 'CVE-2020-8203\n');
    const r = await runTrivy({ args: ['fs'], target: project, workDir: work, ignoreFrom: project });
    expect(mockedRun.mock.calls[0]?.[0].args).toEqual(
      expect.arrayContaining(['--ignorefile', join(project, '.trivyignore')]),
    );
    expect(r.honoured).toEqual(['.trivyignore']);
    expect(honouredNote(r.honoured)).toMatch(/\.trivyignore/);
    const named = withHonoured({ name: 'trivy-image', status: 'ok', reason: 'image x' }, r);
    expect(named.reason).toMatch(/^image x; honoured the project's \.trivyignore/);
    expect(named.honoured_config).toEqual(['.trivyignore']);
    const plain = { name: 'trivy', status: 'ok' } as const;
    expect(withHonoured(plain, { honoured: [] })).toBe(plain);
  });

  it("ignoreFileFrom (the CI gate's --rules-ref copy): that .trivyignore is passed, the project's never", async () => {
    const project = makeTempDir('trivy-run-project-');
    const work = makeTempDir('trivy-run-work-');
    const fromRef = makeTempDir('trivy-run-ref-');
    // The pull request's own suppression, and the base's.
    writeFileSync(join(project, '.trivyignore'), 'CVE-2020-8203\nCVE-2021-23337\n');
    writeFileSync(join(fromRef, '.trivyignore'), 'CVE-2020-8203\n');
    const r = await runTrivy({ args: ['fs'], target: project, workDir: work, ignoreFrom: project, ignoreFileFrom: fromRef });
    const args = mockedRun.mock.calls[0]?.[0].args ?? [];
    expect(args).toEqual(expect.arrayContaining(['--ignorefile', join(fromRef, '.trivyignore')]));
    expect(args).not.toContain(join(project, '.trivyignore'));
    expect(r.honoured).toEqual(['.trivyignore']);

    // None at the ref: none at all — the tree's is not read in its place.
    mockedRun.mockClear();
    const empty = makeTempDir('trivy-run-ref-');
    const none = await runTrivy({ args: ['fs'], target: project, workDir: work, ignoreFrom: project, ignoreFileFrom: empty });
    expect(mockedRun.mock.calls[0]?.[0].args).not.toContain('--ignorefile');
    expect(none.honoured).toEqual([]);
  });

  it('a .trivyignore that is not a regular file is not passed', async () => {
    const project = makeTempDir('trivy-run-project-');
    const work = makeTempDir('trivy-run-work-');
    // A directory by that name.
    mkdirSync(join(project, '.trivyignore'));
    const r = await runTrivy({ args: ['fs'], target: project, workDir: work, ignoreFrom: project });
    expect(mockedRun.mock.calls[0]?.[0].args).not.toContain('--ignorefile');
    expect(r.honoured).toEqual([]);
  });

  it('without ignoreFrom (an image), no project file is read', async () => {
    const work = makeTempDir('trivy-run-work-');
    const r = await runTrivy({ args: ['image'], target: 'alpine:3.19', workDir: work });
    expect(mockedRun.mock.calls[0]?.[0].args).toEqual(['image', '--config', join(work, NEUTRAL_TRIVY_CONFIG), 'alpine:3.19']);
    expect(r.honoured).toEqual([]);
  });

  it('a config that cannot be written is a failed run, and Trivy is never started without it', async () => {
    const project = makeTempDir('trivy-run-project-');
    // A FILE where the work directory should be: mkdir fails.
    const blocker = join(project, 'not-a-dir');
    writeFileSync(blocker, 'x');
    const r = await runTrivy({ args: ['fs'], target: project, workDir: join(blocker, 'sub') });
    expect(r.outcome).toBe('failed');
    expect(r.stderr).toMatch(/neutral Trivy configuration/);
    expect(mockedRun).not.toHaveBeenCalled();
    expect(existsSync(join(blocker, 'sub'))).toBe(false);
  });
});

// ---------------------------------------------------------------- no phoning home

/**
 * Every Trivy run contacted check.trivy.dev — its version check, which also
 * carries anonymous usage data — `fs --scanners license` included (measured
 * by the plugin-surface review with a logging proxy). Only BOTH
 * TRIVY_SKIP_VERSION_CHECK=true and TRIVY_DISABLE_TELEMETRY=true stopped it.
 * The flags came with the check itself, in Trivy 0.63.0 (`pkg/flag/
 * scan_flags.go`: absent at v0.62.1, present at v0.63.0); an older Trivy
 * refuses an unknown flag, so they are passed only to a Trivy known to be
 * 0.63.0 or newer, and the environment variables always.
 */
describe('Trivy never phones home', () => {
  it('passes --skip-version-check --disable-telemetry to a Trivy 0.63.0 or newer, before --config', () => {
    expect(trivyArgv({ args: ['fs', '--quiet'], target: '/p' }, '/r/c.yaml', null, '0.69.3')).toEqual([
      'fs',
      '--quiet',
      '--skip-version-check',
      '--disable-telemetry',
      '--config',
      '/r/c.yaml',
      '/p',
    ]);
    expect(trivyArgv({ args: ['fs'], target: '/p' }, '/r/c.yaml', null, '0.63.0')).toContain('--disable-telemetry');
  });

  it.each([['0.62.1'], ['0.40.0'], [null]])('does not pass the flags to Trivy %s (an unknown flag is fatal there)', (version) => {
    const argv = trivyArgv({ args: ['fs'], target: '/p' }, '/r/c.yaml', null, version);
    expect(argv).not.toContain('--skip-version-check');
    expect(argv).not.toContain('--disable-telemetry');
  });

  it('always sets both environment variables, over whatever the caller passed', async () => {
    const work = makeTempDir('trivy-run-work-');
    await runTrivy({
      args: ['fs'],
      target: '/p',
      workDir: work,
      env: { PATH: '/bin', TRIVY_DISABLE_TELEMETRY: 'false' },
    });
    const env = mockedRun.mock.calls[0]?.[0].env ?? {};
    expect(env['TRIVY_SKIP_VERSION_CHECK']).toBe('true');
    expect(env['TRIVY_DISABLE_TELEMETRY']).toBe('true');
    expect(env['PATH']).toBe('/bin');
  });

  it('asks the installed Trivy its version once, and passes the flags when it is new enough', async () => {
    vi.mocked(execa).mockResolvedValue({ exitCode: 0, stdout: 'Version: 0.69.3\nVulnerability DB:\n' } as never);
    const work = makeTempDir('trivy-run-work-');
    await runTrivy({ args: ['fs'], target: '/p', workDir: work });
    await runTrivy({ args: ['config'], target: '/p', workDir: work });
    expect(vi.mocked(execa)).toHaveBeenCalledTimes(1);
    const probe = vi.mocked(execa).mock.calls[0];
    expect(probe?.[0]).toBe('trivy');
    expect(probe?.[1]).toEqual(['--version']);
    for (const c of mockedRun.mock.calls) expect(c[0].args).toEqual(expect.arrayContaining(['--skip-version-check', '--disable-telemetry']));
  });
});

// ---------------------------------------------------------------- what .trivyignore suppressed

/**
 * Round 4, item 2: the repository's `.trivyignore` silenced findings with no
 * trace in the CI gate. Trivy lists them with `--show-suppressed` (0.50.0 and
 * later: absent in 0.49.1) under `Results[].ExperimentalModifiedFindings` —
 * measured on 0.69.3, lodash 4.17.15 with two ids ignored. `trivy config`
 * refuses the flag (an unknown flag on 0.69.3), so a config pass says what it
 * cannot list instead.
 */
const SUPPRESSED_REPORT = JSON.stringify({
  Results: [
    {
      Target: 'package-lock.json',
      Class: 'lang-pkgs',
      Type: 'npm',
      Vulnerabilities: [],
      ExperimentalModifiedFindings: [
        {
          Type: 'vulnerability',
          Status: 'ignored',
          Statement: '',
          Source: 'C:/p/.trivyignore',
          Finding: {
            VulnerabilityID: 'CVE-2020-8203',
            VendorIDs: ['GHSA-p6mc-m468-83gw'],
            PkgName: 'lodash',
            InstalledVersion: '4.17.15',
            FixedVersion: '4.17.19',
            Title: 'nodejs-lodash: prototype pollution in zipObjectDeep function',
            Description: 'Prototype pollution attack when using _.zipObjectDeep in lodash before 4.17.20.',
            Severity: 'HIGH',
          },
        },
        {
          Type: 'vulnerability',
          Status: 'ignored',
          Statement: '',
          Source: 'C:/p/.trivyignore',
          Finding: {
            VulnerabilityID: 'NSWG-ECO-516',
            PkgName: 'lodash',
            InstalledVersion: '4.17.15',
            FixedVersion: '>=4.17.19',
            Title: 'Allocation of Resources Without Limits or Throttling',
            Severity: 'HIGH',
          },
        },
      ],
    },
  ],
});

describe("what the repository's .trivyignore suppressed", () => {
  const FS = ['fs', '--scanners', 'vuln', '--format', 'json', '--output', '/r/deps.json'];

  it('asks a Trivy 0.50.0 or newer to list it, on the subcommands that accept the flag', () => {
    expect(trivyArgv({ args: FS, target: '/p' }, '/r/c.yaml', '/p/.trivyignore', '0.69.3')).toContain('--show-suppressed');
    expect(trivyArgv({ args: FS, target: '/p' }, '/r/c.yaml', '/p/.trivyignore', '0.50.0')).toContain('--show-suppressed');
    const image = ['image', '--format', 'json', '--output', '/r/i.json'];
    expect(trivyArgv({ args: image, target: 'alpine' }, '/r/c.yaml', '/p/.trivyignore', '0.69.3')).toContain('--show-suppressed');
  });

  it.each([
    ['an older Trivy (unknown flag, fatal)', FS, '0.49.1'],
    ['a Trivy whose version is unknown', FS, null],
    ['trivy config (refuses the flag on 0.69.3)', ['config', '--format', 'json', '--output', '/r/iac.json'], '0.69.3'],
  ])('does not pass it to %s', (_label, args, version) => {
    expect(trivyArgv({ args, target: '/p' }, '/r/c.yaml', '/p/.trivyignore', version)).not.toContain('--show-suppressed');
  });

  it('not without a .trivyignore', () => {
    expect(trivyArgv({ args: FS, target: '/p' }, '/r/c.yaml', null, '0.69.3')).not.toContain('--show-suppressed');
  });

  it('reads the suppressed findings out of the report: counted, named, as they would have been reported', () => {
    const s = repoSuppressionFrom(SUPPRESSED_REPORT, '/p');
    expect(s.file).toBe('.trivyignore');
    expect(s.count).toBe(2);
    expect(s.ids).toEqual(['CVE-2020-8203', 'NSWG-ECO-516']);
    expect(s.findings.map((f) => [f.rule_id, f.severity, f.file_path])).toEqual([
      ['CVE-2020-8203', 'high', 'package-lock.json'],
      ['NSWG-ECO-516', 'high', 'package-lock.json'],
    ]);
    // Bounded: an advisory's description is not carried.
    expect(s.findings.every((f) => f.message === undefined)).toBe(true);
  });

  it('is bounded: every one counted, the first ids and findings kept', () => {
    const many = {
      Results: [
        {
          Target: 'package-lock.json',
          Type: 'npm',
          ExperimentalModifiedFindings: Array.from({ length: 60 }, (_, i) => ({
            Type: 'vulnerability',
            Status: 'ignored',
            Finding: { VulnerabilityID: `CVE-2020-${1000 + i}`, PkgName: 'p', InstalledVersion: '1', Severity: 'LOW' },
          })),
        },
      ],
    };
    const s = repoSuppressionFrom(JSON.stringify(many), '/p');
    expect(s.count).toBe(60);
    expect(s.ids.length).toBeLessThanOrEqual(50);
    expect(s.findings.length).toBeLessThanOrEqual(25);
    expect(suppressionNote(s)).toMatch(/^60 findings suppressed by the repository's \.trivyignore: CVE-2020-1000, .*CVE-2020-1009 and 50 more$/);
  });

  it('names them in the run: its reason and suppressed_by_repo_config', () => {
    const suppressed = repoSuppressionFrom(SUPPRESSED_REPORT, '/p');
    const run = withHonoured({ name: 'trivy', status: 'ok' }, { honoured: ['.trivyignore'], suppressed });
    expect(run.reason).toMatch(
      /2 findings suppressed by the repository's \.trivyignore: CVE-2020-8203, NSWG-ECO-516/,
    );
    expect(run.suppressed_by_repo_config).toEqual(suppressed);
    // Nothing suppressed: the file is still named, no count is claimed.
    const none = withHonoured(
      { name: 'trivy', status: 'ok' },
      { honoured: ['.trivyignore'], suppressed: { file: '.trivyignore', count: 0, ids: [], findings: [] } },
    );
    expect(none.honoured_config).toEqual(['.trivyignore']);
    expect(none.suppressed_by_repo_config).toBeUndefined();
    expect(none.reason).not.toMatch(/suppressed by/);
  });

  it('runTrivy passes the flag and reads the report it wrote', async () => {
    vi.mocked(execa).mockResolvedValue({ exitCode: 0, stdout: 'Version: 0.69.3\n' } as never);
    const project = makeTempDir('trivy-run-project-');
    const work = makeTempDir('trivy-run-work-');
    writeFileSync(join(project, '.trivyignore'), 'CVE-2020-8203\nNSWG-ECO-516\n');
    const out = join(work, 'deps.json');
    mockedRun.mockImplementation(async () => {
      writeFileSync(out, SUPPRESSED_REPORT);
      return { outcome: 'completed', exitCode: 0, stdout: '', stderr: '', truncated: false };
    });
    const r = await runTrivy({
      args: ['fs', '--scanners', 'vuln', '--format', 'json', '--output', out, '--quiet'],
      target: project,
      workDir: work,
      ignoreFrom: project,
    });
    expect(mockedRun.mock.calls[0]?.[0].args).toContain('--show-suppressed');
    expect(r.suppressed?.count).toBe(2);
    expect(r.suppressed?.ids).toEqual(['CVE-2020-8203', 'NSWG-ECO-516']);
  });

  it('a config pass, or a Trivy too old to list them, says so rather than claiming none', async () => {
    vi.mocked(execa).mockResolvedValue({ exitCode: 0, stdout: 'Version: 0.69.3\n' } as never);
    const project = makeTempDir('trivy-run-project-');
    const work = makeTempDir('trivy-run-work-');
    writeFileSync(join(project, '.trivyignore'), 'AVD-AWS-0107\n');
    const config = await runTrivy({
      args: ['config', '--format', 'json', '--output', join(work, 'iac.json')],
      target: project,
      workDir: work,
      ignoreFrom: project,
    });
    expect(config.suppressed).toMatchObject({ file: '.trivyignore', count: null });
    expect(suppressionNote(config.suppressed ?? { file: '', count: 0, ids: [], findings: [] })).toMatch(
      /what the repository's \.trivyignore suppressed cannot be listed \(trivy config has no --show-suppressed\)/,
    );

    resetTrivyVersionCache();
    vi.mocked(execa).mockResolvedValue({ exitCode: 0, stdout: 'Version: 0.49.1\n' } as never);
    const old = await runTrivy({
      args: ['fs', '--format', 'json', '--output', join(work, 'deps.json')],
      target: project,
      workDir: work,
      ignoreFrom: project,
    });
    expect(old.suppressed?.count).toBeNull();
    expect(old.suppressed?.unlisted_because).toMatch(/Trivy 0\.49\.1 predates --show-suppressed \(0\.50\.0\)/);
  });
});

// ---------------------------------------------------------------- the whole tree

const SRC = fileURLToPath(new URL('../../../src/', import.meta.url));

function tsFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const abs = join(dir, e.name);
    if (e.isDirectory()) return tsFiles(abs);
    return e.name.endsWith('.ts') ? [abs] : [];
  });
}

/** A process spawn that names Trivy: `command: 'trivy'`, or `execa('trivy'` / `spawn('trivy'` and kin. */
const TRIVY_SPAWN = /command:\s*['"`]trivy['"`]|\b(?:execa|execaSync|spawn|spawnSync|execFile|execFileSync)\(\s*['"`]trivy['"`]/;

/**
 * The one exemption: the toolchain catalogue's `trivy --version` probe
 * (runners/installCatalog.ts), which reads no project — it runs in the
 * server's own directory, never a scanned one.
 */
const PROBE_LINE = /probe:\s*\{\s*command:\s*'trivy',\s*args:\s*\['--version'\][^}]*\}/;

/**
 * Round 2, item 7: the manifest walk stops at 20 000 directories. Cut, it
 * cannot say every manifest was read, so coverage cannot be full — the same
 * rule as `frameworks/projectLanguages.ts` (an incomplete listing claims
 * nothing as tested). Named, `trivy` stays ok, `trivy:manifest-walk` missing.
 */
describe('judgeTrivyFs: a manifest walk that stopped early', () => {
  const completed = { outcome: 'completed' as const, exitCode: 0, stdout: '', stderr: '', truncated: false, honoured: [] };
  function deepTree(): string {
    const dir = makeTempDir('trivy-walk-');
    for (const d of ['a/b/c', 'd/e/f']) mkdirSync(join(dir, ...d.split('/')), { recursive: true });
    writeFileSync(join(dir, 'package.json'), '{"dependencies":{"lodash":"4.17.4"}}');
    writeFileSync(join(dir, 'package-lock.json'), '{}');
    return dir;
  }
  const RAW = JSON.stringify({ Results: [{ Target: 'package-lock.json', Type: 'npm', Vulnerabilities: [] }] });

  it('is partial, named, never full', () => {
    const j = judgeTrivyFs({ projectPath: deepTree(), raw: RAW, run: completed, exclusions: null, maxDirs: 2 });
    expect(j.toolRun.status).toBe('ok');
    expect(j.toolRun.reason).toMatch(/manifest walk stopped after 2 directories — manifests below were not checked/);
    expect(j.missing).toEqual(['trivy:manifest-walk']);
  });

  it('a walk that read everything adds nothing', () => {
    const j = judgeTrivyFs({ projectPath: deepTree(), raw: RAW, run: completed, exclusions: null });
    expect(j).toEqual({ toolRun: { name: 'trivy', status: 'ok' }, missing: [], gaps: [] });
  });
});

describe('every Trivy spawn in src/ goes through runners/trivyRun.ts', () => {
  it('no file but the helper spawns Trivy', () => {
    const offenders: string[] = [];
    for (const path of tsFiles(SRC)) {
      const rel = relative(SRC, path).split('\\').join('/');
      if (rel === 'runners/trivyRun.ts') continue;
      readFileSync(path, 'utf8')
        .split(/\r?\n/)
        .forEach((line, i) => {
          if (TRIVY_SPAWN.test(line) && !PROBE_LINE.test(line)) offenders.push(`${rel}:${i + 1}: ${line.trim()}`);
        });
    }
    expect(offenders).toEqual([]);
  });

  it('the pattern catches what it is for (positive control)', () => {
    expect(TRIVY_SPAWN.test("        command: 'trivy',")).toBe(true);
    expect(TRIVY_SPAWN.test("await execa('trivy', ['fs'])")).toBe(true);
    expect(TRIVY_SPAWN.test("tools_run.push({ name: 'trivy', status: 'ok' })")).toBe(false);
  });
});
