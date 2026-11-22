/**
 * The known limits that only exist in the dispatcher — the write guards and
 * the third-party MCP tools — pinned against `hooks/guardian-hook.mjs` itself,
 * run as a real subprocess fed the payload Claude Code sends.
 *
 * The shell and secret examples of `test/fixtures/hooks/known-limits.yml` run
 * in `test/unit/hooks/knownLimits.test.ts`; see its header for what a failure
 * means. Requires a built `mcp/dist/` (the dispatcher loads its bundle).
 *
 * Each example gets a project and a home directory of its own, with the files
 * it declares; `${PROJECT}`, `${HOME}` and `${PLUGIN}` in its input are those
 * directories and this repository. An example of another platform is reported
 * as skipped, never as passed.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  evaluateExample,
  exampleRefs,
  loadKnownLimits,
  partitionByPlatform,
  type Actual,
  type ExampleRef,
  type HookDecision,
  type HookExample,
  type KnownLimit,
} from '../docs/knownLimits.js';
import { HOOK_TIMEOUT_MS, runHook } from '../helpers/runHook.js';
import { timeoutAbove } from '../helpers/spawnCap.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

// Above the spawn cap, so a hung hook is reported by the cap, by name.
vi.setConfig({ testTimeout: timeoutAbove(HOOK_TIMEOUT_MS) });

afterAll(cleanupTempDirs);

/** This repository: the plugin whose installed files a limit is about. */
const PLUGIN_ROOT = fileURLToPath(new URL('../../..', import.meta.url));

const label = (ref: ExampleRef): string => `${ref.limit.id} #${String(ref.index + 1)}`;

/** A data file that does not load is the unit file's T-01 to report; here it only means no cases. */
function collected(): { run: ExampleRef[]; skip: ExampleRef[]; all: number } {
  try {
    const hooks = exampleRefs(loadKnownLimits()).filter((r) => r.example.detector === 'hook');
    return { ...partitionByPlatform(hooks, process.platform), all: hooks.length };
  } catch {
    return { run: [], skip: [], all: 0 };
  }
}

const HOOKS = collected();

/** What the dispatcher answered, as a record states it. */
function decisionOf(stdout: unknown): HookDecision {
  const out = (stdout as { hookSpecificOutput?: { permissionDecision?: unknown; additionalContext?: unknown } } | undefined)
    ?.hookSpecificOutput;
  if (out?.permissionDecision === 'deny') return 'deny';
  if (out?.permissionDecision === 'ask') return 'ask';
  if (typeof out?.additionalContext === 'string' && out.additionalContext !== '') return 'warn';
  return 'none';
}

/**
 * A fake AWS key the secret scan reports on a write (AWS's own `…EXAMPLE` key
 * is a placeholder it skips). Joined here, so it never stands whole in the
 * data file — which must itself hold no secret.
 */
const FAKE_AWS_KEY = ['AKIA', 'Q7XZ2M9KDP4RWT3B'].join('');

/** The example's input with the test's directories and its fake key in place of the placeholders. */
function substituted(value: unknown, dirs: Readonly<Record<string, string>>): unknown {
  if (typeof value === 'string') {
    return value.replace(/\$\{(PROJECT|HOME|PLUGIN|FAKE_AWS_KEY)\}/g, (_all, name: string) => dirs[name] ?? '');
  }
  if (Array.isArray(value)) return value.map((v) => substituted(v, dirs));
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, substituted(v, dirs)]));
  }
  return value;
}

/**
 * What an example's hook call gets in its environment beside the launcher's
 * own. The install-vetting examples run with the network switched off
 * (install-vet-lockfile-pins): one that holds a lockfile would otherwise ask
 * OSV, from the suite, about what the lockfile pins — and a record of that
 * area states what the guard answers WITHOUT the network. Set here, not left
 * to the suite's own default (`vitest.config.ts`), which another
 * configuration need not have.
 */
function exampleEnv(limit: KnownLimit): Record<string, string> {
  return limit.area === 'install-vetting' ? { GUARDIAN_OFFLINE: '1' } : {};
}

function answer(example: HookExample, env: Record<string, string> = {}): Actual {
  const project = makeTempDir('guardian-limit-project-');
  const home = makeTempDir('guardian-limit-home-');
  for (const [rel, content] of Object.entries(example.files ?? {})) {
    const target = resolve(project, rel);
    const inside = relative(project, target);
    if (inside === '' || inside.startsWith('..') || isAbsolute(inside)) {
      throw new Error(`the example's file ${rel} is not inside its project`);
    }
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, content, 'utf8');
  }
  const r = runHook(
    {
      hook_event_name: example.event,
      tool_name: example.tool,
      tool_input: substituted(example.input, { PROJECT: project, HOME: home, PLUGIN: PLUGIN_ROOT, FAKE_AWS_KEY }),
      cwd: project,
    },
    { cwd: project, homeDir: home, env },
  );
  expect(r.status, r.stderr).toBe(0);
  return { detector: 'hook', decision: decisionOf(r.stdout) };
}

describe("the hooks' known limits that live in the dispatcher", () => {
  it('T-04 the data file holds hook examples to run', () => {
    expect(HOOKS.all).toBeGreaterThan(0);
  });

  // Most hook examples record `none`. A dispatcher whose bundle is missing
  // also answers nothing (it fails open), so "none" only means something
  // while the same launch still denies what it must.
  it('T-04 the dispatcher these examples run through is answering: a write of the hook configuration is denied', () => {
    const control: HookExample = {
      detector: 'hook',
      event: 'PreToolUse',
      tool: 'Write',
      input: { file_path: '${PROJECT}/.guardian/hooks.config.json', content: '{ "enabled": false }\n' },
      expect: { decision: 'deny' },
    };
    expect(answer(control)).toEqual({ detector: 'hook', decision: 'deny' });
  });

  if (HOOKS.run.length > 0) {
    it.each(HOOKS.run.map((ref) => [label(ref), ref] as const))('T-04 %s answers as recorded', (_name, ref) => {
      const example = ref.example;
      if (example.detector !== 'hook') throw new Error('only hook examples run here');
      const judgement = evaluateExample(ref, () => answer(example, exampleEnv(ref.limit)));
      expect(judgement, judgement.ok ? '' : judgement.message).toEqual({ ok: true });
    });
  }

  for (const ref of HOOKS.skip) {
    it.skip(`T-04 ${label(ref)} answers as recorded (not on ${process.platform})`, () => {});
  }
});

// ───────────────── install-vet-manifest-install — the manifest vetting's limits, through the dispatcher

describe('the limits of the manifest vetting run through the dispatcher', () => {
  it('T-26 the hook examples of the install-vetting area are among those this file runs', () => {
    const ids = new Set(
      [...HOOKS.run, ...HOOKS.skip].filter((r) => (r.limit.area as string) === 'install-vetting').map((r) => r.limit.id),
    );
    expect([...ids].sort()).toEqual([
      'archive-like-names',
      'corepack-manager-download',
      'dotnet-other-install-forms',
      'install-candidates-over-ceiling',
      'install-global-update-by-name',
      'install-initializers',
      'install-inline-script-deps',
      'install-launcher-runs-manager',
      'install-other-runners',
      'install-python-option-parsing',
      'install-python-tool-forms',
      'install-redirect-glued-word',
      'launcher-flag-words',
      'lockfile-origin-host-unsaid',
      'manifest-above-project-root',
      'manifest-lockfile-and-transitive',
      'manifest-not-from-a-registry',
      'manifest-other-managers',
      'manifest-private-scope',
      'manifest-value-not-a-range',
      'manifest-workspace-members',
      'npm-short-flag-groups',
      'tilde-range-word',
      'yarn-bun-npm-protocol',
    ]);
  });

  // Those examples mostly record `none`. So would a dispatcher that never read a manifest: the control is a
  // manifest install it must answer — offline, so nothing is asked of a registry, it says what it did not verify.
  it('T-26 the dispatcher these examples run through does read a manifest: offline, it says what it could not verify', () => {
    const project = makeTempDir('guardian-limit-project-');
    const home = makeTempDir('guardian-limit-home-');
    writeFileSync(resolve(project, 'package.json'), JSON.stringify({ dependencies: { express: '^4.21.0', 'left-pad': '^1.3.0' } }), 'utf8');
    const r = runHook(
      { hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'npm ci' }, cwd: project },
      { cwd: project, homeDir: home, env: { GUARDIAN_OFFLINE: '1' } },
    );
    expect(r.status, r.stderr).toBe(0);
    expect(decisionOf(r.stdout)).toBe('warn');
    expect(JSON.stringify(r.stdout)).toMatch(/2 packages of package\.json.*not verified/);
  });
});

// ───────────────── install-vet-lockfile-pins — the lockfile's limits, through the dispatcher and without the network

describe('install-vet-lockfile-pins', () => {
  const RECORD = 'manifest-lockfile-and-transitive';

  /** The fetch stand-in of the hook tests (`fetchMockPreload.mjs`): given no route, it refuses every request, and logs it. */
  const PRELOAD = new URL('../helpers/fetchMockPreload.mjs', import.meta.url).href;
  /** A launch with that stand-in in the dispatcher's process: a request an example made would be in `log`, never on a real network. */
  const traced = (log: string): Record<string, string> => ({
    NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ''} --import=${PRELOAD}`.trim(),
    GUARDIAN_TEST_FETCH_LOG: log,
  });
  const requestsIn = (log: string): string[] => (existsSync(log) ? readFileSync(log, 'utf8').split('\n').filter(Boolean) : []);

  function lockfileRecord(): KnownLimit {
    const limit = loadKnownLimits().find((l) => l.id === RECORD);
    if (limit === undefined) throw new Error(`the data file has no record ${RECORD}`);
    return limit;
  }

  // The suite's own default is the network switched off (`vitest.config.ts`). Taken away here, so that what keeps these
  // launches off the network is what the harness hands an install-vetting example — `exampleEnv` — and nothing else.
  beforeEach(() => {
    vi.stubEnv('GUARDIAN_OFFLINE', '0');
  });
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  // The record's examples answer `none`, or with a line. So would a dispatcher that never opened a lockfile: the
  // control is a manifest install whose lockfile pins two packages — with the network off, it says how many packages
  // OF THE LOCKFILE it could not verify.
  it('T-32 the dispatcher these examples run through does read a lockfile: without the network, it says how many of its packages it could not verify', () => {
    const project = makeTempDir('guardian-limit-project-');
    const home = makeTempDir('guardian-limit-home-');
    const log = join(home, 'fetch.log');
    const tarball = (name: string, version: string): string => `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`;
    writeFileSync(
      resolve(project, 'package.json'),
      JSON.stringify({ name: 'app', version: '1.0.0', dependencies: { express: '^4.21.0' } }),
      'utf8',
    );
    writeFileSync(
      resolve(project, 'package-lock.json'),
      JSON.stringify(
        {
          name: 'app',
          version: '1.0.0',
          lockfileVersion: 3,
          requires: true,
          packages: {
            '': { name: 'app', version: '1.0.0', dependencies: { express: '^4.21.0' } },
            'node_modules/eslint-config-prettier': { version: '10.1.8', resolved: tarball('eslint-config-prettier', '10.1.8') },
            'node_modules/express': {
              version: '4.21.2',
              resolved: tarball('express', '4.21.2'),
              dependencies: { 'eslint-config-prettier': '^10.1.0' },
            },
          },
        },
        null,
        2,
      ),
      'utf8',
    );
    const r = runHook(
      { hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'npm ci' }, cwd: project },
      { cwd: project, homeDir: home, env: { ...exampleEnv(lockfileRecord()), ...traced(log) } },
    );
    expect(r.status, r.stderr).toBe(0);
    expect(decisionOf(r.stdout)).toBe('warn');
    expect(JSON.stringify(r.stdout)).toMatch(/could not vet 2 packages of package-lock\.json/);
    expect(requestsIn(log)).toEqual([]);
  });

  // A protection: true before the feature, when no example asks anything, and what holds the rewritten record's
  // examples — each with a lockfile the hook would ask OSV about — off the network.
  it('T-32 every example of the record answers as recorded with the network switched off by the harness: nothing is asked', () => {
    const refs = HOOKS.run.filter((r) => r.limit.id === RECORD);
    expect(refs.length).toBeGreaterThan(0);

    // The stand-in really is in the launched process: handed routes that are not JSON, it stops the launch.
    const scratch = makeTempDir('guardian-limit-project-');
    const dead = runHook(
      { hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'echo ok' }, cwd: scratch },
      { cwd: scratch, env: { ...exampleEnv(lockfileRecord()), ...traced(join(scratch, 'fetch.log')), GUARDIAN_TEST_FETCH_ROUTES: '{not json' } },
    );
    expect(dead.status).not.toBe(0);
    expect(dead.stderr).toContain('fetchMockPreload');

    for (const ref of refs) {
      const example = ref.example;
      if (example.detector !== 'hook') throw new Error('only hook examples run here');
      expect(exampleEnv(ref.limit)).toEqual({ GUARDIAN_OFFLINE: '1' });
      const log = join(makeTempDir('guardian-limit-log-'), 'fetch.log');
      const judgement = evaluateExample(ref, () => answer(example, { ...exampleEnv(ref.limit), ...traced(log) }));
      expect(judgement, judgement.ok ? '' : judgement.message).toEqual({ ok: true });
      expect({ example: label(ref), requests: requestsIn(log) }).toEqual({ example: label(ref), requests: [] });
    }
  });
});

// ───────────────── install-vet-through-corepack — the two records of what stays

describe('install-vet-through-corepack', () => {
  it('T-06 the records of the corepack download and of the other runners exist, and every example of theirs is one the dispatcher harness runs', () => {
    const limits = loadKnownLimits();
    // The harness above iterates HOOKS.run and HOOKS.skip (named by label, as its tests are): an example outside them would never be checked against the dispatcher.
    const harnessed = new Set([...HOOKS.run, ...HOOKS.skip].map((ref) => label(ref)));
    for (const id of ['corepack-manager-download', 'install-other-runners']) {
      const record = limits.find((l) => l.id === id);
      expect(record, `the data file has no record ${id}`).toBeDefined();
      expect(record?.area).toBe('install-vetting');
      const examples = record?.examples ?? [];
      expect(examples.filter((e) => e.detector === 'hook').length, id).toBeGreaterThan(0);
      for (const [index, example] of examples.entries()) {
        expect({ id, detector: example.detector, harnessed: harnessed.has(`${id} #${String(index + 1)}`) }).toEqual({ id, detector: 'hook', harnessed: true });
      }
    }
  });
});

// ───────────────── install-vet-unknown-flag-hides-package — the record of the candidate ceiling

describe('install-vet-unknown-flag-hides-package', () => {
  it('T-12 the record of the candidate ceiling exists, is an install-vetting record with a hook example, and its example is one the dispatcher harness runs', () => {
    const id = 'install-candidates-over-ceiling';
    const record = loadKnownLimits().find((l) => l.id === id);
    expect(record, `the data file has no record ${id}`).toBeDefined();
    expect(record?.area).toBe('install-vetting');
    const examples = record?.examples ?? [];
    expect(examples.filter((e) => e.detector === 'hook').length).toBeGreaterThan(0);
    const harnessed = new Set([...HOOKS.run, ...HOOKS.skip].map((ref) => label(ref)));
    for (const [index, example] of examples.entries()) {
      expect({ detector: example.detector, harnessed: harnessed.has(`${id} #${String(index + 1)}`) }).toEqual({ detector: 'hook', harnessed: true });
    }
  });
});

// ───────────────── install-vet-dotnet-forms — the record of the .NET forms that stay unread

describe('install-vet-dotnet-forms', () => {
  it('T-05 the record of the other .NET install forms exists, is an install-vetting record with hook examples, and its examples are ones the dispatcher harness runs', () => {
    const id = 'dotnet-other-install-forms';
    const record = loadKnownLimits().find((l) => l.id === id);
    expect(record, `the data file has no record ${id}`).toBeDefined();
    expect(record?.area).toBe('install-vetting');
    const examples = record?.examples ?? [];
    expect(examples.filter((e) => e.detector === 'hook').length).toBeGreaterThan(0);
    const harnessed = new Set([...HOOKS.run, ...HOOKS.skip].map((ref) => label(ref)));
    for (const [index, example] of examples.entries()) {
      expect({ detector: example.detector, harnessed: harnessed.has(`${id} #${String(index + 1)}`) }).toEqual({ detector: 'hook', harnessed: true });
    }
  });
});

// ───────────────── install-vet-manifest-parent-dir — the record of the manifest above the project root

describe('install-vet-manifest-parent-dir', () => {
  it('T-07 the record of a package.json above the project root exists, is an install-vetting record with a hook example, and its example is one the dispatcher harness runs', () => {
    const id = 'manifest-above-project-root';
    const record = loadKnownLimits().find((l) => l.id === id);
    expect(record, `the data file has no record ${id}`).toBeDefined();
    expect(record?.area).toBe('install-vetting');
    const examples = record?.examples ?? [];
    expect(examples.filter((e) => e.detector === 'hook').length).toBeGreaterThan(0);
    const harnessed = new Set([...HOOKS.run, ...HOOKS.skip].map((ref) => label(ref)));
    for (const [index, example] of examples.entries()) {
      expect({ detector: example.detector, harnessed: harnessed.has(`${id} #${String(index + 1)}`) }).toEqual({ detector: 'hook', harnessed: true });
    }
  });
});

// ───────────────── install-vet-npm-unread-verbs — the record of what the initializers leave unverified

describe('install-vet-npm-unread-verbs', () => {
  describe('known limits', () => {
    it('T-07 the record `install-initializers` exists, is an install-vetting record with hook examples the dispatcher harness runs, and says what these verbs leave unverified or only warn about', () => {
      const id = 'install-initializers';
      const record = loadKnownLimits().find((l) => l.id === id);
      expect(record, `the data file has no record ${id}`).toBeDefined();
      expect(record?.area).toBe('install-vetting');
      const examples = record?.examples ?? [];
      expect(examples.filter((e) => e.detector === 'hook').length).toBeGreaterThan(0);
      const harnessed = new Set([...HOOKS.run, ...HOOKS.skip].map((ref) => label(ref)));
      for (const [index, example] of examples.entries()) {
        expect({ detector: example.detector, harnessed: harnessed.has(`${id} #${String(index + 1)}`) }).toEqual({ detector: 'hook', harnessed: true });
      }
      // The harness runs offline: what an example shows is "could not vet" or silence, never the refusal of a missing name.
      expect(examples.filter((e) => e.detector === 'hook' && e.expect.decision === 'deny')).toEqual([]);
      const doc = record?.doc ?? '';
      expect(doc).toContain('bun create');
      expect(doc).toContain('.bun-create');
      expect(doc).toContain('yarn create @scope@');
      expect(doc).toContain('yarn create -p');
      expect(doc).toContain('create-');
    });

    it('T-07 the record `manifest-other-managers` says that a package given to `npm install-test` is vetted', () => {
      const record = loadKnownLimits().find((l) => l.id === 'manifest-other-managers');
      expect(record, 'the data file has no record manifest-other-managers').toBeDefined();
      expect(record?.doc ?? '').toMatch(/a package given to `npm install-test` is (?:vetted|verified|looked up)/);
    });
  });
});

// ───────────────── install-vet-global-update-by-name — the record of what a global update by name leaves unverified

describe('install-vet-global-update-by-name', () => {
  it('T-07 the record `install-global-update-by-name` exists, says what a global update by name leaves unverified, and has the three offline hook examples the harness runs', () => {
    const id = 'install-global-update-by-name';
    const record = loadKnownLimits().find((l) => l.id === id);
    expect(record, `the data file has no record ${id}`).toBeDefined();
    expect(record?.area).toBe('install-vetting');
    const examples = record?.examples ?? [];
    expect(
      examples.map((e) => ({ detector: e.detector, command: e.detector === 'hook' ? e.input.command : undefined, decision: e.detector === 'hook' ? e.expect.decision : undefined })).sort((a, b) => String(a.command).localeCompare(String(b.command))),
    ).toEqual([
      { detector: 'hook', command: 'npm update -g', decision: 'warn' },
      { detector: 'hook', command: 'npm update -g left-pad', decision: 'warn' },
      { detector: 'hook', command: 'yarn workspace docs upgrade left-pad', decision: 'none' },
    ]);
    const harnessed = new Set([...HOOKS.run, ...HOOKS.skip].map((ref) => label(ref)));
    for (const index of examples.keys()) expect(harnessed.has(`${id} #${String(index + 1)}`), `${id} #${String(index + 1)} is run by the dispatcher harness`).toBe(true);
    const doc = record?.doc ?? '';
    expect(doc).toContain('globally installed');
    expect(doc).toContain('install scripts');
    expect(doc).toContain('vulnerabilities');
    expect(doc).toContain('`yarn workspace <w> upgrade <P>`');
  });
});

// ───────────────── install-vet-launcher-runs-manager — what a launcher in front of a package manager leaves unverified

describe('install-vet-launcher-runs-manager', () => {
  const ID = 'install-launcher-runs-manager';
  const record = (id: string): KnownLimit | undefined => loadKnownLimits().find((l) => l.id === id);
  const commandOf = (e: { detector: string; input?: Record<string, unknown> }): string => (e.detector === 'hook' ? String(e.input?.['command']) : '');

  it('T-08 the record `install-other-runners` no longer says the package behind a launcher that runs a manager is not vetted, and its launcher examples are gone', () => {
    const other = record('install-other-runners');
    expect(other, 'the data file has no record install-other-runners').toBeDefined();
    const doc = other?.doc ?? '';
    expect(doc).not.toContain('the package the manager then installs is not vetted');
    expect(doc).not.toMatch(/npx (?:corepack|pnpm|yarn) /);
    const launchers = (other?.examples ?? []).map(commandOf).filter((c) => /^(?:npx|npm exec|pnpm dlx|yarn dlx|bunx|bun x|pnpx) /.test(c));
    expect(launchers).toEqual([]);
  });

  it('T-08 the record `install-launcher-runs-manager` exists, says the forms that were not measured, the one level, `@pnpm/exe`, `@yarnpkg/cli-dist` and `pnpm exec <manager>`, and has hook examples the dispatcher harness runs', () => {
    const limit = record(ID);
    expect(limit, `the data file has no record ${ID}`).toBeDefined();
    expect(limit?.area).toBe('install-vetting');
    const examples = limit?.examples ?? [];
    expect(examples.filter((e) => e.detector === 'hook').length).toBeGreaterThan(0);
    const harnessed = new Set([...HOOKS.run, ...HOOKS.skip].map((ref) => label(ref)));
    for (const [index, example] of examples.entries()) {
      expect({ detector: example.detector, harnessed: harnessed.has(`${ID} #${String(index + 1)}`) }).toEqual({ detector: 'hook', harnessed: true });
    }
    // The harness runs offline: what an example shows is "could not vet" or silence, never the refusal of a missing name.
    expect(examples.filter((e) => e.detector === 'hook' && e.expect.decision === 'deny')).toEqual([]);
    const doc = limit?.doc ?? '';
    expect(doc).toMatch(/not measured|unmeasured/i);
    expect(doc).toContain('npx npx pnpm');
    expect(doc).toContain('npx pnpm dlx yarn');
    expect(doc).toContain('@pnpm/exe');
    expect(doc).toContain('@yarnpkg/cli-dist');
    expect(doc).toContain('pnpm exec');
    // docs.test.ts keeps this phrase out of every known limit.
    expect(doc).not.toContain('pnpm install <package>');
  });

  it('T-08 the record `install-launcher-runs-manager` has the example `npx pnpm add left-pad` with `node_modules/pnpm/package.json` in the project, which warns (without the fix it is silent)', () => {
    const examples = record(ID)?.examples ?? [];
    const found = examples.filter(
      (e) => e.detector === 'hook' && commandOf(e) === 'npx pnpm add left-pad' && Object.keys(e.files ?? {}).includes('node_modules/pnpm/package.json'),
    );
    expect(found.map((e) => (e.detector === 'hook' ? e.expect.decision : undefined))).toEqual(['warn']);
  });
});

// ───────────────── install-vet-redirect-glued-word — what a word glued to a redirection leaves unverified

describe('install-vet-redirect-glued-word', () => {
  const ID = 'install-redirect-glued-word';
  const record = (id: string): KnownLimit | undefined => loadKnownLimits().find((l) => l.id === id);

  it('T-07 the record `yarn-bun-npm-protocol` no longer says that a range written without quotes is not read', () => {
    const limit = record('yarn-bun-npm-protocol');
    expect(limit, 'the data file has no record yarn-bun-npm-protocol').toBeDefined();
    expect(limit?.doc ?? '').not.toContain('unquoted, the shell takes `>` for a redirection');
  });

  it('T-07 the install-vetting hook examples this file runs include the record `install-redirect-glued-word`', () => {
    const ids = new Set([...HOOKS.run, ...HOOKS.skip].filter((r) => (r.limit.area as string) === 'install-vetting').map((r) => r.limit.id));
    expect(ids.has(ID), `the hook examples of ${ID} are run by this harness`).toBe(true);
  });

  it('T-07 the record `install-redirect-glued-word` exists, says what stays, and has offline hook examples the dispatcher harness runs', () => {
    const limit = record(ID);
    expect(limit, `the data file has no record ${ID}`).toBeDefined();
    expect(limit?.area).toBe('install-vetting');
    const examples = limit?.examples ?? [];
    expect(examples.filter((e) => e.detector === 'hook').length).toBeGreaterThan(0);
    const harnessed = new Set([...HOOKS.run, ...HOOKS.skip].map((ref) => label(ref)));
    for (const [index, example] of examples.entries()) {
      expect({ detector: example.detector, harnessed: harnessed.has(`${ID} #${String(index + 1)}`) }).toEqual({ detector: 'hook', harnessed: true });
    }
    // The harness runs offline: what an example shows is "could not vet" or silence, never the refusal of a missing name.
    expect(examples.filter((e) => e.detector === 'hook' && e.expect.decision === 'deny')).toEqual([]);
    const doc = limit?.doc ?? '';
    // With the PowerShell tool the target of `<name>> out.txt` is asked of the registry as a package.
    expect(doc).toContain('PowerShell');
    expect(doc).toContain('> out.txt');
    // `name@` under a launcher, and `name@npm:` for npm and pnpm, were not measured.
    expect(doc).toMatch(/not measured|unmeasured/i);
    expect(doc).toContain('npx');
    expect(doc).toContain('@npm:');
  });

  it('T-07 the record `install-redirect-glued-word` shows a PowerShell-tool example of a name glued to `>`, and an example of a name ending in `@` under a launcher, both answering "could not vet"', () => {
    const hooks = (record(ID)?.examples ?? []).flatMap((e) => (e.detector === 'hook' ? [e] : []));
    const command = (e: HookExample): string => String(e.input['command']);
    const powershell = hooks.filter((e) => e.tool === 'PowerShell' && command(e).includes('> out.txt'));
    const launcher = hooks.filter((e) => /^(?:npx|pnpm dlx) \S+@$/.test(command(e)));
    expect({ powershell: powershell.map((e) => e.expect.decision), launcher: launcher.map((e) => e.expect.decision) }).toEqual({
      powershell: ['warn'],
      launcher: ['warn'],
    });
  });
});

// ───────────────── install-vet-over-ceiling-asks — the candidate ceiling is a question now, not a note

describe('install-vet-over-ceiling-asks', () => {
  const ID = 'install-candidates-over-ceiling';
  const record = (): KnownLimit | undefined => loadKnownLimits().find((l) => l.id === ID);

  it('T-06 the record `install-candidates-over-ceiling` says the hook asks the user before the install runs, and no longer says it does not deny or ask', () => {
    const doc = (record()?.doc ?? '').replace(/\s+/g, ' ');
    expect(record(), `the data file has no record ${ID}`).toBeDefined();
    expect(doc).not.toContain('it does not deny or ask');
    expect(doc).toContain('the hook says how many packages of the command were not vetted and asks the user before the install runs');
  });

  it('T-06 the record expects `ask` of its example, and the dispatcher, run without the network, gives `ask`', () => {
    const hooks = (record()?.examples ?? []).flatMap((e) => (e.detector === 'hook' ? [e] : []));
    expect(hooks.map((e) => e.expect.decision)).toEqual(['ask']);
    const limit = record();
    expect(limit).toBeDefined();
    const env = limit === undefined ? {} : exampleEnv(limit);
    const given = hooks.map((e) => {
      const got = answer(e, env);
      return got.detector === 'hook' ? got.decision : got.detector;
    });
    expect(given).toEqual(['ask']);
  });
});

// ───────────────── install-vet-python-tool-forms — what the Python forms that fetch a package and build it leave unverified

describe('install-vet-python-tool-forms', () => {
  const record = (id: string): KnownLimit | undefined => loadKnownLimits().find((l) => l.id === id);
  const commandOf = (e: { detector: string; input?: Record<string, unknown> }): string => (e.detector === 'hook' ? String(e.input?.['command']) : '');
  const decisionOf = (e: { detector: string; expect: unknown }): unknown => (e.detector === 'hook' ? (e.expect as { decision?: unknown }).decision : undefined);
  /** The records' examples as the commands and the decisions they state, in the order of the data file. */
  const stated = (id: string): Array<{ command: string; decision: unknown }> =>
    (record(id)?.examples ?? []).map((e) => ({ command: commandOf(e), decision: decisionOf(e) }));
  const harnessed = (): Set<string> => new Set([...HOOKS.run, ...HOOKS.skip].map((ref) => label(ref)));

  describe('known limits', () => {
    it('T-06 the record `install-python-tool-forms` exists in the area install-vetting and says what stays: the symbols and the measurements it names', () => {
      const id = 'install-python-tool-forms';
      const limit = record(id);
      expect(limit, `the data file has no record ${id}`).toBeDefined();
      expect(limit?.area).toBe('install-vetting');
      const doc = (limit?.doc ?? '').replace(/\s+/g, ' ');
      expect(doc).toMatch(/not measured|unmeasured/i);
      for (const symbol of [
        'sdist',
        '--suffix',
        'pipx reinstall',
        'pipx runpip',
        '--with-requirements',
        '-r https://',
        'upgrade-shared',
        'reinstall-all',
        'install-all',
        'uv tool upgrade --all',
        'pipx upgrade-all',
      ]) {
        expect({ symbol, named: doc.includes(symbol) }).toEqual({ symbol, named: true });
      }
    });

    it('T-06 the record `install-python-tool-forms` has the five hook examples the dispatcher harness runs, each with the decision it states', () => {
      const id = 'install-python-tool-forms';
      expect(stated(id)).toEqual(
        expect.arrayContaining([
          { command: 'pipx upgrade-all', decision: 'warn' },
          { command: 'py -m pip download dgprobe-zzq7731-named', decision: 'warn' },
          { command: 'pipx runpip dgprobe-zzq7731-tool list', decision: 'none' },
          { command: 'pipx upgrade-shared', decision: 'none' },
          { command: 'pipx reinstall-all', decision: 'none' },
        ]),
      );
      const run = harnessed();
      for (const index of (record(id)?.examples ?? []).keys()) {
        expect({ example: index + 1, harnessed: run.has(`${id} #${String(index + 1)}`) }).toEqual({ example: index + 1, harnessed: true });
      }
    });

    it('T-06 the record `install-python-option-parsing` exists in the same area, with the two examples of the disagreements, which warn', () => {
      const id = 'install-python-option-parsing';
      const limit = record(id);
      expect(limit, `the data file has no record ${id}`).toBeDefined();
      expect(limit?.area).toBe('install-vetting');
      expect(stated(id)).toEqual(
        expect.arrayContaining([
          { command: 'pipx upgrade --inst dgprobe-zzq7731-named', decision: 'warn' },
          { command: 'pip download --no-bin :all: dgprobe-zzq7731-named', decision: 'warn' },
        ]),
      );
      const run = harnessed();
      for (const index of (limit?.examples ?? []).keys()) {
        expect({ example: index + 1, harnessed: run.has(`${id} #${String(index + 1)}`) }).toEqual({ example: index + 1, harnessed: true });
      }
    });

    it('T-06 the record `manifest-other-managers` names `pip download -r`', () => {
      const limit = record('manifest-other-managers');
      expect(limit, 'the data file has no record manifest-other-managers').toBeDefined();
      expect(limit?.doc ?? '').toContain('pip download -r');
    });
  });
});
