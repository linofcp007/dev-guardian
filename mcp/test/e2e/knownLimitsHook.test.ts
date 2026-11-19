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
      'install-other-runners',
      'launcher-flag-words',
      'manifest-above-project-root',
      'manifest-lockfile-and-transitive',
      'manifest-not-from-a-registry',
      'manifest-other-managers',
      'manifest-private-scope',
      'manifest-workspace-members',
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
