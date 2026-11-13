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

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it, vi } from 'vitest';

import {
  evaluateExample,
  exampleRefs,
  loadKnownLimits,
  partitionByPlatform,
  type Actual,
  type ExampleRef,
  type HookDecision,
  type HookExample,
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

/** The example's input with the test's directories in place of its placeholders. */
function substituted(value: unknown, dirs: Readonly<Record<string, string>>): unknown {
  if (typeof value === 'string') {
    return value.replace(/\$\{(PROJECT|HOME|PLUGIN)\}/g, (_all, name: string) => dirs[name] ?? '');
  }
  if (Array.isArray(value)) return value.map((v) => substituted(v, dirs));
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, substituted(v, dirs)]));
  }
  return value;
}

function answer(example: HookExample): Actual {
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
      tool_input: substituted(example.input, { PROJECT: project, HOME: home, PLUGIN: PLUGIN_ROOT }),
      cwd: project,
    },
    { cwd: project, homeDir: home },
  );
  expect(r.status, r.stderr).toBe(0);
  return { detector: 'hook', decision: decisionOf(r.stdout) };
}

describe("the hooks' known limits that live in the dispatcher", () => {
  it('T-04 the data file holds hook examples to run', () => {
    expect(HOOKS.all).toBeGreaterThan(0);
  });

  if (HOOKS.run.length > 0) {
    it.each(HOOKS.run.map((ref) => [label(ref), ref] as const))('T-04 %s answers as recorded', (_name, ref) => {
      const example = ref.example;
      if (example.detector !== 'hook') throw new Error('only hook examples run here');
      const judgement = evaluateExample(ref, () => answer(example));
      expect(judgement, judgement.ok ? '' : judgement.message).toEqual({ ok: true });
    });
  }

  for (const ref of HOOKS.skip) {
    it.skip(`T-04 ${label(ref)} answers as recorded (not on ${process.platform})`, () => {});
  }
});
