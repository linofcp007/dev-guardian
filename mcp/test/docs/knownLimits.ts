/**
 * The guardrail hooks' known limits, as data.
 *
 * `test/fixtures/hooks/known-limits.yml` holds one record per limit: the text
 * `docs/hooks-known-limits.md` publishes, and examples — a command, a text or
 * a hook call — each with the verdict the detector gives it today. Three
 * consumers read it through this module:
 *
 *   - `test/unit/hooks/knownLimits.test.ts` runs every shell and secret
 *     example through the real detector;
 *   - `test/e2e/knownLimitsHook.test.ts` runs every hook example through the
 *     real dispatcher;
 *   - `test/docs/generate.ts` renders the page (`renderDocs.ts`).
 *
 * This module never calls a detector and never starts a process: it loads,
 * validates, builds an example's input and COMPARES what a detector answered
 * with what the record says — with a direction, because a guard that got
 * stricter means the limit was closed and its record must leave the list.
 *
 * Under `test/`, like `test/ablate/`: maintainer tooling that never reaches
 * `dist/`.
 */

import { fileURLToPath } from 'node:url';

/** The data file. */
export const KNOWN_LIMITS_FILE = fileURLToPath(new URL('../fixtures/hooks/known-limits.yml', import.meta.url));

/** The same file as the generated page names it: repository-relative. */
export const KNOWN_LIMITS_SOURCE = 'mcp/test/fixtures/hooks/known-limits.yml';

/** The areas a limit belongs to, in the order the page lists them. */
export const LIMIT_AREAS = [
  'config-files',
  'shell-guard',
  'download-run',
  'write-guard',
  'secret-scan',
  'mcp-tools',
  'caps',
] as const;

export type LimitArea = (typeof LIMIT_AREAS)[number];

/** The page's section title for each area. */
export const AREA_TITLES: Readonly<Record<LimitArea, string>> = {
  'config-files': 'Configuration and guarded files',
  'shell-guard': 'The shell guard',
  'download-run': 'Download and run',
  'write-guard': 'The write guards',
  'secret-scan': 'The secret scan',
  'mcp-tools': 'Third-party MCP tools',
  caps: 'Size and time limits',
};

/** An input too large to write out: `repeat` × `times`, then `then`. */
export interface BuiltInput {
  repeat: string;
  times: number;
  then: string;
}

export type ShellLevel = 'ok' | 'warn' | 'block';
export type HookDecision = 'deny' | 'ask' | 'warn' | 'none';

export interface ShellExample {
  detector: 'shell';
  shell: 'bash' | 'powershell';
  command?: string;
  build?: BuiltInput;
  /** Injected into the guard's options; default `win32` for PowerShell, `linux` for bash. */
  platform?: NodeJS.Platform;
  expect: { level: ShellLevel; ask?: boolean };
  /** Published beside the example. */
  note?: string;
}

export interface SecretExample {
  detector: 'secret';
  text?: string;
  /** Joined to make the text: a token never stands whole in the data file. */
  parts?: string[];
  build?: BuiltInput;
  expect: { hits: number };
  note?: string;
}

export interface HookExample {
  detector: 'hook';
  event: 'PreToolUse' | 'PostToolUse';
  tool: string;
  /** `${PROJECT}`, `${HOME}` and `${PLUGIN}` in its strings are replaced by the test's directories. */
  input: Record<string, unknown>;
  /** Project-relative files the test creates first. */
  files?: Record<string, string>;
  /** Runs on these platforms only; elsewhere it is reported as skipped. */
  only?: NodeJS.Platform[];
  expect: { decision: HookDecision };
  note?: string;
}

export type LimitExample = ShellExample | SecretExample | HookExample;

export interface KnownLimit {
  /** Kebab-case, stable, unique. */
  id: string;
  area: LimitArea;
  /** The published item: English, inline Markdown. */
  doc: string;
  examples: LimitExample[];
  /** Why it has no example; required when `examples` is empty. */
  not_executable?: string;
}

/** What a detector answered. */
export type Actual =
  | { detector: 'shell'; level: ShellLevel; ask: boolean }
  | { detector: 'secret'; hits: number }
  | { detector: 'hook'; decision: HookDecision };

/** `stricter`: the limit looks closed. `looser`: the guard does less than the record says. */
export type Judgement = { ok: true } | { ok: false; direction: 'stricter' | 'looser' | 'threw'; message: string };

/** One example with the record it belongs to. */
export interface ExampleRef {
  limit: KnownLimit;
  index: number;
  example: LimitExample;
}

function todo(what: string): never {
  throw new Error(`not implemented: ${what} (hook-known-limits)`);
}

/** Parses and validates the data file's text; throws naming the record and the field. */
export function parseKnownLimits(_text: string, _source: string = KNOWN_LIMITS_SOURCE): KnownLimit[] {
  return todo('parseKnownLimits');
}

/** Reads and validates the data file. */
export function loadKnownLimits(_path: string = KNOWN_LIMITS_FILE): KnownLimit[] {
  return todo('loadKnownLimits');
}

/** Every example of every record, in file order. */
export function exampleRefs(_limits: readonly KnownLimit[]): ExampleRef[] {
  return todo('exampleRefs');
}

/** The text a shell or secret example hands its detector. */
export function buildInput(_example: ShellExample | SecretExample): string {
  return todo('buildInput');
}

/** The platform a shell example is judged for. */
export function platformOf(_example: ShellExample): NodeJS.Platform {
  return todo('platformOf');
}

/** Compares what the detector answered with the record. */
export function judgeExample(_ref: ExampleRef, _actual: Actual): Judgement {
  return todo('judgeExample');
}

/** Runs `detect` for the example and judges its answer; a detector that throws fails the example. */
export function evaluateExample(_ref: ExampleRef, _detect: () => Actual): Judgement {
  return todo('evaluateExample');
}

/** The examples that run on `platform`, and those reported as skipped there. */
export function partitionByPlatform(
  _refs: readonly ExampleRef[],
  _platform: NodeJS.Platform,
): { run: ExampleRef[]; skip: ExampleRef[] } {
  return todo('partitionByPlatform');
}

/** How many records have at least one example, and how many have none. */
export function executableCounts(_limits: readonly KnownLimit[]): { total: number; withExample: number; without: number } {
  return todo('executableCounts');
}
