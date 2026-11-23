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

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';

/** The data file. */
export const KNOWN_LIMITS_FILE = fileURLToPath(new URL('../fixtures/hooks/known-limits.yml', import.meta.url));

/** The same file as the generated page names it: repository-relative. */
export const KNOWN_LIMITS_SOURCE = 'mcp/test/fixtures/hooks/known-limits.yml';

/** The areas a limit belongs to, in the order the page lists them. */
export const LIMIT_AREAS = [
  'config-files',
  'shell-guard',
  'download-run',
  'install-vetting',
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
  'install-vetting': 'Install-time package vetting',
  'write-guard': 'The write guards',
  'secret-scan': 'The secret scan',
  'mcp-tools': 'Third-party MCP tools',
  caps: 'Size and time limits',
};

// ------------------------------------------------------------------ schema

const PLATFORMS = ['win32', 'linux', 'darwin'] as const;

/**
 * A piece of a built input. The page shows each piece as code, and Markdown
 * has no way to show a space at the edge of a code span, so a piece carries
 * none: put the space inside the neighbouring piece, or use a separator.
 */
const builtPiece = z
  .string()
  .min(1)
  .refine((s) => s === s.trim(), 'starts or ends with white space, which the page cannot show');

/** An input too large, or too token-like, to write out: `start`, `repeat` × `times`, then `then`. */
const builtInput = z.strictObject({
  start: builtPiece.optional(),
  repeat: builtPiece,
  times: z.number().int().min(1).max(2_000_000),
  then: builtPiece,
});

const note = z.string().trim().min(1).optional();

const shellExample = z.strictObject({
  detector: z.literal('shell'),
  shell: z.enum(['bash', 'powershell']),
  command: z.string().min(1).optional(),
  build: builtInput.optional(),
  /** Injected into the guard's options; default `win32` for PowerShell, `linux` for bash. */
  platform: z.enum(PLATFORMS).optional(),
  expect: z.strictObject({ level: z.enum(['ok', 'warn', 'block']), ask: z.boolean().optional() }),
  /** Published beside the example. */
  note,
});

const secretExample = z.strictObject({
  detector: z.literal('secret'),
  text: z.string().min(1).optional(),
  /** Joined to make the text: a token never stands whole in the data file. */
  parts: z.array(z.string().min(1)).min(2).optional(),
  build: builtInput.optional(),
  expect: z.strictObject({ hits: z.number().int().min(0) }),
  note,
});

const hookExample = z.strictObject({
  detector: z.literal('hook'),
  event: z.enum(['PreToolUse', 'PostToolUse']),
  tool: z.string().min(1),
  /** `${PROJECT}`, `${HOME}`, `${PLUGIN}` and `${FAKE_AWS_KEY}` in its strings are filled in by the test. */
  input: z.record(z.string(), z.unknown()),
  /** Project-relative files the test creates first. */
  files: z.record(z.string(), z.string()).optional(),
  /** Runs on these platforms only; elsewhere it is reported as skipped. */
  only: z.array(z.enum(PLATFORMS)).min(1).optional(),
  expect: z.strictObject({ decision: z.enum(['deny', 'ask', 'warn', 'none']) }),
  note,
});

const limitRecord = z.strictObject({
  /** Kebab-case, stable, unique. */
  id: z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/, 'expected a kebab-case id'),
  area: z.enum(LIMIT_AREAS),
  /** The published item: English Markdown — inline, or several lines (paragraphs and `- ` lists), which the page indents inside the item. */
  doc: z.string().trim().min(1),
  examples: z.array(z.discriminatedUnion('detector', [shellExample, secretExample, hookExample])).default([]),
  /** Why it has no example; required when `examples` is empty. */
  not_executable: z.string().trim().min(1).optional(),
});

export type BuiltInput = z.infer<typeof builtInput>;
export type ShellExample = z.infer<typeof shellExample>;
export type SecretExample = z.infer<typeof secretExample>;
export type HookExample = z.infer<typeof hookExample>;
export type LimitExample = ShellExample | SecretExample | HookExample;
export type KnownLimit = z.infer<typeof limitRecord>;

export type ShellLevel = ShellExample['expect']['level'];
export type HookDecision = HookExample['expect']['decision'];

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

/** A data file the schema refuses; its message names the record and the field. */
export class KnownLimitsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KnownLimitsError';
  }
}

// ----------------------------------------------------------------- loading

/** `record "id" (#3)`, or the position alone when the record has no usable id. */
function recordName(raw: unknown, position: number): string {
  const id = raw !== null && typeof raw === 'object' ? (raw as { id?: unknown }).id : undefined;
  return typeof id === 'string' && id !== '' ? `record "${id}" (#${String(position)})` : `record #${String(position)}`;
}

/** How many of an example's alternative inputs are given. */
function given(...values: unknown[]): number {
  return values.filter((v) => v !== undefined).length;
}

/** Parses and validates the data file's text; throws naming the record and the field. */
export function parseKnownLimits(text: string, source: string = KNOWN_LIMITS_SOURCE): KnownLimit[] {
  let raw: unknown;
  try {
    raw = parseYaml(text);
  } catch (error) {
    throw new KnownLimitsError(`${source}: not valid YAML: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!Array.isArray(raw)) throw new KnownLimitsError(`${source}: expected a list of records`);

  const limits: KnownLimit[] = [];
  const seen = new Set<string>();
  raw.forEach((item: unknown, i) => {
    const name = recordName(item, i + 1);
    const parsed = limitRecord.safeParse(item);
    if (!parsed.success) {
      const problems = parsed.error.issues.map((issue) => {
        const at = issue.path.map(String).join('.');
        return at === '' ? issue.message : `${at}: ${issue.message}`;
      });
      throw new KnownLimitsError(`${source}: ${name}: ${problems.join('; ')}`);
    }
    const limit = parsed.data;
    if (seen.has(limit.id)) throw new KnownLimitsError(`${source}: ${name}: id is used by an earlier record`);
    seen.add(limit.id);
    if (limit.examples.length === 0 && limit.not_executable === undefined) {
      throw new KnownLimitsError(
        `${source}: ${name}: it has no examples, so it needs not_executable — the reason no test can run it`,
      );
    }
    limit.examples.forEach((example, e) => {
      const where = `${source}: ${name}: examples.${String(e)}`;
      if (example.detector === 'shell' && given(example.command, example.build) !== 1) {
        throw new KnownLimitsError(`${where}: give exactly one of command and build`);
      }
      if (example.detector === 'secret' && given(example.text, example.parts, example.build) !== 1) {
        throw new KnownLimitsError(`${where}: give exactly one of text, parts and build`);
      }
    });
    limits.push(limit);
  });
  return limits;
}

/** Reads and validates the data file. */
export function loadKnownLimits(path: string = KNOWN_LIMITS_FILE): KnownLimit[] {
  return parseKnownLimits(readFileSync(path, 'utf8'), path === KNOWN_LIMITS_FILE ? KNOWN_LIMITS_SOURCE : path);
}

/** Every example of every record, in file order. */
export function exampleRefs(limits: readonly KnownLimit[]): ExampleRef[] {
  return limits.flatMap((limit) => limit.examples.map((example, index) => ({ limit, index, example })));
}

/** The text a shell or secret example hands its detector. */
export function buildInput(example: ShellExample | SecretExample): string {
  if (example.build !== undefined) {
    const { start, repeat, times, then } = example.build;
    return (start ?? '') + repeat.repeat(times) + then;
  }
  if (example.detector === 'shell') return example.command ?? '';
  return example.parts !== undefined ? example.parts.join('') : (example.text ?? '');
}

/** The platform a shell example is judged for. */
export function platformOf(example: ShellExample): NodeJS.Platform {
  return example.platform ?? (example.shell === 'powershell' ? 'win32' : 'linux');
}

/** The examples that run on `platform`, and those reported as skipped there. */
export function partitionByPlatform(
  refs: readonly ExampleRef[],
  platform: NodeJS.Platform,
): { run: ExampleRef[]; skip: ExampleRef[] } {
  const run: ExampleRef[] = [];
  const skip: ExampleRef[] = [];
  for (const ref of refs) {
    const only = ref.example.detector === 'hook' ? ref.example.only : undefined;
    (only === undefined || only.some((p) => p === platform) ? run : skip).push(ref);
  }
  return { run, skip };
}

/** How many records have at least one example, and how many have none. */
export function executableCounts(limits: readonly KnownLimit[]): { total: number; withExample: number; without: number } {
  const withExample = limits.filter((l) => l.examples.length > 0).length;
  return { total: limits.length, withExample, without: limits.length - withExample };
}

// --------------------------------------------------------------- comparing

const HOOK_RANK: Readonly<Record<HookDecision, number>> = { none: 0, warn: 1, ask: 2, deny: 3 };

/** What the record says the detector answers. */
export function recordedAnswer(example: LimitExample): Actual {
  if (example.detector === 'shell') {
    return { detector: 'shell', level: example.expect.level, ask: example.expect.ask === true };
  }
  if (example.detector === 'secret') return { detector: 'secret', hits: example.expect.hits };
  return { detector: 'hook', decision: example.expect.decision };
}

/**
 * How severe an answer is, within one detector. The shell guard: `ok`, `warn`,
 * `warn` with a question to the user, `block`. A hook call: nothing, a
 * warning, a question, a denial. The secret scan: its number of findings.
 */
function severity(answer: Actual): number {
  if (answer.detector === 'shell') {
    if (answer.level === 'block') return 3;
    if (answer.level === 'warn') return answer.ask ? 2 : 1;
    return 0;
  }
  if (answer.detector === 'secret') return answer.hits;
  return HOOK_RANK[answer.decision];
}

/** An answer in words: for a failure's message, and for the page. */
export function describeAnswer(answer: Actual): string {
  if (answer.detector === 'shell') return answer.level === 'warn' && answer.ask ? 'warn, and the user is asked' : answer.level;
  if (answer.detector === 'secret') return `${String(answer.hits)} ${answer.hits === 1 ? 'finding' : 'findings'}`;
  return answer.decision === 'none' ? 'none (no answer)' : answer.decision;
}

/** Compares what the detector answered with the record. */
export function judgeExample(ref: ExampleRef, actual: Actual): Judgement {
  const recorded = recordedAnswer(ref.example);
  if (actual.detector !== recorded.detector) {
    throw new Error(`${ref.limit.id}: a ${actual.detector} answer was given for a ${recorded.detector} example`);
  }
  const got = severity(actual);
  const want = severity(recorded);
  if (got === want) return { ok: true };
  const what = `${ref.limit.id}, example ${String(ref.index + 1)}`;
  if (got > want) {
    return {
      ok: false,
      direction: 'stricter',
      message:
        `${what}: the guard now answers "${describeAnswer(actual)}" where the record says "${describeAnswer(recorded)}". ` +
        `The limit looks closed: remove its record from ${KNOWN_LIMITS_SOURCE} (or correct this example) in the same commit, ` +
        'then run `npm run build`.',
    };
  }
  return {
    ok: false,
    direction: 'looser',
    message:
      `${what}: the guard answers "${describeAnswer(actual)}", less than the recorded "${describeAnswer(recorded)}". ` +
      'A guard does less than the list says: restore it — or, if the change is meant, correct the record in the same commit.',
  };
}

/** Runs `detect` for the example and judges its answer; a detector that throws fails the example. */
export function evaluateExample(ref: ExampleRef, detect: () => Actual): Judgement {
  let actual: Actual;
  try {
    actual = detect();
  } catch (error) {
    return {
      ok: false,
      direction: 'threw',
      message:
        `${ref.limit.id}, example ${String(ref.index + 1)}: the detector threw instead of answering — ` +
        `${error instanceof Error ? error.message : String(error)}. A known limit is an answer, never a crash.`,
    };
  }
  return judgeExample(ref, actual);
}
