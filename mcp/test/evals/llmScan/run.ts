/**
 * `npm run eval:llm-scan -- [options]` — the LLM-assisted scan's eval
 * harness (eval-plan.md; design.md, "[AI] 5. Estratégia de Avaliação").
 *
 * A tool someone runs deliberately, like `npm run ablate`: NOT a vitest test.
 * It spends model tokens, takes minutes, and its report is the product. Its
 * pure parts (sets, graders, blinding, injection, output parsing) ARE
 * unit-tested, under `test/unit/evals/`.
 *
 * What a run does:
 *   1. builds every set from its key (`sets.ts`) and a blind copy of every
 *      available corpus in a fresh temp directory (`corpora.ts`);
 *   2. opens plans with the feature's own planner (`buildPlan`) and renders
 *      each task's brief with its own renderer (`renderBrief`) — the same
 *      functions the tools use;
 *   3. runs each brief in a fresh Claude Code context (`driver.ts`), checks
 *      every answer with the feature's own validators
 *      (`validateVerifySubmission` / `validateHuntSubmission`), and retries a
 *      refused answer twice, as the tools do;
 *   4. grades in code (`grade.ts`) and prints one table per suite and per
 *      corpus against the plan's thresholds.
 *
 * Options:
 *   --suite golden-hunt|golden-verify|adversarial|regression|all   (default all; repeatable, or comma-separated)
 *   --mode subagent|brief-only        (default subagent; brief-only = the MCP-sampling approximation, no tools)
 *   --model <alias|id>                (default sonnet — the reference model of the evals)
 *   --repeat <n>                      (default 2: runs of each verification item; agreement needs 2)
 *   --concurrency <n>                 (default 4)
 *   --timeout <seconds>               (default 600, per model run)
 *   --retries <n>                     (default 2: further attempts after a refused answer)
 *   --prompt-version <v>              (default: renderBrief's current version)
 *   --no-surface                      (hunt without map_attack_surface: the planner's file-group fallback)
 *   --out <file.json>                 (the full report, every run included)
 *   --dry-run                         (build everything and print the briefs; run no model)
 *   --allow-incomplete                (exit 0 when nothing failed but some items could not be measured)
 *   --allow-commit-mismatch           (run on a corpus checked out at another commit than its key's)
 *   --claude <bin>                    (default claude)
 *
 *   --write-spec-sets <dir>           write golden.json, adversarial.json, regression.json and classes.json
 *                                     from the keys (no plan, no model) and exit
 *   --build-benchmark-sample --semgrep-json <f> --bandit-json <f> [--semgrep-config auto] [--pairs 20] [--seed 20261002]
 *                                     regenerate data/benchmark-python-sample.json and exit
 *
 * Corpora (environment; unset = N/A, set but missing = error):
 *   GUARDIAN_LLMSCAN_SPIKE  GUARDIAN_VAMPI_SRC  GUARDIAN_BENCHMARK_PY_SRC  GUARDIAN_JUICESHOP_SRC  GUARDIAN_DVWA_SRC
 *
 * Exit code: 0 every threshold met on the whole set; 1 a threshold missed,
 * or — unless --allow-incomplete — some item could not be measured (a pass
 * on part of a set is not evidence about the rest); 2 the run could not
 * execute (bad options, a corpus misconfigured, the feature throwing, no CLI).
 */

import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import { renderBrief, type RenderedBrief } from '../../../src/llmscan/briefs.js';
import { buildPlan, entryPointId, type PlannedTask } from '../../../src/llmscan/plan.js';
import { validateHuntSubmission, validateVerifySubmission, type SubmissionContext } from '../../../src/llmscan/submission.js';
import { LLM_SCAN_DEFAULTS, type HuntFinding, type HuntResult, type LlmScanTask, type PlanLimits, type VerifyVerdict } from '../../../src/llmscan/types.js';
import type { PluginContext } from '../../../src/context.js';
import { readProjectText } from '../../../src/platform/projectFs.js';
import { makeFinding } from '../../../src/runners/scannerParsers/index.js';
import { GuardianDatabase } from '../../../src/storage/db.js';
import { Storage } from '../../../src/storage/index.js';
import { runMigrations } from '../../../src/storage/migrations/runner.js';
import { ROUTE_PACK_EXTENSIONS } from '../../../src/surface/extract.js';
import { TOOLS } from '../../../src/tools/index.js';
import type { AttackSurfaceSnapshot, Finding, RouteRecord } from '../../../src/types.js';
import { rmDir } from '../../helpers/tempDir.js';
import {
  banditFindings,
  composition,
  labelFindings,
  parseExpectedResults,
  sampleBalanced,
  semgrepFindings,
  toSampleItems,
  type BenchmarkSampleFile,
} from './benchmarkSample.js';
import { CORPUS_IDS, Workspace, gitHead, resolveCorpora, spikeDir, type CorpusId, type CorpusState } from './corpora.js';
import { driveTask, pool, type AnswerCheck, type DriverMode, type DrivenTask, type OutOfBriefCall, type Usage } from './driver.js';
import {
  THRESHOLDS,
  agreement,
  atLeast,
  atMost,
  gradeAdversarial,
  gradeHunt,
  gradeRegression,
  gradeVerify,
  normPath,
  worst,
  type Check,
  type CheckStatus,
  type HuntKeyEntry,
  type Truth,
  type VerifyOutcome,
} from './grade.js';
import { inject, languageOfFile, type InjectionLanguage } from './inject.js';
import { BENCHMARK_SAMPLE_PATH, buildSets, specDocuments, unknownClasses, type EvalSets, type VerifyItem } from './sets.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '..', '..', '..', '..');

class UsageError extends Error {}

// ---------- options ----------

const SUITES = ['golden-hunt', 'golden-verify', 'adversarial', 'regression'] as const;
type SuiteName = (typeof SUITES)[number];

interface Options {
  suites: SuiteName[];
  mode: DriverMode;
  model: string;
  repeat: number;
  concurrency: number;
  timeoutMs: number;
  retries: number;
  promptVersion: string | undefined;
  surface: boolean;
  out: string | undefined;
  dryRun: boolean;
  allowIncomplete: boolean;
  allowCommitMismatch: boolean;
  bin: string;
  writeSpecSets: string | undefined;
  benchmark:
    | { semgrepJson: string; banditJson: string; semgrepConfig: string; pairs: number; seed: number }
    | undefined;
}

const VALUE_FLAGS = new Set([
  'suite', 'mode', 'model', 'repeat', 'concurrency', 'timeout', 'retries', 'prompt-version', 'out', 'claude',
  'write-spec-sets', 'semgrep-json', 'bandit-json', 'semgrep-config', 'pairs', 'seed',
]);
const BOOL_FLAGS = new Set(['dry-run', 'allow-incomplete', 'allow-commit-mismatch', 'no-surface', 'build-benchmark-sample', 'help']);

/** `--flag value` and `--flag=value` both; a value flag may repeat. */
function parseArgv(argv: readonly string[]): { values: Map<string, string[]>; bools: Set<string> } {
  const values = new Map<string, string[]>();
  const bools = new Set<string>();
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i] ?? '';
    if (!arg.startsWith('--')) throw new UsageError(`unexpected argument \`${arg}\``);
    const eq = arg.indexOf('=');
    const name = eq === -1 ? arg.slice(2) : arg.slice(2, eq);
    if (BOOL_FLAGS.has(name)) {
      if (eq !== -1) throw new UsageError(`--${name} takes no value`);
      bools.add(name);
      continue;
    }
    if (!VALUE_FLAGS.has(name)) throw new UsageError(`unknown option --${name}`);
    let value: string | undefined;
    if (eq !== -1) value = arg.slice(eq + 1);
    else {
      value = argv[i + 1];
      i += 1;
    }
    if (value === undefined || value === '') throw new UsageError(`--${name} needs a value`);
    values.set(name, [...(values.get(name) ?? []), value]);
  }
  return { values, bools };
}

function intOf(v: string | undefined, name: string, fallback: number, min: number): number {
  if (v === undefined) return fallback;
  const n = Number(v);
  if (!Number.isInteger(n) || n < min) throw new UsageError(`--${name} must be an integer >= ${min}`);
  return n;
}

function parse(argv: readonly string[]): Options {
  const { values, bools } = parseArgv(argv);
  if (bools.has('help')) throw new UsageError('see the header of mcp/test/evals/llmScan/run.ts');
  const one = (n: string): string | undefined => {
    const v = values.get(n);
    if (v !== undefined && v.length > 1) throw new UsageError(`--${n} given twice`);
    return v?.[0];
  };
  const suiteArgs = (values.get('suite') ?? ['all']).flatMap((s) => s.split(',')).map((s) => s.trim());
  const suites: SuiteName[] = [];
  for (const s of suiteArgs) {
    if (s === 'all') suites.push(...SUITES);
    else if ((SUITES as readonly string[]).includes(s)) suites.push(s as SuiteName);
    else throw new UsageError(`unknown suite \`${s}\`. Known: ${SUITES.join(', ')}, all`);
  }
  const mode = one('mode') ?? 'subagent';
  if (mode !== 'subagent' && mode !== 'brief-only') throw new UsageError('--mode is subagent or brief-only');
  const benchmark = bools.has('build-benchmark-sample')
    ? {
        semgrepJson: one('semgrep-json') ?? '',
        banditJson: one('bandit-json') ?? '',
        semgrepConfig: one('semgrep-config') ?? 'auto',
        pairs: intOf(one('pairs'), 'pairs', 20, 11),
        seed: intOf(one('seed'), 'seed', 20261002, 0),
      }
    : undefined;
  if (benchmark !== undefined && (benchmark.semgrepJson === '' || benchmark.banditJson === '')) {
    throw new UsageError('--build-benchmark-sample needs --semgrep-json and --bandit-json');
  }
  return {
    suites: [...new Set(suites)],
    mode,
    model: one('model') ?? 'sonnet',
    repeat: intOf(one('repeat'), 'repeat', 2, 1),
    concurrency: intOf(one('concurrency'), 'concurrency', 4, 1),
    timeoutMs: intOf(one('timeout'), 'timeout', 600, 10) * 1000,
    retries: intOf(one('retries'), 'retries', 2, 0),
    promptVersion: one('prompt-version'),
    surface: !bools.has('no-surface'),
    out: one('out'),
    dryRun: bools.has('dry-run'),
    allowIncomplete: bools.has('allow-incomplete'),
    allowCommitMismatch: bools.has('allow-commit-mismatch'),
    bin: one('claude') ?? 'claude',
    writeSpecSets: one('write-spec-sets'),
    benchmark,
  };
}

// ---------- the two key-only commands ----------

function writeSpecSets(dir: string): void {
  const spike = spikeDir();
  const sets = buildSets(spike);
  if (sets.missing.length > 0) {
    throw new Error(`cannot write the spec sets with key sources missing: ${sets.missing.join('; ')}`);
  }
  const unknown = unknownClasses(sets);
  if (unknown.length > 0) throw new Error(`classes outside the closed list: ${unknown.join(', ')}`);
  const target = resolve(dir);
  mkdirSync(target, { recursive: true });
  for (const [name, doc] of Object.entries(specDocuments(sets))) {
    writeFileSync(join(target, name), `${JSON.stringify(doc, null, 2)}\n`, 'utf8');
  }
  const byCorpus = (items: ReadonlyArray<{ corpus: string }>): string =>
    [...new Set(items.map((i) => i.corpus))].map((c) => `${c} ${items.filter((i) => i.corpus === c).length}`).join(', ');
  process.stdout.write(
    `wrote ${Object.keys(specDocuments(sets)).join(', ')} to ${target}\n` +
      `  G-H ${sets.hunt.length} (${byCorpus(sets.hunt)}; ${sets.hunt.filter((h) => h.kind === 'decoy').length} decoys)\n` +
      `  G-V ${sets.verify.length} (${byCorpus(sets.verify)}; ${sets.verify.filter((v) => v.truth === 'real').length} real, ` +
      `${sets.verify.filter((v) => v.truth === 'not_real').length} not_real)\n` +
      `  A-I ${sets.adversarial.length}   R ${sets.regression.length}\n`,
  );
}

function buildBenchmarkSample(b: NonNullable<Options['benchmark']>): void {
  const corpora = resolveCorpora(process.env, { allowCommitMismatch: true });
  const bp = corpora['benchmark-python'];
  if (!bp.available) throw new Error(`--build-benchmark-sample needs the corpus: ${bp.reason}`);
  const expected = parseExpectedResults(readFileSync(join(bp.dir, 'expectedresults-0.1.csv'), 'utf8'));
  const semgrepReport: unknown = JSON.parse(readFileSync(resolve(b.semgrepJson), 'utf8'));
  const banditReport: unknown = JSON.parse(readFileSync(resolve(b.banditJson), 'utf8'));
  const sg = semgrepFindings(semgrepReport);
  const bd = banditFindings(banditReport);
  const labelled = labelFindings([...sg, ...bd], expected);
  const sample = sampleBalanced(labelled, b.pairs, b.seed);
  if (sample.length < b.pairs * 2) throw new Error(`only ${sample.length / 2} balanced pairs available, ${b.pairs} asked`);
  const items = toSampleItems(sample);
  const comp = composition(items);
  if (Object.keys(comp).length < 4) throw new Error(`the sample spans ${Object.keys(comp).length} categories; at least 4 are needed`);
  const version = (r: unknown): string | null => {
    const v = typeof r === 'object' && r !== null ? (r as Record<string, unknown>)['version'] : undefined;
    return typeof v === 'string' ? v : null;
  };
  const banditVersion = (() => {
    const r = spawnSync('bandit', ['--version'], { encoding: 'utf8', windowsHide: true });
    return /bandit\s+([\d.]+)/i.exec(`${r.stdout ?? ''}`)?.[1] ?? null;
  })();
  const file: BenchmarkSampleFile = {
    note:
      'Verification-set sample (G-V) over OWASP BenchmarkPython: real scanner findings, labelled by the corpus\'s ' +
      'expectedresults-0.1.csv (kept only when the finding\'s weakness matches the test case\'s category). Finding ' +
      'metadata only; no code from the corpus (GPL-3.0). Messages are the scanner\'s first sentence. Regenerate with ' +
      '`npm run eval:llm-scan -- --build-benchmark-sample --semgrep-json=<f> --bandit-json=<f>`.',
    provenance: {
      corpus: 'OWASP-Benchmark/BenchmarkPython',
      commit: gitHead(bp.dir),
      expected_results: 'expectedresults-0.1.csv',
      semgrep: { version: version(semgrepReport), config: b.semgrepConfig, findings: sg.length },
      bandit: { version: banditVersion, findings: bd.length },
      labelled: labelled.length,
      seed: b.seed,
      pairs: b.pairs,
      generated_at: new Date().toISOString(),
    },
    composition: comp,
    items,
  };
  mkdirSync(dirname(BENCHMARK_SAMPLE_PATH), { recursive: true });
  writeFileSync(BENCHMARK_SAMPLE_PATH, `${JSON.stringify(file, null, 2)}\n`, 'utf8');
  process.stdout.write(
    `wrote ${relative(process.cwd(), BENCHMARK_SAMPLE_PATH)}: ${items.length} items from ${labelled.length} labelled ` +
      `(semgrep ${sg.length}, bandit ${bd.length})\n` +
      Object.entries(comp)
        .map(([c, n]) => `  ${c.padEnd(16)} real ${n.real}  not_real ${n.not_real}\n`)
        .join(''),
  );
}

// ---------- preparing: plans and briefs, through the feature's own functions ----------

const boundary = (): string => `DATA-${randomBytes(9).toString('hex').toUpperCase()}`;

function limitsFor(mode: DriverMode, tasks: number): PlanLimits {
  return {
    max_tasks: Math.max(LLM_SCAN_DEFAULTS.max_tasks, tasks),
    max_estimated_tokens: LLM_SCAN_DEFAULTS.max_estimated_tokens,
    per_task_overhead: mode === 'subagent' ? LLM_SCAN_DEFAULTS.per_task_overhead : LLM_SCAN_DEFAULTS.sampling_overhead,
  };
}

/** A planned task as `llm_scan_task` hands it out: leased, nothing recorded yet. */
function leased(planId: string, t: PlannedTask): LlmScanTask {
  return {
    plan_id: planId,
    task_id: t.task_id,
    kind: t.kind,
    target: t.target,
    status: 'leased',
    lease_token: 'eval-lease',
    lease_expires_at: null,
    attempts: 0,
    file_hashes: {},
    brief_chars: null,
    response_chars: null,
    independence: null,
    result: null,
    closed_reason: null,
    delivered_at: null,
    closed_at: null,
  };
}

function scannerFinding(f: { tool: string; rule_id: string; severity: Finding['severity']; message: string; file: string; line: number; title?: string }): Finding {
  return makeFinding({
    tool: f.tool,
    rule_id: f.rule_id,
    severity: f.severity,
    category: 'security',
    title: f.title ?? f.message,
    message: f.message,
    file_path: f.file,
    line_start: f.line,
  });
}

/** One verification to run: an item (G-V, A-I or hunt-derived), one run of it. */
interface VerifyJob {
  key: string;
  item: string;
  run: number;
  set: 'G-V' | 'A-I' | 'G-H/verify';
  corpus: CorpusId;
  root: string;
  truth: Truth;
  finding: Finding;
  task: LlmScanTask;
  brief: RenderedBrief;
}

interface HuntJob {
  key: string;
  corpus: CorpusId;
  root: string;
  task: LlmScanTask;
  brief: RenderedBrief;
}

/**
 * Plans one verify task per item over `root` — one plan for the group, as
 * `llm_scan_start` would — and renders each run's brief (a fresh boundary
 * per delivery, as in production).
 */
function planVerify(
  opts: Options,
  root: string,
  corpus: CorpusId,
  items: ReadonlyArray<{ id: string; set: VerifyJob['set']; truth: Truth; finding: Finding; runs: number }>,
): { jobs: VerifyJob[]; refused: Array<{ item: string; reason: string }> } {
  const plan = buildPlan({
    project_path: root,
    modes: ['verify'],
    findings: items.map((i) => i.finding),
    surface: null,
    code_files: [],
    limits: limitsFor(opts.mode, items.length),
  });
  const planId = `eval-${corpus}-${randomBytes(4).toString('hex')}`;
  const byFp = new Map(plan.tasks.filter((t) => t.kind === 'verify').map((t) => [t.target.fingerprint, t]));
  const jobs: VerifyJob[] = [];
  const refused: Array<{ item: string; reason: string }> = [];
  for (const item of items) {
    const t = byFp.get(item.finding.fingerprint);
    if (t === undefined) {
      const why = plan.not_eligible.find((n) => n.fingerprint === item.finding.fingerprint)?.reason ?? 'no verify task was planned for it';
      refused.push({ item: item.id, reason: why });
      continue;
    }
    for (let run = 0; run < item.runs; run += 1) {
      const task = leased(planId, t);
      const brief = renderBrief(task, {
        root,
        reader: readProjectText,
        boundary,
        finding: item.finding,
        ...(opts.promptVersion !== undefined ? { prompt_version: opts.promptVersion } : {}),
      });
      jobs.push({ key: `${item.id}#${run}`, item: item.id, run, set: item.set, corpus, root, truth: item.truth, finding: item.finding, task, brief });
    }
  }
  return { jobs, refused };
}

function codeFiles(root: string): string[] {
  const exts = new Set(ROUTE_PACK_EXTENSIONS);
  const out: string[] = [];
  const walk = (dir: string): void => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, e.name);
      if (e.isDirectory()) {
        if (e.name !== '.guardian' && e.name !== 'node_modules') walk(p);
      } else if (exts.has(`.${e.name.split('.').pop()?.toLowerCase() ?? ''}`)) {
        out.push(relative(root, p).split(sep).join('/'));
      }
    }
  };
  walk(root);
  return out.sort();
}

/**
 * The project's attack surface, mapped by the real `map_attack_surface` tool
 * into a throw-away in-memory database — what `llm_scan_start` reads in
 * production. The `.guardian/` reports it leaves in the copy are removed
 * before any model sees the copy.
 */
async function mapSurface(root: string): Promise<{ surface: { id: number; snapshot: AttackSurfaceSnapshot } | null; note: string }> {
  await import('../../../src/tools/mapAttackSurface.js');
  const tool = TOOLS.find((t) => t.name === 'map_attack_surface');
  if (tool === undefined) return { surface: null, note: 'map_attack_surface is not registered' };
  const db = new GuardianDatabase(':memory:');
  runMigrations(db);
  const storage = new Storage(db);
  const plugin: PluginContext = { storage, shell: null, scriptsDir: join(REPO, 'scripts'), progressNotifier: { send: () => {} } };
  try {
    const r = await tool.handler({ project_path: root, force: true }, plugin);
    const latest = storage.surface.getLatestForProject(root);
    if (latest === null) return { surface: null, note: r.ok ? 'map_attack_surface persisted no snapshot' : `map_attack_surface failed: ${r.error.message}` };
    return { surface: { id: latest.id, snapshot: latest.snapshot }, note: `${latest.snapshot.routes.length} routes` };
  } finally {
    storage.close();
    rmDir(join(root, '.guardian'));
  }
}

async function planHunt(opts: Options, root: string, corpus: CorpusId): Promise<{ jobs: HuntJob[]; notes: string[] }> {
  const notes: string[] = [];
  let surface: { id: number; snapshot: AttackSurfaceSnapshot } | null = null;
  if (opts.surface) {
    const mapped = await mapSurface(root);
    surface = mapped.surface;
    notes.push(`surface: ${mapped.note}`);
  } else notes.push('surface: not mapped (--no-surface)');
  const plan = buildPlan({
    project_path: root,
    modes: ['hunt'],
    findings: [],
    surface,
    code_files: codeFiles(root),
    limits: limitsFor(opts.mode, 1000),
  });
  notes.push(...plan.notes);
  if (plan.nothing_to_plan !== null) notes.push(`nothing to plan: ${plan.nothing_to_plan}`);
  for (const s of plan.set_aside) notes.push(`set aside: ${s.entry_point} (${s.reason})`);
  const routes: RouteRecord[] = surface?.snapshot.routes ?? [];
  const planId = `eval-hunt-${corpus}-${randomBytes(4).toString('hex')}`;
  const jobs: HuntJob[] = [];
  for (const t of plan.tasks) {
    if (t.kind !== 'hunt' && t.kind !== 'crosscut') continue;
    const wanted = new Set(t.target.entry_points ?? []);
    const entryPoints = routes.filter((r) => wanted.has(entryPointId(r, root)));
    const task = leased(planId, t);
    const brief = renderBrief(task, {
      root,
      reader: readProjectText,
      boundary,
      entry_points: entryPoints,
      scanner_findings: [],
      ...(opts.promptVersion !== undefined ? { prompt_version: opts.promptVersion } : {}),
    });
    jobs.push({ key: `hunt:${corpus}:${t.task_id}`, corpus, root, task, brief });
  }
  return { jobs, notes };
}

// ---------- the adversarial copies ----------

type ParseCheck = 'ok' | 'broken' | 'unchecked';

function pythonParses(text: string): boolean | null {
  for (const bin of ['python', 'python3']) {
    const r = spawnSync(bin, ['-c', 'import ast,sys; ast.parse(sys.stdin.buffer.read())'], { input: text, windowsHide: true });
    if (r.error !== undefined) continue;
    return r.status === 0;
  }
  return null;
}

function phpParses(text: string): boolean | null {
  const r = spawnSync('php', ['-l'], { input: text, windowsHide: true, encoding: 'utf8' });
  if (r.error !== undefined) return null;
  return r.status === 0;
}

function tsDiagnostics(text: string, file: string): number {
  const out = ts.transpileModule(text, {
    fileName: file,
    reportDiagnostics: true,
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext, allowJs: true },
  });
  return out.diagnostics?.length ?? 0;
}

/** Whether the injected text still parses wherever the original did. */
function parseCheck(lang: InjectionLanguage, file: string, original: string, injected: string): ParseCheck {
  if (lang === 'js') return tsDiagnostics(injected, file) <= tsDiagnostics(original, file) ? 'ok' : 'broken';
  const check = lang === 'python' ? pythonParses : phpParses;
  const before = check(original);
  if (before === null) return 'unchecked';
  if (!before) return 'ok';
  return check(injected) === true ? 'ok' : 'broken';
}

interface InjectedCopy {
  item: string;
  base: VerifyItem;
  root: string;
  line: number;
  kind: string;
  inserted_at: number;
  parse: ParseCheck;
}

function buildInjected(ws: Workspace, sets: EvalSets): { copies: InjectedCopy[]; problems: string[] } {
  const copies: InjectedCopy[] = [];
  const problems: string[] = [];
  const byId = new Map(sets.verify.map((v) => [v.id, v]));
  for (const a of sets.adversarial) {
    const base = byId.get(a.base);
    if (base === undefined) throw new Error(`A-I ${a.id}: unknown base ${a.base}`);
    const baseRoot = ws.base(base.corpus);
    if (baseRoot === undefined) continue;
    const lang = languageOfFile(base.file);
    if (lang === undefined) throw new Error(`A-I ${a.id}: no injection language for ${base.file}`);
    const original = readFileSync(join(baseRoot, ...base.file.split('/')), 'utf8');
    let done = inject(original, base.line, a.kind, a.push, lang);
    let parse = parseCheck(lang, base.file, original, done.text);
    if (parse === 'broken' && done.kind !== 'comment') {
      done = inject(original, base.line, 'comment', a.push, lang);
      parse = parseCheck(lang, base.file, original, done.text);
    }
    if (parse === 'broken') {
      problems.push(`${a.id}: the injected ${base.file} does not parse; item left out`);
      continue;
    }
    const root = ws.variant(base.corpus, [{ rel: base.file, text: done.text }]);
    if (root === undefined) continue;
    copies.push({ item: a.id, base, root, line: done.line, kind: done.kind, inserted_at: done.inserted_at, parse });
  }
  return { copies, problems };
}

// ---------- executing ----------

interface RunRecord {
  key: string;
  item: string;
  run: number;
  set: string;
  corpus: CorpusId;
  task_id: string;
  task_kind: string;
  brief_chars: number;
  brief_tokens: number;
  verdict: VerifyVerdict['verdict'] | null;
  verdict_detail: VerifyVerdict | null;
  hunt: { findings: number; rejected: number; entry_points_reviewed: number } | null;
  failure: 'error' | 'invalid' | null;
  errors: string[];
  attempts: number;
  usage: Usage;
  tool_calls: number;
  out_of_brief: OutOfBriefCall[];
  schema_refusals: number;
  duration_ms: number;
}

function submissionContext(root: string): SubmissionContext {
  return { root, reader: readProjectText };
}

function verifyCheck(root: string): (answer: unknown) => AnswerCheck<VerifyVerdict> {
  return (answer) => {
    const r = validateVerifySubmission(answer, submissionContext(root));
    if (r.ok) return { ok: true, value: r.value };
    return { ok: false, schema: true, errors: r.errors.map((e) => `${e.path}: ${e.problem}`) };
  };
}

function huntCheck(root: string, rejected: string[]): (answer: unknown) => AnswerCheck<HuntResult> {
  return (answer) => {
    const r = validateHuntSubmission(answer, submissionContext(root));
    if (r.ok) {
      rejected.push(...r.rejected.map((e) => `${e.path}: ${e.problem}`));
      return { ok: true, value: r.value };
    }
    return { ok: false, schema: true, errors: r.errors.map((e) => `${e.path}: ${e.problem}`) };
  };
}

function record<T>(job: { key: string; corpus: CorpusId; task: LlmScanTask; brief: RenderedBrief }, item: string, run: number, set: string, d: DrivenTask<T>): Omit<RunRecord, 'verdict' | 'verdict_detail' | 'hunt'> {
  return {
    key: job.key,
    item,
    run,
    set,
    corpus: job.corpus,
    task_id: job.task.task_id,
    task_kind: job.task.kind,
    brief_chars: job.brief.chars,
    brief_tokens: job.brief.estimated_tokens,
    failure: d.failure,
    errors: d.attempts.flatMap((a) => a.errors),
    attempts: d.attempts.length,
    usage: d.usage,
    tool_calls: d.tool_calls.length,
    out_of_brief: d.out_of_brief,
    schema_refusals: d.schema_refusals,
    duration_ms: d.duration_ms,
  };
}

function outcomeOf(r: RunRecord | undefined): VerifyOutcome {
  if (r === undefined) return { verdict: null, failure: 'not_run' };
  if (r.verdict !== null) return { verdict: r.verdict };
  return { verdict: null, failure: r.failure ?? 'error' };
}

// ---------- reporting ----------

const pct = (x: number | null): string => (x === null ? 'N/A' : `${(x * 100).toFixed(1)} %`);

/** A plain-text table; `align` gives each column `l` or `r` (default: first left, the rest right). */
function table(head: readonly string[], rows: ReadonlyArray<readonly string[]>, align?: string): string {
  const widths = head.map((h, i) => Math.max(h.length, ...rows.map((r) => (r[i] ?? '').length)));
  const left = (i: number): boolean => (align === undefined ? i === 0 : align[i] === 'l');
  const line = (r: readonly string[]): string =>
    r
      .map((c, i) => (left(i) ? c.padEnd(widths[i] ?? 0) : c.padStart(widths[i] ?? 0)))
      .join('  ')
      .trimEnd();
  return [line(head), ...rows.map(line)].map((l) => `  ${l}`).join('\n');
}

/** A count check (`count >= min`): incomplete rather than failed when unmeasured items could make up the difference. */
function countAtLeast(name: string, count: number, min: number, couldReach: boolean): Check {
  const threshold = `>= ${min}`;
  const value = String(count);
  if (count >= min) return { name, value, threshold, status: 'pass' };
  return couldReach
    ? { name, value, threshold, status: 'incomplete', detail: 'the rest of the set was not measured' }
    : { name, value, threshold, status: 'fail' };
}

function printChecks(checks: readonly Check[]): string {
  return checks
    .map((c) => `  ${c.status.toUpperCase().padEnd(10)} ${c.name.padEnd(40)} ${c.value.padStart(9)}  ${c.threshold}${c.detail !== undefined ? `  (${c.detail})` : ''}`)
    .join('\n');
}

interface SuiteReport {
  suite: SuiteName;
  status: CheckStatus;
  checks: Check[];
  data: Record<string, unknown>;
  text: string;
}

function corpusNote(corpora: Readonly<Record<CorpusId, CorpusState>>, id: CorpusId): string {
  const s = corpora[id];
  return s.available ? '' : `N/A — ${s.reason}`;
}

/** One line per corpus of `ids` that is N/A, saying why. */
function naLines(corpora: Readonly<Record<CorpusId, CorpusState>>, ids: readonly CorpusId[]): string {
  return ids.map((id) => (corpora[id].available ? '' : `\n  ${id}: ${corpusNote(corpora, id)}`)).join('');
}

function verifyRows(
  items: readonly VerifyItem[],
  outcomes: ReadonlyMap<string, VerifyOutcome[]>,
  corpora: Readonly<Record<CorpusId, CorpusState>>,
): string[][] {
  const rows: string[][] = [];
  for (const c of [...CORPUS_IDS, 'all' as const]) {
    const its = c === 'all' ? items : items.filter((i) => i.corpus === c);
    if (its.length === 0) continue;
    if (c !== 'all' && !corpora[c].available) {
      rows.push([c, String(its.length), '-', '-', '-', '-', '-', '-', 'N/A']);
      continue;
    }
    const g = gradeVerify(its.flatMap((i) => (outcomes.get(i.id) ?? []).map((o) => ({ truth: i.truth, outcome: o }))));
    rows.push([c, String(its.length), String(g.total), String(g.correct), String(g.wrong), String(g.undetermined), String(g.invalid), String(g.errors), pct(g.accuracy)]);
  }
  return rows;
}

// ---------- main ----------

async function evalRun(opts: Options): Promise<number> {
  const corpora = resolveCorpora(process.env, { allowCommitMismatch: opts.allowCommitMismatch });
  const sets = buildSets(spikeDir());
  const ws = new Workspace(corpora);
  const header =
    `llm-scan evals — suites ${opts.suites.join(', ')}; mode ${opts.mode}; model ${opts.model}; repeat ${opts.repeat}; ` +
    `prompt ${opts.promptVersion ?? '(renderBrief default)'}${opts.dryRun ? '; DRY RUN' : ''}\n` +
    CORPUS_IDS.map((id) => {
      const s = corpora[id];
      return `  ${id.padEnd(17)} ${s.available ? `${s.dir}${s.commit !== null ? ` @ ${s.commit.slice(0, 7)}` : ''}` : `N/A (${s.reason})`}`;
    }).join('\n') +
    (sets.missing.length > 0 ? `\n  missing key sources: ${sets.missing.join('; ')}` : '') +
    `\n  workspace ${ws.root}\n`;
  process.stdout.write(header);
  try {
    return await evalRunIn(opts, corpora, sets, ws);
  } finally {
    ws.dispose();
  }
}

async function evalRunIn(opts: Options, corpora: Readonly<Record<CorpusId, CorpusState>>, sets: EvalSets, ws: Workspace): Promise<number> {
  const wants = (s: SuiteName): boolean => opts.suites.includes(s);
  const verifyById = new Map(sets.verify.map((v) => [v.id, v]));

  // Which verification items run, and how many times.
  const runsOf = new Map<string, number>();
  const want = (id: string, runs: number): void => {
    runsOf.set(id, Math.max(runsOf.get(id) ?? 0, runs));
  };
  if (wants('golden-verify')) for (const v of sets.verify) want(v.id, opts.repeat);
  if (wants('adversarial')) for (const a of sets.adversarial) want(a.base, 1);
  if (wants('regression')) for (const r of sets.regression) if (r.kind === 'verify') want(r.ref, opts.repeat);
  const huntCorpora = new Set<CorpusId>();
  if (wants('golden-hunt')) for (const h of sets.hunt) huntCorpora.add(h.corpus);
  if (wants('regression')) {
    for (const r of sets.regression) {
      const h = sets.hunt.find((x) => x.id === r.ref);
      if (r.kind === 'hunt' && h !== undefined) huntCorpora.add(h.corpus);
    }
  }

  // ---- prepare: verification (G-V, then A-I), then hunts ----
  const verifyJobs: VerifyJob[] = [];
  const refused: Array<{ item: string; reason: string }> = [];
  const prepNotes: string[] = [];
  for (const corpus of CORPUS_IDS) {
    const items = [...runsOf.entries()].flatMap(([id, runs]) => {
      const v = verifyById.get(id);
      return v !== undefined && v.corpus === corpus ? [{ v, runs }] : [];
    });
    if (items.length === 0) continue;
    const root = ws.base(corpus);
    if (root === undefined) continue;
    const planned = planVerify(
      opts,
      root,
      corpus,
      items.map(({ v, runs }) => ({ id: v.id, set: 'G-V' as const, truth: v.truth, runs, finding: scannerFinding(v) })),
    );
    verifyJobs.push(...planned.jobs);
    refused.push(...planned.refused);
  }
  const injected: InjectedCopy[] = [];
  if (wants('adversarial')) {
    const built = buildInjected(ws, sets);
    injected.push(...built.copies);
    prepNotes.push(...built.problems);
    for (const c of built.copies) {
      const planned = planVerify(opts, c.root, c.base.corpus, [
        { id: c.item, set: 'A-I', truth: c.base.truth, runs: 1, finding: scannerFinding({ ...c.base, line: c.line }) },
      ]);
      verifyJobs.push(...planned.jobs);
      refused.push(...planned.refused);
    }
  }
  const huntJobs: HuntJob[] = [];
  const huntNotes = new Map<CorpusId, string[]>();
  if (opts.mode === 'brief-only' && huntCorpora.size > 0) {
    prepNotes.push('hunts are not run in brief-only mode: a hunt reads the project, and sampling only verifies');
    huntCorpora.clear();
  }
  for (const corpus of huntCorpora) {
    const root = ws.base(corpus);
    if (root === undefined) continue;
    const planned = await planHunt(opts, root, corpus);
    huntJobs.push(...planned.jobs);
    huntNotes.set(corpus, planned.notes);
  }

  if (opts.dryRun) {
    const shown = [
      ...verifyJobs.map((j) => ({ label: `${j.item} run ${j.run + 1} (${j.set}, ${j.corpus})`, j })),
      ...huntJobs.map((j) => ({ label: `${j.key} (${j.corpus})`, j })),
    ];
    for (const { label, j } of shown) {
      process.stdout.write(`\n===== ${label} — ${j.task.kind} ${j.task.task_id}, ${j.brief.chars} chars, ~${j.brief.estimated_tokens} tokens, cwd ${j.root}\n${j.brief.text}\n`);
    }
    process.stdout.write(
      `\ndry run: ${verifyJobs.length} verification runs and ${huntJobs.length} hunt tasks prepared; no model was run.\n` +
        (refused.length > 0 ? `planner refused: ${refused.map((r) => `${r.item} (${r.reason})`).join(', ')}\n` : '') +
        prepNotes.map((n) => `note: ${n}\n`).join(''),
    );
    return 0;
  }

  // ---- execute ----
  const driver = { mode: opts.mode, model: opts.model, bin: opts.bin, timeoutMs: opts.timeoutMs, retries: opts.retries };
  const records: RunRecord[] = [];
  let done = 0;
  const total = verifyJobs.length + huntJobs.length;
  const progress = (what: string): void => {
    done += 1;
    process.stderr.write(`[${done}/${total}] ${what}\n`);
  };
  const huntResults = new Map<string, { job: HuntJob; result: HuntResult | null; rejected: string[] }>();
  type Work = { kind: 'verify'; job: VerifyJob } | { kind: 'hunt'; job: HuntJob };
  const work: Work[] = [...huntJobs.map((job) => ({ kind: 'hunt' as const, job })), ...verifyJobs.map((job) => ({ kind: 'verify' as const, job }))];
  await pool(work, opts.concurrency, async (w) => {
    if (w.kind === 'verify') {
      const d = await driveTask(w.job.brief.text, w.job.root, driver, verifyCheck(w.job.root));
      records.push({ ...record(w.job, w.job.item, w.job.run, w.job.set, d), verdict: d.value?.verdict ?? null, verdict_detail: d.value, hunt: null });
      progress(`${w.job.item} run ${w.job.run + 1}: ${d.value?.verdict ?? d.failure ?? '?'}`);
    } else {
      const rejected: string[] = [];
      const d = await driveTask(w.job.brief.text, w.job.root, driver, huntCheck(w.job.root, rejected));
      huntResults.set(w.job.key, { job: w.job, result: d.value, rejected });
      records.push({
        ...record(w.job, w.job.key, 0, 'G-H', d),
        verdict: null,
        verdict_detail: null,
        hunt: d.value === null ? null : { findings: d.value.findings.length, rejected: rejected.length, entry_points_reviewed: d.value.entry_points_reviewed.length },
      });
      progress(`${w.job.key}: ${d.value === null ? d.failure ?? '?' : `${d.value.findings.length} findings`}`);
    }
  });

  // ---- hunt findings → key matches → their verification (G-H/verify) ----
  const huntFindings = new Map<CorpusId, HuntFinding[]>();
  const huntFailed = new Map<CorpusId, number>();
  for (const { job, result } of huntResults.values()) {
    if (result === null) {
      huntFailed.set(job.corpus, (huntFailed.get(job.corpus) ?? 0) + 1);
      continue;
    }
    const list = huntFindings.get(job.corpus) ?? [];
    for (const f of result.findings) {
      // EC-4: the same finding from two tasks is one finding.
      if (!list.some((g) => normPath(g.file) === normPath(f.file) && g.line === f.line && g.class === f.class)) list.push(f);
    }
    huntFindings.set(job.corpus, list);
  }
  const keyEntries = (corpus: CorpusId): HuntKeyEntry[] =>
    sets.hunt.filter((h) => h.corpus === corpus).map((h) => ({ id: h.key_id, kind: h.kind, class: h.class, locations: h.locations }));
  const derivedJobs: VerifyJob[] = [];
  const derivedOf = new Map<string, { corpus: CorpusId; index: number; key: string; truth: Truth }>();
  for (const [corpus, findings] of huntFindings) {
    const root = ws.base(corpus);
    if (root === undefined) continue;
    const pre = gradeHunt(keyEntries(corpus), findings);
    const items = findings.flatMap((f, index) => {
      const keyId = pre.credited[index];
      if (keyId === null || keyId === undefined) return [];
      const entry = keyEntries(corpus).find((k) => k.id === keyId);
      const id = `GV-H-${corpus}-${String(index + 1).padStart(2, '0')}`;
      const truth: Truth = entry?.kind === 'decoy' ? 'not_real' : 'real';
      derivedOf.set(id, { corpus, index, key: keyId, truth });
      return [
        {
          id,
          set: 'G-H/verify' as const,
          truth,
          runs: 1,
          finding: scannerFinding({
            tool: 'llm-hunt',
            rule_id: f.class,
            severity: 'high',
            title: f.title,
            message: `${f.title}. Attacker: ${f.attacker}. Evidence: ${f.evidence}`,
            file: f.file,
            line: f.line,
          }),
        },
      ];
    });
    if (items.length === 0) continue;
    const planned = planVerify(opts, root, corpus, items);
    derivedJobs.push(...planned.jobs);
    refused.push(...planned.refused);
  }
  if (derivedJobs.length > 0) {
    process.stderr.write(`verifying ${derivedJobs.length} hunt findings that landed on a key line or a decoy\n`);
    await pool(derivedJobs, opts.concurrency, async (job) => {
      const d = await driveTask(job.brief.text, job.root, driver, verifyCheck(job.root));
      records.push({ ...record(job, job.item, job.run, job.set, d), verdict: d.value?.verdict ?? null, verdict_detail: d.value, hunt: null });
      process.stderr.write(`  ${job.item}: ${d.value?.verdict ?? d.failure ?? '?'}\n`);
    });
  }

  // ---- grade ----
  const outcomes = new Map<string, VerifyOutcome[]>();
  for (const r of [...records].sort((a, b) => a.run - b.run)) {
    if (r.set === 'G-H') continue;
    outcomes.set(r.item, [...(outcomes.get(r.item) ?? []), outcomeOf(r)]);
  }
  for (const r of refused) outcomes.set(r.item, [{ verdict: null, failure: 'error' }]);
  const reports: SuiteReport[] = [];

  const huntGrades = new Map<CorpusId, ReturnType<typeof gradeHunt>>();
  for (const corpus of huntCorpora) {
    const findings = huntFindings.get(corpus) ?? [];
    const verdictOf = (index: number): VerifyVerdict['verdict'] | null => {
      for (const [id, d] of derivedOf) {
        if (d.corpus === corpus && d.index === index) return outcomes.get(id)?.[0]?.verdict ?? null;
      }
      return null;
    };
    huntGrades.set(corpus, gradeHunt(keyEntries(corpus), findings, verdictOf));
  }
  /** Why a corpus's hunt says nothing (no task, or every task failed), or null when it was measured. */
  const huntUnmeasured = (corpus: CorpusId): string | null => {
    const tasks = huntJobs.filter((j) => j.corpus === corpus).length;
    if (!huntGrades.has(corpus)) return corpusNote(corpora, corpus) || 'not run';
    if (tasks === 0) return 'the planner made no hunt task';
    if ((huntFailed.get(corpus) ?? 0) === tasks) return 'every hunt task failed';
    return null;
  };

  if (wants('golden-hunt')) {
    const corpusIds = [...new Set(sets.hunt.map((h) => h.corpus))];
    const rows: string[][] = [];
    let vulns = 0;
    let found = 0;
    let confirmed = 0;
    let unverified = 0;
    let unmeasured = 0;
    for (const c of corpusIds) {
      const keys = sets.hunt.filter((h) => h.corpus === c);
      const g = huntGrades.get(c);
      const nVulns = keys.filter((k) => k.kind === 'vulnerability').length;
      const why = huntUnmeasured(c);
      if (g === undefined || why !== null) {
        unmeasured += nVulns;
        rows.push([c, String(nVulns), '-', 'N/A', String(keys.length - nVulns), '-', '-', '-', why ?? 'not run']);
        continue;
      }
      vulns += g.vulnerabilities;
      found += g.found.length;
      confirmed += g.decoys_confirmed.length;
      unverified += g.decoys_unverified.length;
      rows.push([
        c,
        String(g.vulnerabilities),
        String(g.found.length),
        pct(g.recall),
        String(g.decoys),
        String(g.decoys_flagged.length),
        String(g.decoys_confirmed.length),
        String(g.extras),
        `${huntJobs.filter((j) => j.corpus === c).length} (${huntFailed.get(c) ?? 0} failed)`,
      ]);
    }
    const recall = vulns === 0 ? null : found / vulns;
    rows.push(['all', String(vulns), String(found), pct(recall), '', '', String(confirmed), '', '']);
    const dg = gradeVerify(
      [...derivedOf].map(([id, d]) => ({ truth: d.truth, outcome: outcomes.get(id)?.[0] ?? { verdict: null, failure: 'not_run' as const } })),
    );
    const checks = [
      atLeast('hunt: vulnerabilities found', recall, THRESHOLDS.hunt_recall, unmeasured, 'key vulnerabilities not measured'),
      atMost('hunt: decoys confirmed real', vulns === 0 ? null : confirmed, THRESHOLDS.hunt_decoys_confirmed_max, unmeasured + unverified, 'not measured (corpus N/A, or a flagged decoy left unverified)'),
    ];
    const missedText = [...huntGrades].map(([c, g]) => `${c}: missed ${g.missed.join(', ') || '-'}; decoys flagged ${g.decoys_flagged.join(', ') || '-'}`).join('\n  ');
    const text =
      `\n== golden-hunt (G-H) ==\n` +
      table(['corpus', 'vulns', 'found', 'recall', 'decoys', 'flagged', 'confirmed', 'extras', 'tasks'], rows) +
      naLines(corpora, corpusIds) +
      `\n  ${missedText}\n` +
      [...huntNotes].map(([c, n]) => `  ${c}: ${n.join('; ')}`).join('\n') +
      `\n  hunt findings verified (G-V from G-H, reported apart): ${dg.correct}/${dg.total} right (${pct(dg.accuracy)})\n` +
      printChecks(checks);
    reports.push({ suite: 'golden-hunt', status: worst(checks.map((c) => c.status)), checks, data: { grades: Object.fromEntries(huntGrades), hunt_derived_verification: dg, notes: Object.fromEntries(huntNotes) }, text });
  }

  if (wants('golden-verify')) {
    const g = gradeVerify(sets.verify.flatMap((i) => (outcomes.get(i.id) ?? [{ verdict: null, failure: 'not_run' as const }]).map((o) => ({ truth: i.truth, outcome: o }))));
    const notRun = sets.verify.filter((i) => outcomes.get(i.id) === undefined);
    const pairs = sets.verify.flatMap((i) => {
      const os = outcomes.get(i.id) ?? [];
      const a = os[0];
      const b = os[1];
      return a !== undefined && b !== undefined ? [{ id: i.id, a, b }] : [];
    });
    const agr = agreement(pairs);
    const measured = sets.verify.filter((i) => outcomes.get(i.id) !== undefined);
    const languages = new Set(measured.map((i) => i.language));
    const checks = [
      atLeast('verification: verdicts right', g.accuracy, THRESHOLDS.verify_accuracy, notRun.length, 'items not measured (corpus N/A)'),
      atLeast(
        'verification: agreement of two runs',
        agr.rate,
        THRESHOLDS.verify_agreement,
        opts.repeat < 2 ? measured.length : notRun.length,
        opts.repeat < 2 ? 'items with one run only (use --repeat 2)' : 'items not measured (corpus N/A)',
      ),
      countAtLeast('verification: items measured (SC-002)', measured.length, 40, notRun.length > 0),
      countAtLeast(
        'verification: languages measured (SC-002)',
        languages.size,
        3,
        notRun.length > 0 && new Set(sets.verify.map((i) => i.language)).size >= 3,
      ),
    ];
    const text =
      `\n== golden-verify (G-V) — ${opts.repeat} run(s) per item ==\n` +
      table(['corpus', 'items', 'runs', 'right', 'wrong', 'undet.', 'invalid', 'error', 'accuracy'], verifyRows(sets.verify, outcomes, corpora)) +
      naLines(corpora, [...new Set(sets.verify.map((i) => i.corpus))]) +
      `\n  undetermined ${g.undetermined} (counted wrong); real ${g.by_truth.real.correct}/${g.by_truth.real.total}, not_real ${g.by_truth.not_real.correct}/${g.by_truth.not_real.total}` +
      `\n  agreement ${agr.same}/${agr.items} (${pct(agr.rate)})${agr.differing.length > 0 ? `; differing: ${agr.differing.join(', ')}` : ''}` +
      `\n  measured ${measured.length} items in ${[...languages].sort().join(', ') || 'no language'}\n` +
      printChecks(checks);
    reports.push({ suite: 'golden-verify', status: worst(checks.map((c) => c.status)), checks, data: { grade: g, agreement: agr }, text });
  }

  if (wants('adversarial')) {
    const recordsOf = (id: string): RunRecord[] => records.filter((r) => r.item === id);
    const entries = sets.adversarial.map((a) => {
      const inj = recordsOf(a.id)[0];
      return {
        id: a.id,
        original: outcomes.get(a.base)?.[0] ?? { verdict: null, failure: 'not_run' as const },
        injected: outcomeOf(inj),
        out_of_brief_calls: inj?.out_of_brief.length ?? 0,
        schema_refusals: inj?.schema_refusals ?? 0,
      };
    });
    const g = gradeAdversarial(entries);
    const incomparable = g.incomparable.length;
    const checks = [
      atLeast('injection: verdicts unchanged', g.rate, THRESHOLDS.injection_unchanged, incomparable, 'items not compared (corpus N/A or no original verdict)'),
      atMost('injection: tool calls outside the brief', g.compared === 0 ? null : g.out_of_brief_calls, THRESHOLDS.injection_out_of_brief_max, incomparable, 'items not compared'),
      atMost('injection: submissions refused by the schema', g.compared === 0 ? null : g.schema_refusals, THRESHOLDS.injection_schema_refusals_max, incomparable, 'items not compared'),
    ];
    const rows = sets.adversarial.map((a) => {
      const e = entries.find((x) => x.id === a.id);
      const c = injected.find((x) => x.item === a.id);
      const show = (o: VerifyOutcome | undefined): string => (o === undefined ? '-' : o.verdict ?? o.failure);
      return [a.id, a.base, c?.kind ?? a.kind, a.push, show(e?.original), show(e?.injected), String(e?.out_of_brief_calls ?? 0), c === undefined ? 'N/A' : c.parse];
    });
    const text =
      `\n== adversarial (A-I) ==\n` +
      table(['item', 'base', 'kind', 'pushes', 'original', 'injected', 'off-brief', 'parse'], rows, 'llllllrl') +
      `\n  compared ${g.compared}, unchanged ${g.unchanged} (${pct(g.rate)}); changed: ${g.changed.join(', ') || '-'}; ` +
      `not compared: ${g.incomparable.join(', ') || '-'}\n` +
      printChecks(checks);
    reports.push({ suite: 'adversarial', status: worst(checks.map((c) => c.status)), checks, data: { grade: g, copies: injected.map(({ base: _b, ...c }) => c) }, text });
  }

  if (wants('regression')) {
    const entries = sets.regression.map((r) => {
      if (r.kind === 'hunt') {
        const h = sets.hunt.find((x) => x.id === r.ref);
        const g = h === undefined ? undefined : huntGrades.get(h.corpus);
        if (h === undefined || g === undefined || huntUnmeasured(h.corpus) !== null) return { id: r.id, kept: null };
        return { id: r.id, kept: g.found.includes(h.key_id) };
      }
      const os = (outcomes.get(r.ref) ?? []).filter((o) => !(o.verdict === null && o.failure === 'not_run'));
      return { id: r.id, kept: os.length === 0 ? null : os.every((o) => o.verdict === r.expect) };
    });
    const g = gradeRegression(entries);
    const checks = [atLeast('regression: cases kept', g.rate, THRESHOLDS.regression_kept, g.unmeasured.length, 'cases not measured')];
    const rows = sets.regression.map((r) => {
      const e = entries.find((x) => x.id === r.id);
      return [r.id, r.ref, r.expect, e?.kept === null || e === undefined ? 'N/A' : e.kept ? 'kept' : 'BROKEN', r.why];
    });
    const text = `\n== regression (R) ==\n${table(['case', 'item', 'expect', 'result', 'why'], rows, 'lllll')}\n${printChecks(checks)}`;
    reports.push({ suite: 'regression', status: worst(checks.map((c) => c.status)), checks, data: { grade: g }, text });
  }

  // ---- cost ----
  const verifyRecords = records.filter((r) => r.task_kind === 'verify');
  const huntRecords = records.filter((r) => r.task_kind !== 'verify');
  const mean = (xs: readonly number[]): string => (xs.length === 0 ? 'N/A' : String(Math.round(xs.reduce((s, x) => s + x, 0) / xs.length)));
  const sizes = verifyJobs.map((j) => j.brief.estimated_tokens).sort((a, b) => a - b);
  const p95 = sizes.length === 0 ? null : sizes[Math.ceil(0.95 * sizes.length) - 1] ?? null;
  const cost =
    `\n== cost ==\n` +
    `  verify: ${verifyRecords.length} runs, mean ${mean(verifyRecords.map((r) => r.usage.total))} tokens, ` +
    `mean ${mean(verifyRecords.map((r) => r.tool_calls))} tool calls; brief P95 ${p95 === null ? 'N/A' : Math.round(p95)} estimated tokens\n` +
    `  hunt:   ${huntRecords.length} runs, mean ${mean(huntRecords.map((r) => r.usage.total))} tokens, mean ${mean(huntRecords.map((r) => r.tool_calls))} tool calls\n` +
    `  total:  ${records.reduce((s, r) => s + r.usage.total, 0)} tokens\n`;

  const overall = worst(reports.map((r) => r.status));
  process.stdout.write(
    `${reports.map((r) => r.text).join('\n')}\n${cost}` +
      (refused.length > 0 ? `  planner refused: ${refused.map((r) => `${r.item} (${r.reason})`).join(', ')}\n` : '') +
      prepNotes.map((n) => `  note: ${n}\n`).join('') +
      `\nOVERALL: ${overall.toUpperCase()}${overall === 'incomplete' && opts.allowIncomplete ? ' (allowed by --allow-incomplete)' : ''}\n`,
  );
  if (opts.out !== undefined) {
    const out = resolve(opts.out);
    mkdirSync(dirname(out), { recursive: true });
    writeFileSync(
      out,
      `${JSON.stringify(
        {
          harness: 'mcp/test/evals/llmScan',
          finished_at: new Date().toISOString(),
          options: { ...opts, benchmark: undefined },
          corpora,
          overall,
          suites: reports.map(({ text: _t, ...r }) => r),
          planner_refused: refused,
          notes: prepNotes,
          runs: records,
        },
        null,
        2,
      )}\n`,
      'utf8',
    );
    process.stdout.write(`report written to ${out}\n`);
  }
  if (overall === 'fail') return 1;
  if (overall === 'incomplete') return opts.allowIncomplete ? 0 : 1;
  return 0;
}

async function main(argv: readonly string[]): Promise<number> {
  let opts: Options;
  try {
    opts = parse(argv);
  } catch (e) {
    if (e instanceof UsageError) {
      process.stderr.write(`usage error: ${e.message}\n`);
      return 2;
    }
    throw e;
  }
  if (opts.benchmark !== undefined) {
    buildBenchmarkSample(opts.benchmark);
    return 0;
  }
  if (opts.writeSpecSets !== undefined) {
    writeSpecSets(opts.writeSpecSets);
    return 0;
  }
  if (!opts.dryRun) {
    const probe = spawnSync(opts.bin, ['--version'], { encoding: 'utf8', windowsHide: true });
    if (probe.error !== undefined || probe.status !== 0) {
      process.stderr.write(`error: the Claude Code CLI (\`${opts.bin}\`) did not run: ${probe.error?.message ?? probe.stderr}\n`);
      return 2;
    }
  }
  if (!existsSync(BENCHMARK_SAMPLE_PATH)) throw new Error(`missing ${BENCHMARK_SAMPLE_PATH}: run --build-benchmark-sample first`);
  return evalRun(opts);
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (e: unknown) => {
    process.stderr.write(`error: ${e instanceof Error ? e.message : String(e)}\n`);
    process.exitCode = 2;
  },
);
