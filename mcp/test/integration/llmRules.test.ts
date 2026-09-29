/**
 * Runs `configs/semgrep/llm.yml` — the LLM-application pack `scan_sast`
 * appends to every run (`runners/semgrepConfigs.ts`) — against the fixture
 * pairs in `mcp/test/fixtures/llm/{hits,misses}/` and asserts, per file, the
 * EXACT count of every rule, the exact LINES that fire (each `# BUG:` /
 * `// BUG:` marker), the number of files Semgrep actually scanned, and that
 * the misses fire nothing.
 *
 * The hits are written so that every source and sink branch of the taint
 * rules is reached by exactly one case of its own: a branch the ablation
 * harness removes must lose a line here, or it reads DEAD. The misses hold
 * the false-positive classes measured on the application corpus (see the
 * pack header), the near-miss each regex exists to exclude, and the fixes the
 * messages prescribe — a pack that fires on its own prescription tells the
 * user to make a change it then complains about.
 *
 * The in-repo fixture path contains a `test/` segment, which Semgrep's
 * default ignore list skips wholesale — which is why fixtures are copied to a
 * temp dir first, and why the scanned count is asserted every time.
 *
 * SKIPPED, not silently passed, when Semgrep is absent;
 * `GUARDIAN_REQUIRE_SEMGREP=1` turns that absence into a hard failure.
 */

import { afterAll, describe, expect, it, vi } from 'vitest';

// Real, synchronous `semgrep` calls are not bounded by vitest's default
// testTimeout; see baseRules.test.ts.
vi.setConfig({ testTimeout: 180_000 });
import { cpSync, existsSync, readdirSync, readFileSync } from 'node:fs';
import { basename, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';
import { semgrepParserFor } from '../../src/runners/scannerParsers/semgrep.js';
import { semgrepAvailable, semgrepStdout } from '../helpers/semgrep.js';
import { cleanupTempDirs, makeTempDir } from '../helpers/tempDir.js';

afterAll(cleanupTempDirs);

const REPO_ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const RULES = resolve(REPO_ROOT, 'configs', 'semgrep', 'llm.yml');
const FIXTURES = resolve(REPO_ROOT, 'mcp', 'test', 'fixtures', 'llm');
const REQUIRE_SEMGREP = process.env['GUARDIAN_REQUIRE_SEMGREP'] === '1';

const AVAILABLE = semgrepAvailable();

interface SemgrepResult {
  check_id: string;
  path: string;
  start: { line: number };
  extra?: { severity?: string };
}

interface SemgrepRun {
  readonly rows: SemgrepResult[];
  readonly scanned: number;
  readonly errors: number;
  readonly raw: unknown;
  /** The temp copy that was scanned. */
  readonly work: string;
}

function run(dir: string, config = RULES): SemgrepRun {
  const work = makeTempDir('guardian-llm-');
  cpSync(dir, work, { recursive: true });
  const out = semgrepStdout([`--config=${config}`, '--json', '--quiet', '--no-git-ignore', '--metrics=off', work], { cwd: work });
  const parsed = JSON.parse(out) as { results?: unknown[]; errors?: unknown[]; paths?: { scanned?: unknown[] } };
  return {
    rows: (parsed.results ?? []) as SemgrepResult[],
    scanned: (parsed.paths?.scanned ?? []).length,
    errors: (parsed.errors ?? []).length,
    raw: parsed,
    work,
  };
}

// One scan of each corpus per file run: the taint rules make a scan cost
// seconds, and every assertion below reads the same result.
let hitsRun: SemgrepRun | undefined;
let missesRun: SemgrepRun | undefined;
const hits = (): SemgrepRun => (hitsRun ??= run(resolve(FIXTURES, 'hits')));
const misses = (): SemgrepRun => (missesRun ??= run(resolve(FIXTURES, 'misses')));

/** Last dot-separated segment — Semgrep prefixes the config path onto ids. */
function ruleOf(row: SemgrepResult): string {
  return row.check_id.split('.').pop() ?? row.check_id;
}

function countsByFile(result: SemgrepRun): Record<string, Record<string, number>> {
  const out: Record<string, Record<string, number>> = {};
  for (const row of result.rows) {
    const file = basename(row.path);
    const byRule = out[file] ?? {};
    byRule[ruleOf(row)] = (byRule[ruleOf(row)] ?? 0) + 1;
    out[file] = byRule;
  }
  return out;
}

function filesIn(dir: string): string[] {
  return readdirSync(dir).sort();
}

const INTERPRETER_PY = 'llm-output-to-interpreter-py';
const DISPATCH_PY = 'llm-tool-name-dispatch-py';
const TRUST_REMOTE = 'llm-trust-remote-code';
const TORCH_UNSAFE = 'llm-torch-load-weights-only-false';
const TORCH_DEFAULT = 'llm-torch-load-no-weights-only';
const NO_MAX_PY = 'llm-openai-no-max-tokens-py';
const INTERPRETER_JS = 'llm-output-to-interpreter-js';
const SYSTEM_PROMPT_JS = 'llm-request-in-system-prompt-js';
const NO_MAX_JS = 'llm-openai-no-max-tokens-js';

/**
 * The exact count of every rule in every `hits/` fixture. A fixture on disk
 * with no entry here fails Step 0 rather than being silently unmeasured.
 */
const EXPECTED_HITS: Readonly<Record<string, Readonly<Record<string, number>>>> = {
  // Twenty-five sources into exec/eval (one each), twenty sinks (one each).
  // The review of the pack added the structured-output, Anthropic-stream and
  // Hugging Face sources, a LangChain model held in `model`, and replaced
  // "any subprocess argument" by the positions that run something: shell=True,
  // argv[0], `sh -c`/`python -c`, shlex.split, getoutput, create_subprocess_exec.
  // Review round 2 (I-B): the model's text anywhere in the argv of an
  // interpreter, shell or wrapper, or of any program with a shell; os.exec*,
  // os.spawn*, create_subprocess_exec of bash.
  'output_to_interpreter.py': { [INTERPRETER_PY]: 74 },
  // Four spellings of a model-chosen name, five lookups; and (review, I-1)
  // seven guards that are not allowlists: a warning, `pass`, dir(), a string,
  // a class __dict__, vars(), and the ELSE arm of a real one.
  // Review round 2 (I-A): fourteen more — a membership test on something
  // else, the first name checked and the second dispatched, a rebinding, an
  // exit that is conditional or belongs to a nested def or loop, two elif
  // shapes, and three containers that are every attribute or a string.
  'tool_dispatch.py': { [DISPATCH_PY]: 26 },
  // Two kwargs carriers of trust_remote_code (review); torch.load split by
  // what the call says about weights_only (review, I-3).
  'model_supply_chain.py': { [TRUST_REMOTE]: 7, [TORCH_UNSAFE]: 1, [TORCH_DEFAULT]: 2 },
  // max_tokens=None and the two .parse() calls (review).
  'no_max_tokens.py': { [NO_MAX_PY]: 6 },
  // Fifteen sources into eval (one each), thirteen sinks (one each).
  // Review round 2 (I-B): eleven argv shapes of interpreters, wrappers and shells.
  'outputToInterpreter.ts': { [INTERPRETER_JS]: 48 },
  // Four request sources; four sink shapes — the message object (one pattern
  // covers both key orders: Semgrep's object pattern ignores order, which the
  // ablation measured), a top-level `system`, `instructions`, a SystemMessage —
  // and both role names. Review of the pack: route parameters, a header,
  // nextUrl.searchParams, new URL(request.url), the LangChain.js
  // ['system', ...] tuple, and two calls whose NAME holds "search" without
  // being a retrieval (I-4).
  'systemPrompt.ts': { [SYSTEM_PROMPT_JS]: 14 },
  // max_tokens: undefined and the two .parse() calls (review).
  'noMaxTokens.ts': { [NO_MAX_JS]: 6 },
};

/** The designed tier of every rule — see the pack's header for the criterion. */
const EXPECTED_SEVERITY: Readonly<Record<string, string>> = {
  [INTERPRETER_PY]: 'WARNING',
  [DISPATCH_PY]: 'WARNING',
  [TRUST_REMOTE]: 'WARNING',
  [TORCH_UNSAFE]: 'WARNING',
  [TORCH_DEFAULT]: 'LOW',
  [NO_MAX_PY]: 'LOW',
  [INTERPRETER_JS]: 'WARNING',
  [SYSTEM_PROMPT_JS]: 'LOW',
  [NO_MAX_JS]: 'LOW',
};

/**
 * The OWASP Top 10 for LLM Applications 2025, verbatim from
 * <https://genai.owasp.org/llm-top-10/> (retrieved 2026-09-28). Every rule
 * names exactly one of these in `metadata.owasp-llm` — NOT in `owasp`, which
 * this repo's parsers read as the web Top 10.
 */
const OWASP_LLM_2025 = new Set([
  'LLM01:2025 Prompt Injection',
  'LLM02:2025 Sensitive Information Disclosure',
  'LLM03:2025 Supply Chain',
  'LLM04:2025 Data and Model Poisoning',
  'LLM05:2025 Improper Output Handling',
  'LLM06:2025 Excessive Agency',
  'LLM07:2025 System Prompt Leakage',
  'LLM08:2025 Vector and Embedding Weaknesses',
  'LLM09:2025 Misinformation',
  'LLM10:2025 Unbounded Consumption',
]);

/** The category each rule is filed under. */
const EXPECTED_OWASP_LLM: Readonly<Record<string, string>> = {
  [INTERPRETER_PY]: 'LLM05:2025 Improper Output Handling',
  [DISPATCH_PY]: 'LLM06:2025 Excessive Agency',
  [TRUST_REMOTE]: 'LLM03:2025 Supply Chain',
  [TORCH_UNSAFE]: 'LLM03:2025 Supply Chain',
  [TORCH_DEFAULT]: 'LLM03:2025 Supply Chain',
  [NO_MAX_PY]: 'LLM10:2025 Unbounded Consumption',
  [INTERPRETER_JS]: 'LLM05:2025 Improper Output Handling',
  [SYSTEM_PROMPT_JS]: 'LLM01:2025 Prompt Injection',
  [NO_MAX_JS]: 'LLM10:2025 Unbounded Consumption',
};

function expectedLines(file: string): number[] {
  const lines: number[] = [];
  readFileSync(resolve(FIXTURES, 'hits', file), 'utf8')
    .split('\n')
    .forEach((text, i) => {
      if (/(?:\/\/|#) BUG:/.test(text)) lines.push(i + 1);
    });
  return lines;
}

interface RuleDoc {
  id: string;
  severity?: string;
  languages?: string[];
  metadata?: Record<string, unknown>;
}

function packRules(): RuleDoc[] {
  const doc = parse(readFileSync(RULES, 'utf8')) as { rules?: RuleDoc[] };
  return doc.rules ?? [];
}

describe('llm rules', () => {
  it.runIf(REQUIRE_SEMGREP)('the toolchain must be usable when the flag is set', () => {
    expect(AVAILABLE).toBe(true);
  });

  // Where scan_sast looks for it is asserted by scanSastProjectRules.test.ts
  // ("the pack is on disk where the plan looks for it").
  it('the rule file exists in the plugin pack directory', () => {
    expect(existsSync(RULES)).toBe(true);
  });

  it('Step 0: every hits/ fixture on disk has a registered expectation, and vice versa', () => {
    expect(filesIn(resolve(FIXTURES, 'hits'))).toEqual(Object.keys(EXPECTED_HITS).sort());
  });

  it('every hits/ fixture has a misses/ twin', () => {
    expect(filesIn(resolve(FIXTURES, 'misses'))).toEqual(filesIn(resolve(FIXTURES, 'hits')));
  });

  it('declares exactly the rules the fixtures are written for', () => {
    expect(packRules().map((r) => r.id).sort()).toEqual(Object.keys(EXPECTED_SEVERITY).sort());
  });

  it('every rule is filed as security, under one OWASP LLM Top 10 2025 category, with CWE ids', () => {
    for (const rule of packRules()) {
      const meta = rule.metadata ?? {};
      expect([rule.id, meta['category']]).toEqual([rule.id, 'security']);
      expect([rule.id, meta['owasp-llm']]).toEqual([rule.id, EXPECTED_OWASP_LLM[rule.id]]);
      expect(OWASP_LLM_2025.has(String(meta['owasp-llm']))).toBe(true);
      // Not `owasp`: this repo's parsers read that key as the web Top 10.
      expect([rule.id, meta['owasp']]).toEqual([rule.id, undefined]);
      const cwe = meta['cwe'];
      expect(Array.isArray(cwe) && cwe.length > 0).toBe(true);
      for (const c of Array.isArray(cwe) ? cwe : []) expect(String(c)).toMatch(/^CWE-\d+: \S/);
      expect(String(meta['subcategory'])).toMatch(/^llm-[a-z-]+$/);
    }
  });

  it.skipIf(!AVAILABLE)('fires exactly the expected rules, exactly the expected number of times, in EACH hit fixture', () => {
    const result = hits();
    expect(result.errors).toBe(0);
    expect(result.scanned).toBe(filesIn(resolve(FIXTURES, 'hits')).length);
    expect(countsByFile(result)).toEqual(EXPECTED_HITS);
  });

  it.skipIf(!AVAILABLE)('fires on exactly the marked lines of every hit fixture', () => {
    const { rows } = hits();
    for (const file of Object.keys(EXPECTED_HITS)) {
      const got = rows.filter((r) => basename(r.path) === file).map((r) => r.start.line).sort((a, b) => a - b);
      expect([file, got]).toEqual([file, expectedLines(file)]);
    }
  });

  it.skipIf(!AVAILABLE)('fires NOTHING in EACH near-miss fixture', () => {
    const { rows, scanned, errors } = misses();
    expect(errors).toBe(0);
    // Every misses/ file must actually have been looked at, or "nothing" is
    // "never read".
    expect(scanned).toBe(filesIn(resolve(FIXTURES, 'misses')).length);
    expect(rows.map((r) => `${basename(r.path)}:${r.start.line}: ${ruleOf(r)}`)).toEqual([]);
  });

  it.skipIf(!AVAILABLE)('reports each rule at its DESIGNED severity tier', () => {
    const seen = new Map<string, Set<string>>();
    for (const row of hits().rows) {
      const severity = row.extra?.severity;
      if (severity === undefined) throw new Error(`no severity on ${ruleOf(row)}`);
      const set = seen.get(ruleOf(row)) ?? new Set<string>();
      set.add(severity);
      seen.set(ruleOf(row), set);
    }
    for (const [id, tier] of Object.entries(EXPECTED_SEVERITY)) {
      expect([id, [...(seen.get(id) ?? [])]]).toEqual([id, [tier]]);
    }
  });

  /**
   * The ids a user's baseline and suppressions key on. Semgrep names a rule of
   * a file outside its working directory by that file's whole path, dotted —
   * a new id with every plugin version (`runners/semgrepRuleIds.ts`). Run the
   * way scan_sast runs it (cwd = the project, the pack by absolute path),
   * every finding must come out under the rule's own id, filed as security,
   * at the severity the pack declares.
   */
  it.skipIf(!AVAILABLE)('scan_sast stores every finding under the bare rule id, as security, at the declared severity', () => {
    const { raw, work } = hits();
    const parsed = semgrepParserFor([RULES], { projectPath: work, cwd: work }).parse(raw, { project_path: work });
    expect(parsed.findings.length).toBe(hits().rows.length);
    const ids = new Set(Object.keys(EXPECTED_SEVERITY));
    for (const f of parsed.findings) {
      expect(ids.has(f.rule_id ?? '')).toBe(true);
      expect(f.category).toBe('security');
      expect(f.subcategory ?? '').toMatch(/^llm-/);
      expect(f.severity).toBe(EXPECTED_SEVERITY[f.rule_id ?? ''] === 'LOW' ? 'low' : 'medium');
    }
  });
});

/**
 * The retrieval sanitizer of `llm-request-in-system-prompt-js` decides by the
 * NAME of the call, so the name list is the whole of its precision. Review of
 * the pack, I-4: the first version, `(?i)\w*(?:retriev|search)\w*`, took
 * `researchInstructions(topic)` and `searchAndReplace(...)` for retrievals and
 * silenced the request text they return. The regex is case-sensitive and has
 * no inline modifier, so Node evaluates it as Semgrep does (left-anchored, as
 * `metavariable-regex` is — hence the `^`).
 */
describe('the retrieval sanitizer of the system-prompt rule', () => {
  function sanitizerRegex(): RegExp {
    const rule = packRules().find((r) => r.id === SYSTEM_PROMPT_JS) as
      | (RuleDoc & { 'pattern-sanitizers'?: Array<{ patterns?: Array<Record<string, unknown>> }> })
      | undefined;
    const regexes = (rule?.['pattern-sanitizers'] ?? [])
      .flatMap((s) => s.patterns ?? [])
      .map((p) => p['metavariable-regex'] as { metavariable?: string; regex?: string } | undefined)
      .filter((m): m is { metavariable: string; regex: string } => m?.metavariable === '$FN' && typeof m.regex === 'string');
    expect(regexes).toHaveLength(1);
    const source = regexes[0]?.regex ?? '';
    expect(source.startsWith('^')).toBe(true);
    expect(source).not.toMatch(/\(\?[a-z]+[):]/);
    return new RegExp(source);
  }

  const RETRIEVALS = [
    'retrieveContext', 'retrieve', 'retrieveDocuments', 'retrieve_context', 'this.rag.retrieveChunks',
    'search', 'searchDocs', 'searchDocuments', 'searchKnowledgeBase', 'searchContext', 'searchChunks', 'searchIndex',
    'similaritySearch', 'vectorStore.similaritySearch', 'this.store.hybridSearch', 'vectorSearch', 'semanticSearchDocs',
    'getRelevantDocuments', 'retriever.invoke', 'this.retriever.ainvoke', 'vectorRetriever.getRelevantDocuments',
    'SearchService.search',
  ];
  const NOT_RETRIEVALS = [
    'researchInstructions', 'research', 'researchPrompt', 'searchAndReplace', 'this.util.searchAndReplace',
    'mySearchAndReplace', 'buildSearchQuery', 'searchParams', 'url.searchParams.get', 'Research', 'toPrompt',
    'retrieverConfig', 'getSearchTerm', 'saveSearchHistory',
  ];

  it.each(RETRIEVALS)('%s is a retrieval', (name) => {
    expect(sanitizerRegex().test(name)).toBe(true);
  });

  it.each(NOT_RETRIEVALS)('%s is not', (name) => {
    expect(sanitizerRegex().test(name)).toBe(false);
  });
});
