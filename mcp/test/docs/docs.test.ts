/**
 * The documentation against the code it describes.
 *
 * Every number below drifted at least once while it was maintained by hand:
 * the README said 57 tools while CLAUDE.md said 54 and `mcp/README.md` said
 * both, and CLAUDE.md's pack table said 134 rules across nine packs after a
 * tenth pack had shipped. So:
 *
 *   - `docs/tools.md` and `docs/rule-packs.md` are GENERATED (`npm run build`
 *     runs `test/docs/generate.ts`); a committed page that differs from what
 *     the generator would write fails here;
 *   - every tool, resource, skill and command count the READMEs, CLAUDE.md,
 *     `mcp/README.md` and the hand-written docs (docs/maintainers/ included)
 *     state equals the registry / the tree — a stale count anywhere in those
 *     files fails, not only the first one;
 *   - CLAUDE.md is an index of at most 8 KB that links every maintainer note;
 *   - the ablation notes' rule-pack table (docs/maintainers/ablation.md,
 *     moved out of CLAUDE.md) and its totals equal the pack files, as the
 *     ablation harness itself enumerates them;
 *   - `docs/env.md` names every `GUARDIAN_*` environment variable the code
 *     reads.
 */

import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';

import type { ResourceModule } from '../../src/resources/index.js';
import type { FoldRecord } from '../../src/tools/fold.js';
import { listedTools, type ToolModule } from '../../src/tools/index.js';
import {
  AREA_TITLES,
  buildInput,
  exampleRefs,
  executableCounts,
  KNOWN_LIMITS_SOURCE,
  LIMIT_AREAS,
  loadKnownLimits,
} from './knownLimits.js';
import {
  GENERATED_NOTICE,
  KNOWN_LIMITS_TITLE,
  noClauseKind,
  PACK_CONSUMERS,
  packTotals,
  renderKnownLimitsDoc,
  renderRulePacksDoc,
  renderToolsDoc,
  type PackInput,
} from './renderDocs.js';
import { listProblems } from './markdownLists.js';
import { DOCS_DIR, loadPacks, loadRegistry, REPO_ROOT } from './sources.js';

/** The listed tools — what a host sees, and what the docs count and name. */
let tools: readonly ToolModule[];
let registered: readonly ToolModule[];
let folds: readonly FoldRecord[];
let resources: readonly ResourceModule[];
let packs: PackInput[];

beforeAll(async () => {
  ({ tools: registered, resources, folds } = await loadRegistry());
  tools = listedTools(registered);
  packs = loadPacks();
});

function read(rel: string): string {
  return readFileSync(resolve(REPO_ROOT, rel), 'utf8');
}

/** `text` with every run of white space as one space: a record is found wherever the page wraps or indents it. */
function flat(text: string): string {
  return text.replace(/\s+/g, ' ').trim();
}

const REGENERATE = 'run `npm run build` in mcp/ to regenerate it — never edit a generated page by hand';

describe('generated reference pages', () => {
  it('docs/tools.md is what the registry renders to', () => {
    expect(read('docs/tools.md'), REGENERATE).toBe(renderToolsDoc(registered, resources, folds));
  });

  it('docs/rule-packs.md is what the pack files render to', () => {
    expect(read('docs/rule-packs.md'), REGENERATE).toBe(renderRulePacksDoc(packs));
  });

  it('names the tool that runs every pack, and no pack that does not exist', () => {
    expect(Object.keys(PACK_CONSUMERS).sort()).toEqual(packs.map((p) => p.file).sort());
  });

  it('classifies every rule with no ablatable clause as bare or positive-only', () => {
    const unclassified = packs
      .flatMap((p) => p.inventory)
      .filter((r) => r.clauseCount === 0 && noClauseKind(r.noClausesReason ?? '') === 'other')
      .map((r) => `${r.ruleId}: ${r.noClausesReason ?? ''}`);
    expect(unclassified).toEqual([]);
  });
});

// ------------------------------------------------------------------ counts

interface CountSpec {
  label: string;
  /** Group 1 is the number: `57 tools`, `57 ferramentas MCP`, … */
  re: RegExp;
  /** The heading form, `## Tools (57)`, when a file uses one. */
  heading?: RegExp;
  actual: () => number;
}

const skillCount = (): number =>
  readdirSync(resolve(REPO_ROOT, 'skills'), { withFileTypes: true }).filter(
    (d) => d.isDirectory() && existsSync(resolve(REPO_ROOT, 'skills', d.name, 'SKILL.md')),
  ).length;
const commandCount = (): number => readdirSync(resolve(REPO_ROOT, 'commands')).filter((f) => f.endsWith('.md')).length;

const COUNTS: readonly CountSpec[] = [
  {
    label: 'tools',
    re: /(\d+)\s+(?:MCP\s+)?(?:tools|ferramentas|herramientas)\b/gi,
    heading: /\b(?:tools|ferramentas|herramientas)\s+\((\d+)\)/gi,
    actual: () => tools.length,
  },
  {
    label: 'resources',
    re: /(\d+)\s+(?:MCP\s+)?(?:resources|recursos)\b/gi,
    heading: /\b(?:resources|recursos)\s+\((\d+)\)/gi,
    actual: () => resources.length,
  },
  { label: 'skills', re: /(\d+)\s+skills\b/gi, actual: skillCount },
  { label: 'commands', re: /(\d+)\s+(?:slash\s+)?(?:commands|comandos)\b/gi, actual: commandCount },
];

/** Each file, and the counts it must state at least once. */
const COUNTED_FILES: readonly [string, readonly string[]][] = [
  ['README.md', ['tools', 'resources', 'skills', 'commands']],
  ['README.pt-PT.md', ['tools', 'resources', 'skills', 'commands']],
  ['README.es.md', ['tools', 'resources', 'skills', 'commands']],
  ['CLAUDE.md', ['tools', 'resources', 'skills']],
  ['mcp/README.md', ['tools', 'resources']],
];

/** Hand-written pages under docs/ and docs/maintainers/: any count they state must be right too. */
function handWrittenDocs(): string[] {
  const pages = readdirSync(DOCS_DIR)
    .filter((f) => f.endsWith('.md') && f !== 'tools.md' && f !== 'rule-packs.md')
    .map((f) => `docs/${f}`);
  const maintainers = resolve(DOCS_DIR, 'maintainers');
  if (existsSync(maintainers)) {
    pages.push(...readdirSync(maintainers).filter((f) => f.endsWith('.md')).map((f) => `docs/maintainers/${f}`));
  }
  return pages;
}

function statedCounts(text: string, c: CountSpec): number[] {
  return [c.re, ...(c.heading !== undefined ? [c.heading] : [])].flatMap((re) =>
    [...text.matchAll(re)].map((m) => Number(m[1])),
  );
}

describe("the hooks' known-limits page", () => {
  const PAGE = 'docs/hooks-known-limits.md';

  it('T-10 renders a section per area, each limit with its text and each example with its input and its verdict', () => {
    const limits = loadKnownLimits();
    const page = renderKnownLimitsDoc(limits);
    const lines = page.split('\n');

    // One section per area that has a limit, in the fixed order.
    const used = LIMIT_AREAS.filter((area) => limits.some((l) => l.area === area));
    const at = used.map((area) => lines.indexOf(`## ${AREA_TITLES[area]}`));
    expect(at.every((i) => i >= 0), `a section is missing: ${JSON.stringify(at)}`).toBe(true);
    expect([...at].sort((x, y) => x - y)).toEqual(at);

    for (const l of limits) {
      expect(flat(page), l.id).toContain(flat(l.doc));
      if (l.examples.length === 0) expect(page, l.id).toContain((l.not_executable ?? '').trim());
    }
    for (const { limit, index, example } of exampleRefs(limits)) {
      const what = `${limit.id} #${String(index + 1)}`;
      if (example.detector === 'hook') {
        expect(lines.some((line) => line.includes(example.tool) && line.includes(example.expect.decision)), what).toBe(true);
        continue;
      }
      const verdict = example.detector === 'shell' ? example.expect.level : String(example.expect.hits);
      if (example.build !== undefined) {
        // An input by construction is described, never written out.
        const { repeat, times, then } = example.build;
        expect(
          lines.some((line) => line.includes(repeat) && line.includes(String(times)) && line.includes(then) && line.includes(verdict)),
          what,
        ).toBe(true);
        if (repeat.length * times > 200) expect(page, what).not.toContain(buildInput(example));
        continue;
      }
      // A token is published as its parts are written, never joined.
      const shown = example.detector === 'secret' && example.parts !== undefined ? (example.parts[0] ?? '') : buildInput(example);
      expect(lines.some((line) => line.includes(shown) && line.includes(verdict)), what).toBe(true);
      if (example.detector === 'shell' && example.expect.ask === true) {
        expect(lines.some((line) => line.includes(shown) && /ask/i.test(line)), what).toBe(true);
      }
    }
  });

  it('T-11 docs/hooks-known-limits.md is what the data file renders to', () => {
    expect(existsSync(resolve(REPO_ROOT, PAGE)), `${PAGE} is missing: ${REGENERATE}`).toBe(true);
    expect(read(PAGE), REGENERATE).toBe(renderKnownLimitsDoc(loadKnownLimits()));
  });

  it('T-12 the page says it is generated, from which file, and how many limits have an example a test runs', () => {
    const limits = loadKnownLimits();
    const page = renderKnownLimitsDoc(limits);
    expect(page.startsWith(`${KNOWN_LIMITS_TITLE}\n\n${GENERATED_NOTICE}\n`)).toBe(true);
    const intro = page.slice(0, page.indexOf('\n## '));
    expect(intro).toContain(KNOWN_LIMITS_SOURCE);
    const counts = executableCounts(limits);
    expect(counts.total).toBe(limits.length);
    expect(counts.withExample + counts.without).toBe(counts.total);
    expect(counts.withExample).toBe(limits.filter((l) => l.examples.length > 0).length);
    for (const n of [counts.total, counts.withExample, counts.without]) expect(intro).toMatch(new RegExp(`\\b${String(n)}\\b`));
  });

  it('T-13 docs/hooks.md points at the page where the list was, and lists no limit by hand', () => {
    const hooks = read('docs/hooks.md');
    const at = hooks.indexOf('**Known limits.**');
    expect(at, 'the "Known limits." paragraph of docs/hooks.md').toBeGreaterThan(-1);
    const rest = hooks.slice(at);
    const next = rest.search(/\r?\n## /);
    const paragraph = next === -1 ? rest : rest.slice(0, next);
    expect(paragraph).toContain('](hooks-known-limits.md)');
    // A limit is a record of the data file: nothing is listed here by hand.
    expect(paragraph.split(/\r?\n/).filter((line) => /^\s*[-*] /.test(line))).toEqual([]);
  });

  it('T-14 the page is listed among the generated files that are never edited by hand', () => {
    expect(read('CLAUDE.md')).toContain(PAGE);
    expect(read('docs/maintainers/build-and-test.md')).toContain(PAGE);
  });
});

describe('counts the docs state equal the code', () => {
  it.each(COUNTED_FILES)('%s states each count, and every statement of it is right', (rel, required) => {
    const text = read(rel);
    const problems: string[] = [];
    for (const c of COUNTS) {
      const stated = statedCounts(text, c);
      if (required.includes(c.label) && stated.length === 0) problems.push(`states no ${c.label} count`);
      for (const n of stated) if (n !== c.actual()) problems.push(`says ${n} ${c.label}, the code has ${c.actual()}`);
    }
    expect(problems).toEqual([]);
  });

  it('every count stated in a hand-written docs/ page is right', () => {
    const problems: string[] = [];
    for (const rel of handWrittenDocs()) {
      const text = read(rel);
      for (const c of COUNTS) {
        for (const n of statedCounts(text, c)) {
          if (n !== c.actual()) problems.push(`${rel}: says ${n} ${c.label}, the code has ${c.actual()}`);
        }
      }
    }
    expect(problems).toEqual([]);
  });

  it.each(['README.md', 'README.pt-PT.md', 'README.es.md'])('%s names every registered tool, and no tool that is not', (rel) => {
    const text = read(rel);
    const names = new Set(tools.map((t) => t.name));
    expect(tools.map((t) => t.name).filter((n) => !text.includes(`\`${n}\``))).toEqual([]);
    // A backticked snake_case name that looks like a tool (a known tool's
    // first word) but is not one: a renamed or removed tool left behind.
    const prefixes = new Set(tools.map((t) => t.name.split('_')[0] ?? ''));
    const strays = [...text.matchAll(/`([a-z]+(?:_[a-z0-9]+)+)`/g)]
      .map((m) => m[1] ?? '')
      .filter((n) => prefixes.has(n.split('_')[0] ?? '') && !names.has(n));
    expect([...new Set(strays)]).toEqual([]);
  });

  const READMES = ['README.md', 'README.pt-PT.md', 'README.es.md'];

  it.each(READMES)('%s states the rule and pack totals the pack files add up to', (rel) => {
    const t = packTotals(packs);
    const stated = [
      ...read(rel).matchAll(/(\d+)\s+(?:Semgrep\s+)?(?:rules|regras|reglas)(?:\s+Semgrep)?\s+(?:in|em|en)\s+(\d+)\s+packs\b/gi),
    ].map((m) => [Number(m[1]), Number(m[2])]);
    expect(stated.length).toBeGreaterThan(0);
    for (const pair of stated) expect(pair).toEqual([t.rules, t.packs]);
  });

  /** The support matrix's bug-rule column, per row label, against its pack. */
  const MATRIX_ROWS: readonly [string, string][] = [
    ['JavaScript / TypeScript', 'bugfix-js.yml'],
    ['Python', 'bugfix-py.yml'],
    ['Go', 'bugfix-go.yml'],
    ['Rust', 'bugfix-rs.yml'],
    ['Java', 'bugfix-java.yml'],
    ['C# / .NET', 'bugfix-cs.yml'],
    ['PHP', 'bugfix-php.yml'],
  ];

  it.each(READMES)("%s's support matrix states each bug pack's rule count", (rel) => {
    const rows = new Map(
      read(rel)
        .split(/\r?\n/)
        .filter((l) => l.startsWith('| '))
        .map((l) => l.split('|').map((c) => c.trim()))
        .map((cells) => [cells[1] ?? '', cells[3] ?? ''] as const),
    );
    const problems: string[] = [];
    for (const [label, file] of MATRIX_ROWS) {
      const cell = rows.get(label);
      const pack = packs.find((p) => p.file === file);
      const m = cell === undefined ? null : /(\d+)\s+(?:rules?|regras?|reglas?)\b/i.exec(cell);
      if (pack === undefined) problems.push(`${file}: no such pack`);
      else if (m === null) problems.push(`${label}: no rule count in the matrix`);
      else if (Number(m[1]) !== pack.rules.length) problems.push(`${label}: says ${m[1]}, ${file} has ${pack.rules.length}`);
    }
    expect(problems).toEqual([]);
  });

  it('the READMEs link to each other', () => {
    const missing: string[] = [];
    const all = ['README.md', 'README.pt-PT.md', 'README.es.md'];
    for (const rel of all) {
      const text = read(rel);
      for (const other of all.filter((o) => o !== rel)) {
        if (!text.includes(`](${other})`)) missing.push(`${rel} -> ${other}`);
      }
    }
    expect(missing).toEqual([]);
  });
});

// ------------------------------------------------ the ablation notes' packs

/** The ablation harness's maintainer notes — moved out of CLAUDE.md, which is now an index (review 8). */
const ABLATION_NOTES = 'docs/maintainers/ablation.md';

describe("the ablation notes' rule-pack table", () => {
  const TABLE_ROW = /^\|\s*`([a-z0-9-]+)`\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*$/;

  function tableRows(): Map<string, [number, number, number]> {
    const lines = read(ABLATION_NOTES).split(/\r?\n/);
    const header = lines.findIndex((l) => /^\|\s*pack\s*\|\s*rules\s*\|\s*with ablatable clauses\s*\|\s*with none\s*\|/i.test(l));
    expect(header, `${ABLATION_NOTES} has the "| pack | rules | with ablatable clauses | with none |" table`).toBeGreaterThanOrEqual(0);
    const rows = new Map<string, [number, number, number]>();
    for (const line of lines.slice(header + 2)) {
      const m = TABLE_ROW.exec(line);
      if (m === null) break;
      rows.set(m[1] ?? '', [Number(m[2]), Number(m[3]), Number(m[4])]);
    }
    return rows;
  }

  it('lists every pack in configs/semgrep, with its rules and clause coverage', () => {
    const expected = new Map(
      packs.map((p) => {
        const none = p.inventory.filter((r) => r.clauseCount === 0).length;
        return [p.file.replace(/\.yml$/, ''), [p.rules.length, p.rules.length - none, none] as [number, number, number]];
      }),
    );
    expect(Object.fromEntries(tableRows())).toEqual(Object.fromEntries(expected));
  });

  it('states the totals the pack files add up to', () => {
    const text = read(ABLATION_NOTES);
    const t = packTotals(packs);
    const ofTheRules = [...text.matchAll(/\*\*(\d+) of the (\d+) rules\*\*/g)].map((m) => [Number(m[1]), Number(m[2])]);
    expect(ofTheRules.length).toBeGreaterThan(0);
    for (const pair of ofTheRules) expect(pair).toEqual([t.withNone, t.rules]);
    const split = [...text.matchAll(/(\d+) bare and (\d+) positive-only/g)].map((m) => [Number(m[1]), Number(m[2])]);
    expect(split.length).toBeGreaterThan(0);
    for (const pair of split) expect(pair).toEqual([t.bare, t.positiveOnly]);
  });
});

// ------------------------------------------------------------- CLAUDE.md

// CLAUDE.md is loaded into every session in this repository. It was 41.5 KB,
// two thirds of it the ablation harness's manual; it is an index now, and the
// notes live in docs/maintainers/ — linked, never `@`-imported (an import
// would inline them into every session again).
describe('CLAUDE.md is an index', () => {
  const INDEX_MAX_BYTES = 8 * 1024;
  const text = (): string => read('CLAUDE.md');

  it(`is at most ${INDEX_MAX_BYTES} bytes`, () => {
    expect(Buffer.byteLength(text(), 'utf8')).toBeLessThanOrEqual(INDEX_MAX_BYTES);
  });

  it('links every docs/maintainers/ topic file, and imports none', () => {
    const topics = readdirSync(resolve(DOCS_DIR, 'maintainers')).filter((f) => f.endsWith('.md'));
    expect(topics.length).toBeGreaterThan(3);
    expect(topics.filter((f) => !text().includes(`](docs/maintainers/${f})`))).toEqual([]);
    expect(text()).not.toMatch(/^@\S/m);
  });
});

// ------------------------------------------------------------- docs/env.md

/** Where environment variables are read: runtime code, and the developer tooling. */
const ENV_SOURCES = [
  'mcp/src',
  'hooks',
  'cli',
  'mcp/scripts',
  'mcp/test/ablate',
  'mcp/test/e2e',
  'mcp/test/evals',
  'mcp/test/helpers',
  'mcp/test/integration',
  'mcp/test/setup',
  'mcp/test/unit',
  'mcp/vitest.config.ts',
];

/**
 * `GUARDIAN_*` tokens that are identifiers, not environment variables: a
 * constant's name, the `GUARDIAN_REQUIRE_` prefix written alone, another
 * project's identifier, and the names tests set or look for in an environment
 * they build (a hook switch nobody defined, the variable a DAST credential is
 * read from), which dev-guardian itself never reads.
 */
const NOT_ENV_VARS = new Set([
  'GUARDIAN_IGNORE_FILE',
  'GUARDIAN_REQUIRE',
  'GUARDIAN_GAP_KINDS',
  'GUARDIAN_FORWARDED',
  'GUARDIAN_ANYTHING',
  'GUARDIAN_SOMETHING_NEW',
  'GUARDIAN_EXPLICIT',
  'GUARDIAN_PROCESSRUNNER_PARENT_SECRET',
  'GUARDIAN_DAST_AUTH',
  'GUARDIAN_DAST_TEST_AUTH',
]);

function filesUnder(rel: string): string[] {
  const abs = resolve(REPO_ROOT, rel);
  if (!statSync(abs).isDirectory()) return [abs];
  const out: string[] = [];
  for (const entry of readdirSync(abs, { withFileTypes: true })) {
    const child = join(abs, entry.name);
    if (entry.isDirectory()) out.push(...filesUnder(relative(REPO_ROOT, child)));
    else if (/\.(ts|mjs|js)$/.test(entry.name)) out.push(child);
  }
  return out;
}

describe('docs/env.md', () => {
  it('names every GUARDIAN_* environment variable the code and its tooling read', () => {
    const names = new Set<string>();
    for (const file of ENV_SOURCES.flatMap(filesUnder)) {
      for (const m of readFileSync(file, 'utf8').matchAll(/(?<![A-Z0-9_])GUARDIAN_[A-Z0-9_]*[A-Z0-9]/g)) {
        if (!NOT_ENV_VARS.has(m[0]) && !m[0].startsWith('GUARDIAN_TEST_')) names.add(m[0]);
      }
    }
    expect(names.size).toBeGreaterThan(10);
    const env = read('docs/env.md');
    const undocumented = [...names].filter((n) => !env.includes(`\`${n}\``)).sort();
    expect(undocumented).toEqual([]);
  });
});

// The container run WITHOUT --toolchain skips every test of a real scanner.
// It was the release gate, with the scanners "an option", and ten tests were
// red on Linux for as long as nobody took the option — one of them a rule
// pack that found half of its fixture there.
describe('the release gate, as CONTRIBUTING states it', () => {
  it('T-05 step 0 of a release is the container run with the pinned scanners required, and the WPScan switch is documented', () => {
    const contributing = read('CONTRIBUTING.md').replace(/\r\n/g, '\n');
    const step0 = /^0\. [^]*?(?=^1\. )/m.exec(contributing)?.[0] ?? '';
    expect(step0).toMatch(/`npm run test:docker -- --toolchain`/);
    expect(read('docs/env.md')).toMatch(/^\| `GUARDIAN_REQUIRE_WPSCAN` \| test suite \|/m);
  });
});

// ───────────────── the cross-plugin review (dev-spec-driven 1.41 × 3.17.0): who hands the finish its base, two streams

describe("docs/ci.md on dev-spec-driven's finish check and on a name printed on two streams", () => {
  /** A `## ` section of docs/ci.md, up to the next one, whitespace joined. */
  const section = (heading: string): string => {
    const ci = read('docs/ci.md').replace(/\r\n/g, '\n');
    const at = ci.indexOf(`\n${heading}\n`);
    expect(at, heading).toBeGreaterThan(-1);
    const rest = ci.slice(at + heading.length + 2);
    const end = rest.search(/^## /m);
    return flat(end === -1 ? rest : rest.slice(0, end));
  };

  it('RX-1 the base comes from `finish --run`; a check reported over MCP gets none, so neither diff pass runs in it', () => {
    const finish = section("## As dev-spec-driven's finish check");
    expect(finish).not.toMatch(/its finish hands the launcher/);
    expect(finish).toContain("its `finish --run` (1.33 or later) hands the launcher the feature's base (`DEV_SPEC_DIFF_BASE`)");
    expect(finish).toContain(
      'a check run by hand and reported over MCP (`spec_finish` with its evidence) gets no base, so neither diff pass runs in it unless that run sets `DEV_SPEC_DIFF_BASE`',
    );
  });

  it('RX-6 `metrics` reads one file in print order, dev-spec-driven stdout then stderr: one stream reads the same in both', () => {
    const metrics = section('## `metrics`');
    expect(metrics).toContain('`metrics` reads one file, in print order: a job that captures `2>&1`');
    expect(metrics).toContain("dev-spec-driven reads stdout, then stderr, so stderr's line wins there");
    expect(metrics).toContain('print a name on one stream to get the same reading from both');
  });

  // DG-17 (metric-bytes/1): the decoding is decided by what is READ — the file's last 64 MiB past the bound, where a
  // UTF-16 file's byte-order mark no longer is (the fixture's tail-window case) —, and a mark mid-file reads nothing.
  it('DG-17 `metrics` decodes what is read as check --file does, and a byte-order mark mid-file leaves its line unread', () => {
    const metrics = section('## `metrics`');
    expect(metrics).toContain(
      'UTF-16 when what is read — the file, or its last 64 MiB — starts with a UTF-16 byte-order mark or NUL-interleaved bytes',
    );
    expect(metrics).toContain(
      'a byte-order mark further in — the stream printed second, in a `2>&1` capture of a tool that writes one on each stream — leaves its line unread',
    );
  });

  // Review 2 (R2-DG-HZ-8): "ANSI colour codes are removed first" read as if a code inside the keyword were
  // removed too; the reader (and dev-spec-driven's) reads the keyword as printed (R2-MF-6).
  it('R2-DG-HZ-8 the grammar says a colour code that splits the keyword reads nothing', () => {
    expect(section('## `metrics`')).toContain(
      'ANSI colour codes are removed first, but the keyword is read as printed: a colour code inside it (`MET`, the code, `RIC`) splits it, and the line reads nothing;',
    );
  });

  it('R2-DG-HZ-8 the upgrade note names both blanket IaC ignores, `#trivy:ignore:*` and `#tfsec:ignore:*`', () => {
    const upgrading = flat(read('CHANGELOG.md')).split('### Upgrading from 3.16.1')[1]?.split('### Added')[0] ?? '';
    expect(upgrading).toContain('`#trivy:ignore:*` or `#tfsec:ignore:*`');
  });
});

// ───────────────── install-vet-manifest-install — the docs say a manifest install is vetted

describe('the docs of the manifest vetting', () => {
  it('T-27 the known-limits page has the install-vetting section; docs/hooks.md and hooks.json say what is vetted and what leaves the machine', () => {
    const title = (AREA_TITLES as Readonly<Record<string, string | undefined>>)['install-vetting'];
    expect(title, 'the install-vetting area has a section title').toBeDefined();
    expect(read('docs/hooks-known-limits.md')).toContain(`## ${String(title)}`);

    const hooks = read('docs/hooks.md');
    const at = hooks.indexOf('## Install-time package vetting');
    expect(at).toBeGreaterThan(-1);
    const end = hooks.indexOf('\n## ', at + 1);
    const section = hooks.slice(at, end === -1 ? undefined : end);
    for (const said of ['installs from a manifest', '`npm ci`', '`pnpm install`', '`pip install -r`', '`package.json`']) {
      expect({ said, found: section.includes(said) }).toEqual({ said, found: true });
    }
    // What leaves the machine is declared, and what stays.
    expect(section).toContain('are sent to the public registry and to OSV');
    expect(section).toMatch(/scope[^.]*registry of its own[^.]*not sent/s);

    const description = String((JSON.parse(read('hooks/hooks.json')) as { description?: unknown }).description ?? '');
    expect(description).toMatch(/manifest/);
  });
});

// ───────────────── install-vet-pnpm-install-named — the docs name `pnpm install <pkg>` as a by-name install

describe('the docs of `pnpm install <package>`', () => {
  it('T-04 docs/hooks.md lists pnpm add|i|install among the by-name installs, and no known limit names `pnpm install <package>`', () => {
    const hooks = read('docs/hooks.md');
    const at = hooks.indexOf('## Install-time package vetting');
    const end = hooks.indexOf('\n## ', at + 1);
    const section = hooks.slice(at, end === -1 ? undefined : end);
    expect(section).toContain('`pnpm add|i|install`');
    for (const page of ['docs/hooks-known-limits.md', 'mcp/test/fixtures/hooks/known-limits.yml']) {
      expect({ page, namesIt: read(page).includes('pnpm install <package>') }).toEqual({ page, namesIt: false });
    }
  });
});

// ───────────────── secrets-history-old-git — the docs say what each git reads

describe('the docs of the secrets history pass on an older git (secrets-history-old-git)', () => {
  it("T-13 docs/ci.md and SECURITY.md no longer list the tree's .gitattributes as a limit of a git older than 2.40, and keep the merges of one older than 2.36", () => {
    for (const page of ['docs/ci.md', 'SECURITY.md']) {
      const text = read(page).replace(/\s+/g, ' ');
      expect({ page, listsTheOldLimit: /older than 2\.40/.test(text) }).toEqual({ page, listsTheOldLimit: false });
      expect({ page, keepsTheMerges: /older than 2\.36/.test(text) }).toEqual({ page, keepsTheMerges: true });
      // And says, once, that the tree's attributes are set aside whatever the git.
      expect({ page, saysSo: /working tree's `\.gitattributes` are set aside on any git/.test(text) }).toEqual({ page, saysSo: true });
    }
  });
});

// ───────────────── install-vet-lockfile-pins — the docs say what a lockfile changes

describe('install-vet-lockfile-pins', () => {
  /**
   * The sentences of a passage, each on one line. A dot ends one only before white space — not inside
   * `package-lock.json` or a link — and so do a line break and the bar between two cells of a table.
   */
  const sentences = (text: string): string[] =>
    text
      .replace(/\r\n/g, '\n')
      .split(/(?<=[.!?])\s+|\n+|\s\|\s/)
      .map((s) => s.replace(/\s+/g, ' ').trim())
      .filter((s) => s !== '');

  // The two things US-2.AC-2 wants said, each looked for as ONE sentence that holds its words — in English or, for
  // the skill, in Portuguese — whatever the phrasing around them. The words alone are already in docs/hooks.md,
  // which says the lockfile is NOT read: only a sentence that joins them says the new thing.
  const STATEMENTS: Array<[what: string, words: RegExp[]]> = [
    [
      'with a lockfile, the pairs it pins — of every dependency, the transitive ones too — go to OSV',
      [/lockfile/i, /\bOSV\b/, /transitiv/i],
    ],
    [
      'the registry is asked only for the direct dependencies the lockfile does not cover',
      [/lockfile/i, /regist(?:r(?:y|ies)|os?)\b/i, /\bdirec?t/i],
    ],
  ];
  const notSaid = (passage: string): string[] =>
    STATEMENTS.filter(([, words]) => !sentences(passage).some((s) => words.every((w) => w.test(s)))).map(([what]) => what);

  it('T-33 docs/hooks.md, the description in hooks.json and the guardian-deps skill say what a lockfile changes: its pinned pairs go to OSV, and the registry is asked only for the direct dependencies it does not cover', () => {
    const hooks = read('docs/hooks.md');
    const at = hooks.indexOf('## Install-time package vetting');
    expect(at).toBeGreaterThan(-1);
    const end = hooks.indexOf('\n## ', at + 1);
    const section = hooks.slice(at, end === -1 ? undefined : end);

    const description = String((JSON.parse(read('hooks/hooks.json')) as { description?: unknown }).description ?? '');

    const skill = read('skills/guardian-deps/SKILL.md');
    const from = skill.indexOf('## 3.');
    const to = skill.indexOf('## 4.');
    expect(from).toBeGreaterThan(-1);
    expect(to).toBeGreaterThan(from);
    const beforeInstalling = skill.slice(from, to);

    // US-2.AC-3: the skill says it inside the budget it already has.
    expect(Buffer.byteLength(skill, 'utf8')).toBeLessThanOrEqual(12 * 1024);

    // What was true before must no longer be said: that the lockfile and the transitive dependencies are not read
    // (docs/hooks.md), and that the hook's silence says nothing of the lockfile (the skill).
    const stillSaid = [
      ...(/lockfile, transitive dependencies[^.]*\bnot read\b/i.test(section.replace(/\s+/g, ' ')) ? ['docs/hooks.md: the lockfile and the transitive dependencies are not read'] : []),
      ...(/nem do lockfile/i.test(beforeInstalling.replace(/\s+/g, ' ')) ? ['the skill: the hook\'s silence does not speak of the lockfile'] : []),
    ];

    expect({
      'docs/hooks.md, "Install-time package vetting"': notSaid(section),
      'hooks/hooks.json, description': notSaid(description),
      'skills/guardian-deps/SKILL.md, section 3': notSaid(beforeInstalling),
      stillSaid,
    }).toEqual({
      'docs/hooks.md, "Install-time package vetting"': [],
      'hooks/hooks.json, description': [],
      'skills/guardian-deps/SKILL.md, section 3': [],
      stillSaid: [],
    });
  });
});

// ───────────────── selftest-install-vet-canary — the docs say there are five hook checks, and that one of them uses the network

describe('selftest-install-vet-canary', () => {
  /**
   * The sentences of a hard-wrapped page, each on one line: a line break inside a paragraph is a space; a blank
   * line, a list item and a full stop before white space end one; a table row is one, whole.
   */
  const sentences = (text: string): string[] =>
    text
      .replace(/\r\n/g, '\n')
      .split(/\n\s*\n|\n(?=\s*(?:[-*]|\d+\.)\s)|\n(?=\|)/)
      .flatMap((block) => {
        const line = block.replace(/\s+/g, ' ').trim();
        return line.startsWith('|') ? [line] : line.split(/(?<=[.!?])\s+/);
      })
      .filter((s) => s !== '');

  // What US-1.AC-8 and EC-1 want said, each looked for as ONE sentence (or one table row) that holds its words,
  // whatever the phrasing around them.
  const STATEMENTS: Array<[what: string, words: RegExp[]]> = [
    ['there are five hook checks', [/\bfive\b/i, /\bhooks?\b/i]],
    ['the install check is the only one that uses the network', [/\bonly\b/i, /\bnetwork\b/i]],
    ["what it asks, and of whom: the canary package's name, of the public npm registry and of OSV", [/\bregistry\b/i, /\bOSV\b/, /\bname\b|crossenv/i]],
    ['how to read its `unverified`: the registry was not asked, or did not answer — the network, not the guard', [/`unverified`/, /\bnetwork\b|\bregistry\b/i]],
    ['its `silent` may be the canary, not the guard: npm no longer serving the placeholder is the first place to look (EC-1)', [/`silent`/, /\bplaceholder\b|crossenv/i]],
  ];

  it('T-09 docs/selftest.md has the line of hooks:install-vet, says it is the one hook check that uses the network, what it asks and how to read its verdicts; the CLI help says five checks of the hooks', () => {
    const page = read('docs/selftest.md');
    const said = sentences(page);
    const from = page.indexOf('## The core controls');
    const to = page.indexOf('\n## ', from + 1);
    const controls = sentences(page.slice(from, to === -1 ? undefined : to));
    const row = controls.find((s) => s.startsWith('|') && s.includes('`hooks:install-vet`')) ?? '';

    // The CLI's own help, as its source holds it: the selftest's paragraph, one line.
    const cli = read('cli/dev-guardian.mjs');
    const start = cli.indexOf('selftest — does each core control DETECT');
    expect(start, "the selftest's paragraph of the CLI help").toBeGreaterThan(-1);
    const help = cli.slice(start, cli.indexOf('\nExamples:', start)).replace(/\s+/g, ' ');

    expect({
      'docs/selftest.md, "The core controls": the row of hooks:install-vet, which must answer `deny`': /`deny`/.test(row),
      'docs/selftest.md does not say': STATEMENTS.filter(([, words]) => !said.some((s) => words.every((w) => w.test(s)))).map(([what]) => what),
      'docs/selftest.md still says "all four"': /\ball four\b/i.test(page.replace(/\s+/g, ' ')),
      'the CLI help says five checks of the hooks': /\bfive\b[^.]*\bhooks?\b/i.test(help),
      'the CLI help still says four checks': /\bfour\b[^.]*\bhooks?\b/i.test(help),
    }).toEqual({
      'docs/selftest.md, "The core controls": the row of hooks:install-vet, which must answer `deny`': true,
      'docs/selftest.md does not say': [],
      'docs/selftest.md still says "all four"': false,
      'the CLI help says five checks of the hooks': true,
      'the CLI help still says four checks': false,
    });
  });
});

// ───────────────── pkgvet-registry-credentials-said — the docs say the warning names the registry's host, never its URL

describe('pkgvet-registry-credentials-said', () => {
  /** The sentences of a hard-wrapped page, each on one line: a blank line, a list item and a full stop before white space end one. */
  const sentences = (text: string): string[] =>
    text
      .replace(/\r\n/g, '\n')
      .split(/\n\s*\n|\n(?=\s*(?:[-*]|\d+\.)\s)|\n(?=\|)/)
      .flatMap((block) => block.replace(/\s+/g, ' ').trim().split(/(?<=[.!?])\s+/))
      .filter((s) => s !== '');

  it('T-06 docs/hooks.md says the warning names the configured registry by its host and never by its URL; the CHANGELOG has a Security entry with what to do', () => {
    const hooks = read('docs/hooks.md');
    const at = hooks.indexOf('## Install-time package vetting');
    expect(at, 'the "Install-time package vetting" section of docs/hooks.md').toBeGreaterThan(-1);
    const end = hooks.indexOf('\n## ', at + 1);
    const section = hooks.slice(at, end === -1 ? undefined : end);
    const namesHostNotUrl = sentences(section).some(
      (s) => /\bregistry\b/i.test(s) && /\bhost\b/i.test(s) && /\bnever\b/i.test(s) && /\bURLs?\b/.test(s) && /\bwarning\b/i.test(s),
    );

    // The entry is written under [Unreleased] and a release moves it to that version's section: the "### Security"
    // block of every section is read, and the one about this is the one that names the scheme and host.
    const log = read('CHANGELOG.md').replace(/\r\n/g, '\n');
    const securityBlocks = log.split(/\n(?=## \[)/).map((section) => {
      const sec = section.indexOf('\n### Security');
      if (sec === -1) return '';
      const secEnd = section.indexOf('\n### ', sec + 1);
      return section.slice(sec, secEnd === -1 ? undefined : secEnd).replace(/\s+/g, ' ');
    });
    const security = securityBlocks.find((block) => /registry URL/i.test(block) && /credentials/i.test(block) && /scheme and host/i.test(block)) ?? '';
    const aboutIt = /registry/i.test(security) && /credential|password|token/i.test(security);
    const saysWhatToDo = /\b(?:change|rotate|revoke|replace)\b/i.test(security) && /transcript/i.test(security);

    expect({
      'docs/hooks.md: a sentence says the warning names the registry by its host and never by its URL': namesHostNotUrl,
      'CHANGELOG: a Security section about the credentials in a registry URL': aboutIt,
      'CHANGELOG: it says to change the credentials a session transcript may hold': saysWhatToDo,
    }).toEqual({
      'docs/hooks.md: a sentence says the warning names the registry by its host and never by its URL': true,
      'CHANGELOG: a Security section about the credentials in a registry URL': true,
      'CHANGELOG: it says to change the credentials a session transcript may hold': true,
    });
  });
});

// ───────────────── pkgvet-public-registry-url-parse — the docs say what counts as the public registry

describe('pkgvet-public-registry-url-parse', () => {
  /** The sentences of a hard-wrapped page, each on one line: a blank line, a list item and a full stop before white space end one. */
  const sentences = (text: string): string[] =>
    text
      .replace(/\r\n/g, '\n')
      .split(/\n\s*\n|\n(?=\s*(?:[-*]|\d+\.)\s)|\n(?=\|)/)
      .flatMap((block) => block.replace(/\s+/g, ' ').trim().split(/(?<=[.!?])\s+/))
      .filter((s) => s !== '');

  it('T-05 docs/hooks.md says a registry URL with credentials, or with anything but the public host in its authority, counts as another registry', () => {
    const hooks = read('docs/hooks.md');
    const at = hooks.indexOf('## Install-time package vetting');
    expect(at, 'the "Install-time package vetting" section of docs/hooks.md').toBeGreaterThan(-1);
    const end = hooks.indexOf('\n## ', at + 1);
    const section = hooks.slice(at, end === -1 ? undefined : end);
    const saysIt = sentences(section).some(
      (s) => /\bURL\b/.test(s) && /\bcredentials\b/i.test(s) && /\bauthority\b/i.test(s) && /\bcounts?\b/i.test(s) && /\banother registry\b/i.test(s),
    );
    expect({ 'docs/hooks.md: a sentence says a URL with credentials, or with more than the public host in its authority, counts as another registry': saysIt }).toEqual({
      'docs/hooks.md: a sentence says a URL with credentials, or with more than the public host in its authority, counts as another registry': true,
    });
  });
});

// ───────────────── pkgvet-archive-like-name — the docs say which endings each manager reads as a file

describe('pkgvet-archive-like-name', () => {
  /** The sentences of a hard-wrapped page, each on one line: a blank line, a list item, a table row and a full stop before white space end one. */
  const sentences = (text: string): string[] =>
    text
      .replace(/\r\n/g, '\n')
      .split(/\n\s*\n|\n(?=\s*(?:[-*]|\d+\.)\s)|\n(?=\|)/)
      .flatMap((block) => block.replace(/\s+/g, ' ').trim().split(/(?<=[.!?])\s+/))
      .filter((s) => s !== '');

  const NPM_FILES = ['.tgz', '.tar.gz', '.tar'];
  const PIP_FILES = ['.zip', '.whl', '.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz', '.tar.xz', '.txz', '.tlz', '.tar.lz', '.tar.lzma'];
  const UV_FILES = ['.zip', '.whl', '.tgz', '.tar.gz', '.tar'];

  it('T-09 docs/hooks.md names the endings each manager reads as a file, and no longer says without a qualification that tarballs are never looked up', () => {
    const hooks = read('docs/hooks.md');
    const at = hooks.indexOf('## Install-time package vetting');
    expect(at, 'the "Install-time package vetting" section of docs/hooks.md').toBeGreaterThan(-1);
    const end = hooks.indexOf('\n## ', at + 1);
    const lines = sentences(hooks.slice(at, end === -1 ? undefined : end));
    const code = (endings: readonly string[]): ((s: string) => boolean) => (s) => endings.every((e) => s.includes(`\`${e}\``));
    const says = (manager: RegExp, check: (s: string) => boolean): boolean =>
      lines.some((s) => manager.test(s) && /\bfiles?\b/i.test(s) && check(s));

    const found = {
      'npm: .tgz .tar.gz .tar': says(/\bnpm\b/, code(NPM_FILES)),
      'bun: .tgz .tar.gz .tar': says(/\bbun\b/, code(NPM_FILES)),
      'pip: the twelve': says(/\bpip\b/, code(PIP_FILES)),
      'uv: the five': says(/\buv\b/, code(UV_FILES)),
      'poetry: pip\'s list without .whl': says(/\bpoetry\b/, (s) => s.includes('`.whl`') && /\bwithout\b|\bexcept\b|\bnot\b/i.test(s)),
      'pnpm and Yarn: none': lines.some((s) => /\bpnpm\b/.test(s) && /\bYarn\b/.test(s) && /\bnone\b|\bno ending\b/i.test(s)),
      'no unqualified "tarballs are never looked up"': !lines.some(
        (s) => /\btarballs?\b/i.test(s) && /never looked up/i.test(s) && !/\b(?:reads?|reading)\b/i.test(s),
      ),
    };
    expect(found).toEqual({
      'npm: .tgz .tar.gz .tar': true,
      'bun: .tgz .tar.gz .tar': true,
      'pip: the twelve': true,
      'uv: the five': true,
      'poetry: pip\'s list without .whl': true,
      'pnpm and Yarn: none': true,
      'no unqualified "tarballs are never looked up"': true,
    });
  });

  it('T-09 a record of the known limits says what stays (the managers that were not measured, the .tgz value of a manifest under Yarn 1) and has an example; the generated page has it', () => {
    const limit = loadKnownLimits().find((l) => l.id === 'archive-like-names');
    expect(limit, 'a record with the id archive-like-names in mcp/test/fixtures/hooks/known-limits.yml').toBeDefined();
    if (limit === undefined) return;
    expect(limit.area).toBe('install-vetting');
    expect(limit.examples.length, 'at least one example a test runs').toBeGreaterThanOrEqual(1);
    for (const said of ['pipx', 'composer', 'dotnet', 'Yarn 1']) {
      expect({ said, found: limit.doc.includes(said) }).toEqual({ said, found: true });
    }
    expect(read('docs/hooks-known-limits.md'), REGENERATE).toContain(limit.doc.trim());
  });
});

// ───────────────── install-vet-project-registry-said — the docs say the line, the files of each manager, and what stays

describe('install-vet-project-registry-said', () => {
  /** The sentences of a hard-wrapped page, each on one line: a blank line, a list item, a table row and a full stop before white space end one. */
  const sentences = (text: string): string[] =>
    text
      .replace(/\r\n/g, '\n')
      .split(/\n\s*\n|\n(?=\s*(?:[-*]|\d+\.)\s)|\n(?=\|)/)
      .flatMap((block) => block.replace(/\s+/g, ' ').trim().split(/(?<=[.!?])\s+/))
      .filter((s) => s !== '');

  it('T-08 docs/hooks.md describes the line a project default registry gets and the files each manager obeys', () => {
    const hooks = read('docs/hooks.md');
    const at = hooks.indexOf('## Install-time package vetting');
    expect(at, 'the "Install-time package vetting" section of docs/hooks.md').toBeGreaterThan(-1);
    const end = hooks.indexOf('\n## ', at + 1);
    const lines = sentences(hooks.slice(at, end === -1 ? undefined : end));
    const code = (s: string, ...files: string[]): boolean => files.every((f) => s.includes(`\`${f}\``));
    const found = {
      'the line: a file of the project sets the default registry, and what it serves was not vetted': lines.some(
        (s) => /sets the default registry/i.test(s) && /\bproject\b/i.test(s) && /\bnot (?:vetted|verified)\b/i.test(s),
      ),
      'npm and pnpm: .npmrc': lines.some((s) => /\bnpm\b/.test(s) && /\bpnpm\b/.test(s) && code(s, '.npmrc') && !code(s, 'bunfig.toml')),
      'bun: .npmrc and bunfig.toml': lines.some((s) => /\bbun\b/.test(s) && code(s, '.npmrc', 'bunfig.toml')),
      'Yarn: .npmrc, .yarnrc and .yarnrc.yml': lines.some((s) => /\bYarn\b/.test(s) && code(s, '.npmrc', '.yarnrc', '.yarnrc.yml')),
      'where: beside the package.json and at a workspace root': lines.some(
        (s) => /\bdefault registry\b/i.test(s) && /\bworkspace\b/i.test(s) && /package\.json/.test(s),
      ),
    };
    expect(found).toEqual({
      'the line: a file of the project sets the default registry, and what it serves was not vetted': true,
      'npm and pnpm: .npmrc': true,
      'bun: .npmrc and bunfig.toml': true,
      'Yarn: .npmrc, .yarnrc and .yarnrc.yml': true,
      'where: beside the package.json and at a workspace root': true,
    });
  });

  it('T-08 the record manifest-lockfile-and-transitive no longer says a project default registry is not said', () => {
    const limit = loadKnownLimits().find((l) => l.id === 'manifest-lockfile-and-transitive');
    expect(limit, 'the record manifest-lockfile-and-transitive').toBeDefined();
    const doc = limit?.doc ?? '';
    expect(doc, 'the record still lists the other things that stay out').toContain('another source');
    const about = doc.split('\n').filter((l) => /default registry/i.test(l) && /configuration file of the project/i.test(l));
    expect(about.filter((l) => /\bIt is not said\b/.test(l))).toEqual([]);
  });

  it('T-08 a record project-default-registry says what stays: Yarn 1 and 4, and the indexes of PyPI, Composer and NuGet; the generated page has it', () => {
    const limit = loadKnownLimits().find((l) => l.id === 'project-default-registry');
    expect(limit, 'a record with the id project-default-registry in mcp/test/fixtures/hooks/known-limits.yml').toBeDefined();
    if (limit === undefined) return;
    expect(limit.area).toBe('install-vetting');
    // The harness of the known limits runs offline and does not see the line: no example proves anything about it.
    expect(limit.examples, 'no example: the offline harness does not see the line').toEqual([]);
    expect((limit.not_executable ?? '').trim(), 'the reason no test of the harness can run it').not.toBe('');
    for (const said of ['Yarn 1', 'Yarn 4', 'PyPI', 'Composer', 'NuGet']) {
      expect({ said, found: limit.doc.includes(said) }).toEqual({ said, found: true });
    }
    // What stays after the fix round: a registry variable assigned inline in the command itself, and a line that
    // names a file the manager ends up not obeying (a member's file under a workspace root).
    const doc = limit.doc.toLowerCase();
    expect({ inline: doc.includes('inline'), environment: doc.includes('environment'), workspace: doc.includes('workspace') }).toEqual({
      inline: true,
      environment: true,
      workspace: true,
    });
    expect(limit.doc, 'the indexes a project file sets are said only when a name is missing').toMatch(/\bonly\b[^.]*\bmissing\b|\bmissing\b[^.]*\bonly\b/i);
    expect(flat(read('docs/hooks-known-limits.md')), REGENERATE).toContain(flat(limit.doc));
  });
});

// ───────────────── install-vet-named-install-manifest — the prose says an install by name also vets the manifest

describe('install-vet-named-install-manifest', () => {
  /** The "Install-time package vetting" section of docs/hooks.md, with its line breaks flattened. */
  const vettingSection = (): string => {
    const hooks = read('docs/hooks.md');
    const at = hooks.indexOf('## Install-time package vetting');
    expect(at).toBeGreaterThan(-1);
    const end = hooks.indexOf('\n## ', at + 1);
    return hooks.slice(at, end === -1 ? undefined : end).replace(/\s+/g, ' ');
  };
  /** A sentence that says an install which names a package also reads the manifest, in the plain words a page would use. */
  const SAYS_NAMED_READS_MANIFEST = /An install that names a package[^]{0,400}installs the project's `package\.json` beside it/;

  it('T-09 docs/hooks.md no longer says a manifest is read "never for a by-name install", and says a by-name install also reads it', () => {
    const section = vettingSection();
    expect(section).not.toMatch(/never for a by-name install/);
    expect(section).toMatch(SAYS_NAMED_READS_MANIFEST);
  });

  it('T-09 the "what leaves the machine" paragraph says the manifest names also go for an install that names a package', () => {
    const section = vettingSection();
    const at = section.indexOf('**What leaves the machine.**');
    expect(at).toBeGreaterThan(-1);
    const paragraph = section.slice(at, section.indexOf('**', at + 30));
    expect(paragraph).toMatch(/(install that names a package|by[- ]name install|install by name|named package)/i);
  });

  it('T-09 the description in hooks/hooks.json no longer calls the manifest install a "bare npm install", and covers an install by name', () => {
    const description = String((JSON.parse(read('hooks/hooks.json')) as { description?: unknown }).description ?? '');
    expect(description).not.toMatch(/a bare npm install/);
    expect(description).toMatch(/(by name|names a package|named package|install <pkg>|with a package)/i);
  });

  it('T-09 the SECURITY.md egress row for the public registries says an install by name inside a project sends the manifest names too', () => {
    const row = read('SECURITY.md')
      .split('\n')
      .find((line) => line.startsWith('| `registry.npmjs.org`'));
    expect(row, 'the egress row of the public registries').toBeDefined();
    expect(row).toMatch(/install by name inside a project[^|]*installs the manifest too/);
  });

  it('T-09 skills/guardian-deps/SKILL.md no longer says the manifest is read only for `npm install` "sem nomes"', () => {
    const skill = read('skills/guardian-deps/SKILL.md');
    expect(skill).not.toMatch(/`npm install` sem nomes/);
    expect(skill).toMatch(/`npm install` com ou sem nomes/);
  });
});

// ───────────────── install-vet-launcher-runs-manager — the prose says a launcher that runs a package manager is read like the manager

describe('install-vet-launcher-runs-manager', () => {
  it('T-10 the SECURITY.md egress row for the public registries says a launcher that runs a package manager sends the manifest names too', () => {
    const row = read('SECURITY.md')
      .split('\n')
      .find((line) => line.startsWith('| `registry.npmjs.org`'));
    expect(row, 'the egress row of the public registries').toBeDefined();
    expect(row).toMatch(/launcher that runs a package manager[^|]*manifest/);
  });

  it('T-10 skills/guardian-deps/SKILL.md no longer says the manifest is not read for `npx`', () => {
    const skill = read('skills/guardian-deps/SKILL.md');
    expect(skill).not.toContain('nem `npx`');
  });
});

// ───────────────── install-vet-over-ceiling-asks — docs/hooks.md says that going past a ceiling is a question

describe('install-vet-over-ceiling-asks', () => {
  /** docs/hooks.md with its line breaks flattened, so a sentence is found wherever the page wraps it. */
  const hooksPage = (): string => read('docs/hooks.md').replace(/\s+/g, ' ');
  const occurrences = (text: string, phrase: string): number => text.split(phrase).length - 1;

  it('T-07 the by-name and the manifest passages no longer say "a note says how many more were not vetted": the user is asked, and the question says how many', () => {
    const page = hooksPage();
    expect(page).not.toContain('a note says how many more were not vetted');
    // One for the installs by name, one for the manifests.
    expect(occurrences(page, 'the user is asked, and the question says how many more were not vetted')).toBeGreaterThanOrEqual(2);
  });

  it('T-07 the passage on the candidate words says the rest are counted in the line and the user is asked', () => {
    const page = hooksPage();
    expect(page).toContain('are counted in the "more packages in this command were not vetted" line, and the user is asked');
  });

  it('T-07 the passage on the 512 KB cut says that past it the user is asked, not that a note says so', () => {
    const page = hooksPage();
    expect(page).not.toContain('512 KB (past that, no missing-name deny, and a note says so');
    expect(page).toContain('512 KB (past that, no missing-name deny, and the user is asked, even when the first 512 KB install nothing)');
  });

  it('T-07 "With the block switched off each is only a warning" no longer covers the question of the install vetting, which the block switch does not turn off', () => {
    const page = hooksPage();
    expect(page).not.toContain('With the block switched off each is only a warning.');
    expect(page).toContain('With the block switched off each is only a warning, except the question about an install past a ceiling, which the block does not follow');
  });

  it('T-07 the page says there is no switch for this question alone, and what happens when no one can answer it', () => {
    const page = hooksPage();
    expect(page).toContain('no switch for this question alone');
    expect(page).toContain('when no one can answer, the call is refused and the model reads the reason');
  });
});

// ───────────────── install-vet-global-in-short-cluster — the docs say an npm group reads as its letters apart, and what stays

describe('install-vet-global-in-short-cluster', () => {
  // A one-dash word, not the tail of a two-dash one: `-global`, never the `-global` inside `--global`.
  const ONE_DASH_GLOBAL = /(?<![\w-])-global(?![\w-])/;
  const ONE_DASH_LOCAL = /(?<![\w-])-local(?![\w-])/;
  const GROUP_GD = /(?<![\w-])-gD(?![\w-])/;
  const APART_G_D = /(?<![\w-])-g -D(?![\w-])/;

  it('T-08 the "Install-time package vetting" section of docs/hooks.md no longer says a cluster with a `g` is never global, and has a sentence that reads `-gD` as `-g -D`', () => {
    const hooks = read('docs/hooks.md');
    const at = hooks.indexOf('## Install-time package vetting');
    expect(at, 'the "Install-time package vetting" section of docs/hooks.md').toBeGreaterThan(-1);
    const end = hooks.indexOf('\n## ', at + 1);
    const section = hooks.slice(at, end === -1 ? undefined : end).replace(/\s+/g, ' ');
    const sameReading = section.split(/(?<=[.!?])\s+/).some((s) => GROUP_GD.test(s) && APART_G_D.test(s));
    expect({ neverGlobal: section.includes('a cluster that holds a `g` is never read as global'), sameReading }).toEqual({
      neverGlobal: false,
      sameReading: true,
    });
  });

  it('T-08 the record project-default-registry no longer names "a short cluster such as `-gD`", and names `-gL project` and `-global`; the generated page has it', () => {
    const limit = loadKnownLimits().find((l) => l.id === 'project-default-registry');
    expect(limit, 'the record project-default-registry').toBeDefined();
    const doc = limit?.doc ?? '';
    expect({ cluster: doc.includes('a short cluster such as `-gD`'), gLProject: doc.includes('-gL project'), oneDashGlobal: ONE_DASH_GLOBAL.test(doc) }).toEqual({
      cluster: false,
      gLProject: true,
      oneDashGlobal: true,
    });
    expect(flat(read('docs/hooks-known-limits.md')), REGENERATE).toContain(flat(doc));
  });

  it('T-08 a record npm-short-flag-groups (install-vetting) names `-global`, `-local` and the groups inside the launchers, with its two examples; the generated page has it', () => {
    const limit = loadKnownLimits().find((l) => l.id === 'npm-short-flag-groups');
    expect(limit, 'a record with the id npm-short-flag-groups in mcp/test/fixtures/hooks/known-limits.yml').toBeDefined();
    if (limit === undefined) return;
    expect(limit.area).toBe('install-vetting');
    expect({ oneDashGlobal: ONE_DASH_GLOBAL.test(limit.doc), oneDashLocal: ONE_DASH_LOCAL.test(limit.doc), launchers: /\blaunchers?\b/i.test(limit.doc) }).toEqual({
      oneDashGlobal: true,
      oneDashLocal: true,
      launchers: true,
    });
    // The harness runs offline: the hook says what it could not verify, a warning.
    const examples = limit.examples.flatMap((e) => (e.detector === 'hook' ? [{ command: e.input['command'], decision: e.expect.decision }] : []));
    expect(examples).toEqual(
      expect.arrayContaining([
        { command: 'npm install -global dgprobe-zzq7731', decision: 'warn' },
        { command: 'npx -yL global dgprobe-zzq7731', decision: 'warn' },
      ]),
    );
    expect(flat(read('docs/hooks-known-limits.md')), REGENERATE).toContain(flat(limit.doc));
  });
});

// ───────────────── install-vet-inline-script-deps — the docs say that `uv run` and `pipx run` read a script's inline dependencies

describe('install-vet-inline-script-deps', () => {
  /** A paragraph of docs/hooks.md, from its bold lead to the next blank line. */
  const paragraph = (lead: string): string => {
    const para = read('docs/hooks.md')
      .split(/\n\s*\n/)
      .find((p) => p.startsWith(lead));
    return (para ?? '').replace(/\s+/g, ' ');
  };

  it('T-11 the "When" cell of the SECURITY.md row of the public registries names PEP 723, `uv run`, `pipx run` and `--with`', () => {
    const row = read('SECURITY.md')
      .split('\n')
      .find((line) => line.startsWith('| `registry.npmjs.org`, `pypi.org`'));
    expect(row, 'the egress row of the public registries').toBeDefined();
    // | Destination | Who contacts it | When |: the third cell. The symbols carry their code ticks, so today's text does not match by chance.
    const when = (row ?? '').split(' | ')[2] ?? '';
    expect({
      pep723: when.includes('PEP 723'),
      uvRun: when.includes('`uv run`'),
      pipxRun: when.includes('`pipx run`'),
      withFlag: when.includes('`--with`'),
    }).toEqual({ pep723: true, uvRun: true, pipxRun: true, withFlag: true });
  });

  it('T-11 the paragraph "What leaves the machine." of docs/hooks.md names PEP 723 and `uv run --with`', () => {
    const para = paragraph('**What leaves the machine.**');
    expect(para, 'the paragraph "What leaves the machine."').not.toBe('');
    expect({ pep723: para.includes('PEP 723'), uvRunWith: para.includes('`uv run --with`') }).toEqual({ pep723: true, uvRunWith: true });
  });

  it('T-11 the paragraph "Past a ceiling the user is asked." of docs/hooks.md says that the inline dependencies of a script are asked about too', () => {
    const para = paragraph('**Past a ceiling the user is asked.**');
    expect(para, 'the paragraph "Past a ceiling the user is asked."').not.toBe('');
    expect(para).toContain('inline dependencies');
  });
});

// ───────────────── install-vet-registry-files-unread — the docs say what the code reads (red until the fix)

describe('install-vet-registry-files-unread', () => {
  /** The sentences of a text, its line breaks folded: a sentence ends at a full stop, `!` or `?` and a space. */
  const sentences = (text: string): string[] => text.replace(/\s+/g, ' ').split(/(?<=[.!?])\s+/);
  const said = (text: string, parts: Array<string | RegExp>): boolean =>
    sentences(text).some((s) => parts.every((p) => (typeof p === 'string' ? s.includes(p) : p.test(s))));

  const hooksSection = (): string => {
    const hooks = read('docs/hooks.md');
    const at = hooks.indexOf('## Install-time package vetting');
    expect(at, 'the section "Install-time package vetting"').toBeGreaterThan(-1);
    const end = hooks.indexOf('\n## ', at + 1);
    return hooks.slice(at, end === -1 ? undefined : end);
  };
  const limitRecord = (): string => {
    const page = read('docs/hooks-known-limits.md');
    const start = page.indexOf('When a file of the project sets the default registry');
    expect(start, 'the record project-default-registry').toBeGreaterThan(-1);
    const stop = page.indexOf('The line is added to an install that is vetted', start);
    return page.slice(start, stop === -1 ? undefined : stop);
  };

  const HOOKS_SENTENCES: Array<[what: string, parts: Array<string | RegExp>]> = [
    ['the bun reads a .env, by NODE_ENV, for BUN_CONFIG_REGISTRY', ['bun', '.env', 'NODE_ENV', 'BUN_CONFIG_REGISTRY']],
    ['[install.registry] of the bunfig.toml is read', ['[install.registry]']],
    ['pipx does not count the uv.toml of the project', ['pipx', 'uv.toml', /not count|does not|never/]],
    ['a withdrawn malicious name stays refused with a registry only a project file configures', ['malicious', /refus/, /only a file of the project|project file/]],
  ];

  it.each(HOOKS_SENTENCES)('T-07 docs/hooks.md, install-time vetting: %s', (_what, parts) => {
    expect(said(hooksSection(), parts)).toBe(true);
  });

  it('T-07 SECURITY.md says the hook reads only the registry variables of a .env, and that the host reaches the model', () => {
    expect(said(read('SECURITY.md'), ['.env', /only/, 'host', 'model'])).toBe(true);
  });

  const LIMIT_SENTENCES: Array<[what: string, parts: Array<string | RegExp>]> = [
    ['the NODE_ENV of the shell, which the hook does not see', ['NODE_ENV', 'shell']],
    ['the env of .claude/settings.json (EC-14)', ['.claude/settings.json', 'env']],
    ['the line of the bunfig.toml or .npmrc that loses to the .env is still said', ['bunfig.toml', '.npmrc', '.env', /still/]],
  ];

  it.each(LIMIT_SENTENCES)('T-07 the record project-default-registry of docs/hooks-known-limits.md says %s', (_what, parts) => {
    expect(said(limitRecord(), parts)).toBe(true);
  });
});

// ───────────────── pkgvet-archive-names-pipx-composer — the docs say what the pipx and the composer were measured to read

describe('pkgvet-archive-names-pipx-composer', () => {
  /** The sentences of a hard-wrapped page, each on one line: a blank line, a list item, a table row and a full stop before white space end one. */
  const sentences = (text: string): string[] =>
    text
      .replace(/\r\n/g, '\n')
      .split(/\n\s*\n|\n(?=\s*(?:[-*]|\d+\.)\s)|\n(?=\|)/)
      .flatMap((block) => block.replace(/\s+/g, ' ').trim().split(/(?<=[.!?])\s+/))
      .filter((s) => s !== '');

  const TWELVE = ['.zip', '.whl', '.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz', '.tar.xz', '.txz', '.tlz', '.tar.lz', '.tar.lzma'];
  const OLD_SENTENCE = 'pipx, composer and dotnet were not measured';

  it('T-08 docs/hooks.md says what the pipx and the composer read as a file, and that only the dotnet was not measured', () => {
    const hooks = read('docs/hooks.md');
    const at = hooks.indexOf('## Install-time package vetting');
    expect(at, 'the "Install-time package vetting" section of docs/hooks.md').toBeGreaterThan(-1);
    const end = hooks.indexOf('\n## ', at + 1);
    const lines = sentences(hooks.slice(at, end === -1 ? undefined : end));
    const code = (s: string, endings: readonly string[]): boolean => endings.every((e) => s.includes(`\`${e}\``));

    const found = {
      'pipx: the twelve endings between backticks, and the word "file"': lines.some((s) => /\bpipx\b/.test(s) && code(s, TWELVE) && /\bfile\b/.test(s)),
      'composer: .zip and .tar.gz between backticks': lines.some((s) => /\bcomposer\b/.test(s) && code(s, ['.zip', '.tar.gz'])),
      'dotnet: not measured': lines.some((s) => /\bdotnet\b/.test(s) && /not measured/.test(s)),
      'no sentence says "pipx, composer and dotnet were not measured"': !lines.some((s) => s.includes(OLD_SENTENCE)),
    };
    expect(found).toEqual({
      'pipx: the twelve endings between backticks, and the word "file"': true,
      'composer: .zip and .tar.gz between backticks': true,
      'dotnet: not measured': true,
      'no sentence says "pipx, composer and dotnet were not measured"': true,
    });
  });

  it('T-08 the record archive-like-names says what was measured and where, and runs the examples of the new readings; the generated page has its text', () => {
    const limit = loadKnownLimits().find((l) => l.id === 'archive-like-names');
    expect(limit, 'a record with the id archive-like-names in mcp/test/fixtures/hooks/known-limits.yml').toBeDefined();
    if (limit === undefined) return;
    const runs = (command: string, decision: string): boolean =>
      limit.examples.some((e) => e.detector === 'hook' && e.input.command === command && e.expect.decision === decision);
    const found = {
      'the text says pipx': /\bpipx\b/.test(limit.doc),
      'the text says measured': /\bmeasured\b/.test(limit.doc),
      'the text names Linux': /\bLinux\b/.test(limit.doc),
      'the text names Windows': /\bWindows\b/.test(limit.doc),
      'pipx install thing.zip: none': runs('pipx install thing.zip', 'none'),
      'pipx run thing.zip: none': runs('pipx run thing.zip', 'none'),
      'cd "$D" && pipx run thing.zip: warn': runs('cd "$D" && pipx run thing.zip', 'warn'),
      'pipx install --force thing.zip: warn': runs('pipx install --force thing.zip', 'warn'),
      'composer require vendor/thing.whl: warn': runs('composer require vendor/thing.whl', 'warn'),
      'the generated page has the text': read('docs/hooks-known-limits.md').includes(limit.doc.trim()),
    };
    expect(found).toEqual({
      'the text says pipx': true,
      'the text says measured': true,
      'the text names Linux': true,
      'the text names Windows': true,
      'pipx install thing.zip: none': true,
      'pipx run thing.zip: none': true,
      'cd "$D" && pipx run thing.zip: warn': true,
      'pipx install --force thing.zip: warn': true,
      'composer require vendor/thing.whl: warn': true,
      'the generated page has the text': true,
    });
  });
});

// ───────────────── llm-scan-codex-smoke-findings — the versioned documents say what the server does

describe('llm-scan-codex-smoke-findings', () => {
  /** The blocks of a page (split on blank lines), white space collapsed to single spaces. */
  const blocks = (text: string): string[] =>
    text
      .replace(/\r\n/g, '\n')
      .split(/\n\s*\n/)
      .map((block) => block.replace(/\s+/g, ' ').trim());

  /** The sentences of a page, each on one line. */
  const sentencesOf = (text: string): string[] => blocks(text).flatMap((block) => block.split(/(?<=[.!?])\s+/)).filter((s) => s !== '');

  it('T-06 docs/llm-scan.md says that confirm never raises the limit, what the plan record says, why nothing_to_plan and where the Codex run stands', () => {
    const page = read('docs/llm-scan.md').replace(/\r\n/g, '\n');
    const confirmParagraph = blocks(page).find((b) => b.startsWith('**`confirm` opens the gate')) ?? '';
    const recordStart = page.indexOf("## The plan's scan record");
    const recordEnd = page.indexOf('\n## ', recordStart + 1);
    const recordSection = recordStart === -1 ? '' : page.slice(recordStart, recordEnd === -1 ? undefined : recordEnd);
    const nothingToPlanRow = page.split('\n').find((line) => line.startsWith('| `nothing_to_plan`')) ?? '';
    const runParagraph = blocks(page).find((b) => b.startsWith('Run end to end on a real host so far')) ?? '';

    const found = {
      'the confirm paragraph exists': confirmParagraph !== '',
      'the confirm paragraph says new plan': confirmParagraph.includes('new plan'),
      'the confirm paragraph says without `plan_id`': confirmParagraph.includes('without `plan_id`'),
      'the confirm paragraph no longer says start again': !confirmParagraph.includes('start again'),
      'the plan record section names verify_source': recordSection.includes('verify_source'),
      'the nothing_to_plan row says open set': nothingToPlanRow.includes('open set'),
      'the nothing_to_plan row says scoped': nothingToPlanRow.includes('scoped'),
      'the run paragraph names Codex': runParagraph.includes('Codex'),
      'the run paragraph names 2026-11-19': runParagraph.includes('2026-11-19'),
      'the run paragraph names reservations': runParagraph.includes('reservations'),
    };
    expect(found).toEqual({
      'the confirm paragraph exists': true,
      'the confirm paragraph says new plan': true,
      'the confirm paragraph says without `plan_id`': true,
      'the confirm paragraph no longer says start again': true,
      'the plan record section names verify_source': true,
      'the nothing_to_plan row says open set': true,
      'the nothing_to_plan row says scoped': true,
      'the run paragraph names Codex': true,
      'the run paragraph names 2026-11-19': true,
      'the run paragraph names reservations': true,
    });
  });

  it('T-06 docs/hosts.md says that the project .codex/config.toml was not loaded by Codex CLI 0.165.0 and that -c mcp_servers worked', () => {
    const sentence = sentencesOf(read('docs/hosts.md')).find((s) => s.includes('Codex CLI 0.165.0')) ?? '';
    expect({
      'a sentence names Codex CLI 0.165.0': sentence !== '',
      'it names .codex/config.toml': sentence.includes('.codex/config.toml'),
      'it names -c mcp_servers': sentence.includes('-c mcp_servers'),
    }).toEqual({
      'a sentence names Codex CLI 0.165.0': true,
      'it names .codex/config.toml': true,
      'it names -c mcp_servers': true,
    });
  });
});

// ───────────────── known-limits-doc-markdownlint — the page keeps the list layout markdownlint accepts

describe('known-limits-doc-markdownlint', () => {
  const pageOf = (): string => renderKnownLimitsDoc(loadKnownLimits());
  /** The generator writes a record as a single block when its text has no line break. */
  const multiBlock = (limit: { doc: string }): boolean => limit.doc.trim().includes('\n');
  /** A problem without its explanation: `"<line>: <rule>"`. */
  const brief = (problems: string[]): string[] =>
    problems.map((p) => p.split(' ').slice(0, p.includes(': not modelled') ? 3 : 2).join(' '));

  it('T-03 (a) a sample in the layout of the page before the fix is refused with MD005 and MD032', () => {
    const rules = brief(listProblems('## A\n\n- one\n\n- inner\n\nclosing\n  - ex\n- two\n'));
    expect(rules).toEqual(['7: MD005', '8: MD032']);
  });

  // [name, text, line, rule]: the rule and the line the check names.
  const refused: [string, string, number, string][] = [
    ['a space at the end of a line (markdownlint: MD009)', '## A\n\n- one \n', 3, 'MD009'],
    ['two blank lines in a row (markdownlint: MD012)', '## A\n\n\n- one\n', 3, 'MD012'],
    ['two newlines at the end (markdownlint: MD012)', '## A\n\n- one\n\n', 4, 'MD012'],
    ['no newline at the end (markdownlint: MD047)', '## A\n\n- one', 3, 'MD047'],
    ['an item at 4 spaces (markdownlint: MD007)', '## A\n\n- one\n    - deep\n', 4, 'MD007'],
    ['an item at 2 spaces outside an item (markdownlint: MD007)', '## A\n\n  - stray\n', 3, 'MD007'],
    ['an item glued to a paragraph at column 0 (markdownlint: MD032)', '## A\n\npara\n- one\n', 4, 'MD032'],
    ['an item at 2 spaces glued to a paragraph of the item (only this check refuses it)', '## A\n\n- one\n\n  para\n  - ex\n', 6, 'MD032'],
    ['a paragraph of the item glued to an item at 2 spaces (only this check refuses it)', '## A\n\n- one\n  - ex\n  para\n', 5, 'MD032'],
    ['a line at column 0 glued to two items of a section (only this check refuses it)', '## A\n\n- one\nloose\n- two\n', 4, 'MD005'],
    ['a line at column 0 between two lists separated by blank lines (not measured with markdownlint)', '## A\n\n- one\n\nloose\n\n- two\n', 5, 'MD005'],
  ];
  for (const [name, text, line, rule] of refused) {
    it(`T-03 (b) refuses ${name}`, () => {
      expect(brief(listProblems(text))).toEqual([`${String(line)}: ${rule}`]);
    });
  }

  // The shapes the check does not model: refused, with their line and the words "not modelled".
  const notModelled: [string, string, number][] = [
    ['a ``` line', '## A\n\n```\n', 3],
    ['a ~~~ line', '## A\n\n~~~\n', 3],
    ['an ordered item', '## A\n\n1. one\n', 3],
    ['an item that starts with "*"', '## A\n\n* one\n', 3],
    ['an item that starts with "+"', '## A\n\n+ one\n', 3],
    ['a "-" followed by two spaces', '## A\n\n-  one\n', 3],
    ['a heading inside an item', '## A\n\n- one\n\n  ### inner\n', 5],
  ];
  for (const [name, text, line] of notModelled) {
    it(`T-03 (b) says it does not model ${name}`, () => {
      expect(brief(listProblems(text))).toEqual([`${String(line)}: not modelled`]);
    });
  }

  it('T-03 (c) passes a record of one block with two examples, and a record of several blocks with examples and without them', () => {
    const passing = {
      'one block': '## A\n\n- doc\n  - ex1\n  - ex2\n- doc2\n',
      'several blocks with examples': '## A\n\n- first\n\n  - stays 1\n  - stays 2\n\n  Examples:\n\n  - ex1\n- next\n',
      'several blocks without examples': '## A\n\n- first\n\n  - stays 1\n\n  No test runs it: why.\n- next\n',
    };
    expect(Object.fromEntries(Object.entries(passing).map(([name, text]) => [name, listProblems(text)]))).toEqual({
      'one block': [],
      'several blocks with examples': [],
      'several blocks without examples': [],
    });
  });

  it('T-04 (a) a record of one block with examples keeps its item, its example lines at two spaces and its reason, with no blank line between', () => {
    const lines = pageOf().split('\n');
    const failing: string[] = [];
    for (const limit of loadKnownLimits().filter((l) => !multiBlock(l) && l.examples.length > 0)) {
      const at = lines.indexOf(`- ${limit.doc.trim()}`);
      const count = limit.examples.length + (limit.not_executable !== undefined ? 1 : 0);
      const after = lines.slice(at + 1, at + 1 + count);
      const next = lines[at + 1 + count];
      const ok = at >= 0 && after.length === count && after.every((l) => l.startsWith('  - ')) && (next === '' || next?.startsWith('- ') === true);
      if (!ok) failing.push(limit.id);
    }
    expect(failing).toEqual([]);
  });

  it('T-04 (b) the page and the committed page hold the text of every record, with white space joined', () => {
    const page = flat(pageOf());
    const committed = flat(read('docs/hooks-known-limits.md'));
    const missing = loadKnownLimits().flatMap((l) => [
      ...(page.includes(flat(l.doc)) ? [] : [`${l.id} (generated)`]),
      ...(committed.includes(flat(l.doc)) ? [] : [`${l.id} (committed)`]),
    ]);
    expect(missing).toEqual([]);
  });

  it('T-04 (c) the page keeps the titles of its sections in the order of the areas and the introduction with the counts', () => {
    const limits = loadKnownLimits();
    const lines = pageOf().split('\n');
    const used = LIMIT_AREAS.filter((area) => limits.some((l) => l.area === area));
    expect(lines.filter((line) => line.startsWith('## '))).toEqual(used.map((area) => `## ${AREA_TITLES[area]}`));
    const counts = executableCounts(limits);
    const intro = lines.find((line) => line.startsWith('This page is rendered from')) ?? '';
    expect(intro.startsWith(`This page is rendered from [\`${KNOWN_LIMITS_SOURCE}\`](../${KNOWN_LIMITS_SOURCE}): **${String(counts.total)} limits**, `)).toBe(true);
    expect(intro).toContain(`${String(counts.withExample)} with at least one example and ${String(counts.without)} with none, which says why.`);
  });

  /** The text of the reason line of a record: the reason with a single full stop at the end. */
  const reasonLine = (limit: { examples: readonly unknown[]; not_executable?: string | undefined }): string => {
    const reason = (limit.not_executable ?? '').trim();
    return `${limit.examples.length === 0 ? 'No test runs it' : 'What no test runs'}: ${reason}${reason.endsWith('.') ? '' : '.'}`;
  };

  it('T-01 the generated page and the committed page pass the list check', () => {
    const problems = { generated: listProblems(pageOf()), committed: listProblems(read('docs/hooks-known-limits.md')) };
    expect(problems.generated, `generated page:\n${problems.generated.join('\n')}`).toEqual([]);
    expect(problems.committed, `committed page:\n${problems.committed.join('\n')}`).toEqual([]);
  });

  it('T-02 (a) every section has one top-level item per record of its area', () => {
    const limits = loadKnownLimits();
    const lines = pageOf().split('\n');
    const wrong: string[] = [];
    for (const area of LIMIT_AREAS) {
      const records = limits.filter((l) => l.area === area).length;
      if (records === 0) continue;
      const start = lines.indexOf(`## ${AREA_TITLES[area]}`);
      const rest = lines.slice(start + 1);
      const end = rest.findIndex((line) => line.startsWith('## '));
      const items = (end === -1 ? rest : rest.slice(0, end)).filter((line) => line.startsWith('- ')).length;
      if (items !== records) wrong.push(`${AREA_TITLES[area]}: ${String(items)} items for ${String(records)} records`);
    }
    expect(wrong).toEqual([]);
  });

  it('T-02 (b) a record of several blocks keeps its lines at two spaces, then "Examples:", its examples and its reason', () => {
    const lines = pageOf().split('\n');
    const wrong: string[] = [];
    for (const limit of loadKnownLimits().filter(multiBlock)) {
      const docLines = limit.doc.trim().split('\n');
      const at = lines.indexOf(`- ${docLines[0] ?? ''}`);
      const expected = docLines.slice(1).map((line) => (line === '' ? '' : `  ${line}`));
      const hasReason = limit.not_executable !== undefined;
      const exampleCount = limit.examples.length;
      if (exampleCount > 0) expected.push('', '  Examples:', '');
      else if (hasReason) expected.push('');
      const start = at + 1;
      const doc = lines.slice(start, start + expected.length);
      const exampleLines = lines.slice(start + expected.length, start + expected.length + exampleCount);
      const reasonAt = start + expected.length + exampleCount;
      const reason = hasReason ? (exampleCount > 0 ? `  - ${reasonLine(limit)}` : `  ${reasonLine(limit)}`) : undefined;
      const next = lines[reasonAt + (reason === undefined ? 0 : 1)];
      const ok =
        at >= 0 &&
        JSON.stringify(doc) === JSON.stringify(expected) &&
        exampleLines.length === exampleCount &&
        exampleLines.every((line) => line.startsWith('  - ')) &&
        (reason === undefined || lines[reasonAt] === reason) &&
        (next === '' || next?.startsWith('- ') === true);
      if (!ok) wrong.push(limit.id);
    }
    expect(wrong).toEqual([]);
  });

  it('T-02 (c) the reason of every record ends with a single full stop', () => {
    const lines = pageOf().split('\n');
    const wrong: string[] = [];
    for (const limit of loadKnownLimits().filter((l) => l.not_executable !== undefined)) {
      const indent = !multiBlock(limit) || limit.examples.length > 0 ? '  - ' : '  ';
      if (!lines.includes(`${indent}${reasonLine(limit)}`)) wrong.push(limit.id);
    }
    expect(wrong).toEqual([]);
  });

  it('T-02 (d) a record of two lines with no blank line between them keeps the second line in the item, then "Examples:"', () => {
    const example = loadKnownLimits().flatMap((l) => l.examples)[0];
    expect(example, 'an example of a real record').toBeDefined();
    if (example === undefined) return;
    const page = renderKnownLimitsDoc([{ id: 'synthetic', area: 'install-vetting', doc: 'one\ntwo', examples: [example] }]);
    const lines = page.split('\n');
    const at = lines.indexOf('- one');
    expect({ shape: lines.slice(at, at + 5), example: lines[at + 5]?.startsWith('  - ') === true, problems: listProblems(page) }).toEqual({
      shape: ['- one', '  two', '', '  Examples:', ''],
      example: true,
      problems: [],
    });
  });
});

// ───────────────── install-vet-with-requirements-directory-link — what the documentation says of where the requirements file is read

describe('install-vet-with-requirements-directory-link', () => {
  it('T-06 docs/hooks.md: the sentence on where the script is looked for says the file of `uv run --with-requirements` is, and that a `..` after a link reads both paths', () => {
    const paragraph = read('docs/hooks.md')
      .split('\n')
      .find((line) => line.startsWith('**The inline script block.**'));
    expect(paragraph, 'the "The inline script block." paragraph of docs/hooks.md').toBeDefined();
    const text = flat(paragraph ?? '');
    const at = text.indexOf('The script is looked for');
    expect(at, 'the sentence "The script is looked for …" in that paragraph').toBeGreaterThan(-1);
    const sentence = text.slice(at, text.indexOf('. ', at) + 1);
    expect({ requirements: sentence.includes('`--with-requirements`'), dotdot: sentence.includes('`..`') }).toEqual({ requirements: true, dotdot: true });
  });

  it('T-06 docs/hooks-known-limits.md carries the text of the install-inline-script-deps record, with `tools/../r.txt` and `pip install -r` (whitespace joined)', () => {
    const limit = loadKnownLimits().find((l) => l.id === 'install-inline-script-deps');
    expect(limit, 'the record install-inline-script-deps').toBeDefined();
    const page = flat(read('docs/hooks-known-limits.md'));
    const doc = flat(limit?.doc ?? '');
    expect({
      pageHasRecord: doc !== '' && page.includes(doc),
      recordNamesDotdotWord: doc.includes('tools/../r.txt'),
      recordNamesPip: doc.includes('pip install -r'),
      pageNamesDotdotWord: page.includes('tools/../r.txt'),
    }).toEqual({ pageHasRecord: true, recordNamesDotdotWord: true, recordNamesPip: true, pageNamesDotdotWord: true });
  });
});

// ───────────────── install-vet-uv-run-project-index — the docs say the line `uv run` gets and what the managers do not obey

describe('install-vet-uv-run-project-index', () => {
  const paragraph = (start: string): string => {
    const found = read('docs/hooks.md')
      .split('\n')
      .find((line) => line.startsWith(start));
    expect(found, `the "${start}" paragraph of docs/hooks.md`).toBeDefined();
    return flat(found ?? '');
  };
  const recordDoc = (id: string): string => {
    const limit = loadKnownLimits().find((l) => l.id === id);
    expect(limit, `the record ${id}`).toBeDefined();
    return flat(limit?.doc ?? '');
  };

  it('T-05 docs/hooks.md "The inline script block." says the line ("sets the package index") and where the search starts ("beside the script")', () => {
    const text = paragraph('**The inline script block.**');
    expect({ line: text.includes('sets the package index'), beside: text.includes('beside the script') }).toEqual({ line: true, beside: true });
  });

  it('T-05 docs/hooks.md "The files a manager does not obey." names `uv run`, and a script given to `pipx run` is no longer one of "Every other pair"', () => {
    const text = paragraph('**The files a manager does not obey.**');
    const at = text.indexOf('Every other pair');
    expect(at, 'the sentence "Every other pair …"').toBeGreaterThan(-1);
    const sentence = text.slice(at, text.indexOf('. ', at) + 1);
    expect({ namesUvRun: text.includes('`uv run`'), scriptListed: sentence.includes('a script given to `pipx run`') }).toEqual({
      namesUvRun: true,
      scriptListed: false,
    });
  });

  it('T-05 docs/hooks-known-limits.md carries the project-default-registry record, with `uv run` and with no script given to `pipx run` (whitespace joined)', () => {
    const page = flat(read('docs/hooks-known-limits.md'));
    const doc = recordDoc('project-default-registry');
    const lines = (loadKnownLimits().find((l) => l.id === 'project-default-registry')?.doc ?? '').split('\n');
    expect({
      pageHasRecord: doc !== '' && page.includes(doc),
      namesUvRun: lines.some((line) => line.includes('gives PyPI') && line.includes('`uv run`')),
      scriptListed: page.includes('a script given to `pipx run`'),
    }).toEqual({
      pageHasRecord: true,
      namesUvRun: true,
      scriptListed: false,
    });
  });

  it('T-05 docs/hooks-known-limits.md carries the install-inline-script-deps record, with "above the repository root" and no "is not read (`install-vet-registry-files-unread`)" (whitespace joined)', () => {
    const page = flat(read('docs/hooks-known-limits.md'));
    const doc = recordDoc('install-inline-script-deps');
    expect({
      pageHasRecord: doc !== '' && page.includes(doc),
      namesRoot: page.includes('above the repository root') && doc.includes('above the repository root'),
      saysNotRead: page.includes('is not read (`install-vet-registry-files-unread`)'),
    }).toEqual({ pageHasRecord: true, namesRoot: true, saysNotRead: false });
  });
});
