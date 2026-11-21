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
      expect(page, l.id).toContain(l.doc.trim());
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
    expect(read('docs/hooks-known-limits.md'), REGENERATE).toContain(limit.doc.trim());
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
    expect(read('docs/hooks-known-limits.md'), REGENERATE).toContain(doc.trim());
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
    expect(read('docs/hooks-known-limits.md'), REGENERATE).toContain(limit.doc.trim());
  });
});
