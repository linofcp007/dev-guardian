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
    const undocumented = [...names].filter((n) => !new RegExp(`\`${n}\``).test(env)).sort();
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
