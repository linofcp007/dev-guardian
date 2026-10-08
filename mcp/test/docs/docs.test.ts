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
 *   - every tool, resource, skill and command count the READMEs, CLAUDE.md
 *     and `mcp/README.md` state equals the registry / the tree — a stale
 *     count anywhere in those files fails, not only the first one;
 *   - CLAUDE.md's rule-pack table and its totals equal the pack files, as the
 *     ablation harness itself enumerates them;
 *   - `docs/env.md` names every `GUARDIAN_*` environment variable the code
 *     reads.
 */

import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';

import type { ResourceModule } from '../../src/resources/index.js';
import type { ToolModule } from '../../src/tools/index.js';
import { noClauseKind, PACK_CONSUMERS, packTotals, renderRulePacksDoc, renderToolsDoc, type PackInput } from './renderDocs.js';
import { DOCS_DIR, loadPacks, loadRegistry, REPO_ROOT } from './sources.js';

let tools: readonly ToolModule[];
let resources: readonly ResourceModule[];
let packs: PackInput[];

beforeAll(async () => {
  ({ tools, resources } = await loadRegistry());
  packs = loadPacks();
});

function read(rel: string): string {
  return readFileSync(resolve(REPO_ROOT, rel), 'utf8');
}

const REGENERATE = 'run `npm run build` in mcp/ to regenerate it — never edit a generated page by hand';

describe('generated reference pages', () => {
  it('docs/tools.md is what the registry renders to', () => {
    expect(read('docs/tools.md'), REGENERATE).toBe(renderToolsDoc(tools, resources));
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

/** Hand-written pages under docs/: any count they state must be right too. */
function handWrittenDocs(): string[] {
  return readdirSync(DOCS_DIR)
    .filter((f) => f.endsWith('.md') && f !== 'tools.md' && f !== 'rule-packs.md')
    .map((f) => `docs/${f}`);
}

function statedCounts(text: string, c: CountSpec): number[] {
  return [c.re, ...(c.heading !== undefined ? [c.heading] : [])].flatMap((re) =>
    [...text.matchAll(re)].map((m) => Number(m[1])),
  );
}

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

// -------------------------------------------------------- CLAUDE.md packs

describe("CLAUDE.md's rule-pack table", () => {
  const TABLE_ROW = /^\|\s*`([a-z0-9-]+)`\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*$/;

  function tableRows(): Map<string, [number, number, number]> {
    const lines = read('CLAUDE.md').split(/\r?\n/);
    const header = lines.findIndex((l) => /^\|\s*pack\s*\|\s*rules\s*\|\s*with ablatable clauses\s*\|\s*with none\s*\|/i.test(l));
    expect(header, 'CLAUDE.md has the "| pack | rules | with ablatable clauses | with none |" table').toBeGreaterThanOrEqual(0);
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
    const text = read('CLAUDE.md');
    const t = packTotals(packs);
    const ofTheRules = [...text.matchAll(/\*\*(\d+) of the (\d+) rules\*\*/g)].map((m) => [Number(m[1]), Number(m[2])]);
    expect(ofTheRules.length).toBeGreaterThan(0);
    for (const pair of ofTheRules) expect(pair).toEqual([t.withNone, t.rules]);
    const split = [...text.matchAll(/(\d+) bare and (\d+) positive-only/g)].map((m) => [Number(m[1]), Number(m[2])]);
    expect(split.length).toBeGreaterThan(0);
    for (const pair of split) expect(pair).toEqual([t.bare, t.positiveOnly]);
  });
});

// ------------------------------------------------------------- docs/env.md

/** Where environment variables are read: runtime code, and the developer tooling. */
const ENV_SOURCES = ['mcp/src', 'hooks', 'cli', 'mcp/test/ablate', 'mcp/test/evals', 'mcp/test/helpers', 'mcp/test/setup', 'mcp/vitest.config.ts'];

/** `GUARDIAN_*` tokens that are identifiers, not environment variables. */
const NOT_ENV_VARS = new Set(['GUARDIAN_IGNORE_FILE']);

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
