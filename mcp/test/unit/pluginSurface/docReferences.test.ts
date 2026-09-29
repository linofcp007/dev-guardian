/**
 * The plugin's slash commands and skills against the MCP surface they drive.
 *
 * Everything a command or skill tells the model to call is prose, and prose
 * drifts silently: a renamed tool, a parameter that never existed, a command
 * that points at a command that was removed. Each of those reads fine to a
 * reviewer and fails only when a user runs it. So this file holds the prose to
 * the registered zod schemas:
 *
 *   - `commands/` is exactly the ten consolidated commands, and none of them
 *     shares a name with a skill — a command named like a skill shadows it,
 *     and nine skills were unreachable that way (the command said "invoke the
 *     X skill", the model found X already loaded, and looped);
 *   - every `tool { key: … }` / `tool(key=…)` call names a registered tool,
 *     only parameters its schema has (nested `scope.diff.base` included),
 *     only enum values the schema allows, and every parameter it requires;
 *   - every `guardian://` resource named is a registered resource;
 *   - every backticked tool-shaped identifier is a tool or a parameter;
 *   - every `/command` a command, skill or hook message points at exists;
 *   - every `${CLAUDE_PLUGIN_ROOT}/…` path exists;
 *   - every `.guardian/budgets.yml` example is a file `loadBudgets` accepts.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { ZodTypeAny } from 'zod';
import { loadBudgets } from '../../../src/budgets/budgets.js';
import { RESOURCES } from '../../../src/resources/index.js';
import { TOOL_CATALOG } from '../../../src/runners/installCatalog.js';
import { TOOLS } from '../../../src/tools/index.js';
import { cleanupTempDirs, makeTempDir } from '../../helpers/tempDir.js';
import {
  REPO_ROOT,
  allDocs,
  commandDocs,
  enumValues,
  inlineCode,
  objectShape,
  skillDocs,
  toolCalls,
  type PluginDoc,
} from './pluginDocs.js';

beforeAll(async () => {
  await import('../../../src/registerAll.js');
});
afterAll(cleanupTempDirs);

/** The consolidated command set (full-review Task 14). Binding: change it deliberately. */
const EXPECTED_COMMANDS = [
  'g',
  'guardian-dotnet',
  'guardian-fix',
  'guardian-incident',
  'guardian-infra',
  'guardian-release',
  'guardian-report',
  'guardian-scan',
  'guardian-status',
  'guardian-wp',
];

/**
 * Plugin-root paths the docs may name before they exist, each with the task
 * that creates it. Everything else a doc names under `${CLAUDE_PLUGIN_ROOT}`
 * must be on disk.
 */
const NOT_YET_SHIPPED = new Set<string>([]);

/**
 * Backticked identifiers that look like a tool (they start with a tool's first
 * word) but name a RESULT field, not an input or an enum value. Keep it short:
 * a name added here is one the test can no longer tell from a typo'd tool.
 */
const RESULT_FIELDS = new Set<string>([]);

/** Strings that were false in the docs this task rewrote, and must not come back. */
const DEAD_REFERENCES: readonly [RegExp, string][] = [
  [/ai-product-spec-scale/, 'a skill that does not exist'],
  [/configs\/grafana/, 'a directory that does not exist'],
  [/perf-budget\.yml/, 'a budget file nothing reads — budgets live in .guardian/budgets.yml'],
  [/\bfid_ms\b|\bFID_ms\b/, 'FID was retired as a Core Web Vital; the budget field is perf.inp_ms'],
  [/\bcpf\b/i, 'a Brazilian id; the PT identifiers are NIF, NISS and Cartão de Cidadão'],
  [/review-scan\.sh|full-security-scan\.sh|initial-scan\.sh/, 'a shell script in place of the MCP tool'],
  [/WSL2 or fail|falha cedo e indica WSL2|Windows: instruir o utilizador a usar WSL2/, 'install_toolchain supports winget/scoop/choco'],
  [/--include="\*\.\{/, 'a brace glob in --include matches nothing'],
  [
    /Nenhuma tool deteta typosquatting/,
    'vet_packages checks typosquatting, OSV MAL- advisories, publish age and install scripts (review 3.0 I4)',
  ],
  // Review 3.0 M3: scan_sast, security_scan_full and review_pr run the
  // plugin's LLM-application pack (configs/semgrep/llm.yml) on every run.
  [/não há módulo dedicado|there is no dedicated module|Nenhuma tool verifica isto/, 'the LLM pack covers part of it'],
];

let toolByName: Map<string, (typeof TOOLS)[number]>;
/** Every parameter name, at any nesting depth, and every enum value a parameter accepts. */
let allParamNames: Set<string>;
let toolPrefixes: Set<string>;

beforeAll(() => {
  toolByName = new Map(TOOLS.map((t) => [t.name, t]));
  allParamNames = new Set<string>();
  const collect = (shape: Record<string, ZodTypeAny>): void => {
    for (const [k, v] of Object.entries(shape)) {
      allParamNames.add(k);
      for (const value of enumValues(v) ?? []) allParamNames.add(value);
      const nested = objectShape(v);
      if (nested !== null) collect(nested);
    }
  };
  for (const t of TOOLS) collect(t.inputSchema);
  toolPrefixes = new Set(TOOLS.map((t) => t.name.split('_')[0] ?? ''));
});

const isToolShaped = (name: string): boolean => toolPrefixes.has(name.split('_')[0] ?? '');

/** The README and its translations — each lists the commands and resources. */
const READMES = ['README.md', 'README.pt-PT.md', 'README.es.md'];

function docsWithHook(): { rel: string; text: string; checkAliases: boolean }[] {
  const docs = allDocs().map((d) => ({ rel: d.rel, text: d.text, checkAliases: true }));
  // The READMEs document the command set to people who never open commands/.
  for (const rel of READMES) docs.push({ rel, text: readFileSync(resolve(REPO_ROOT, rel), 'utf8'), checkAliases: true });
  const hook = 'hooks/guardian-hook.mjs';
  // The hook is JavaScript: its regex literals end in flags like `/gi`, so only
  // `/guardian…` names are checked there, never the two-letter aliases.
  docs.push({ rel: hook, text: readFileSync(resolve(REPO_ROOT, hook), 'utf8'), checkAliases: false });
  return docs;
}

describe('the command set', () => {
  it('is exactly the ten consolidated commands', () => {
    expect(commandDocs().map((c) => c.name)).toEqual(EXPECTED_COMMANDS);
  });

  it('has no command named like a skill (a command shadows the skill it names)', () => {
    const skills = new Set(skillDocs().map((s) => s.name));
    expect(commandDocs().filter((c) => skills.has(c.name)).map((c) => c.name)).toEqual([]);
  });

  it('every command drives a named MCP tool, or says it is a checklist with no automation', () => {
    const offenders: string[] = [];
    for (const c of commandDocs()) {
      // An alias drives whatever the skill it loads routes to.
      if (/^Alias of the `[a-z-]+` (?:router )?skill\b/m.test(c.body)) continue;
      // A multi-mode command is checked per mode section (`## \`mode\``).
      const sections = c.body.split(/^## `/m);
      const units = sections.length > 1 ? sections.slice(1).map((s) => `## \`${s}`) : [c.body];
      for (const unit of units) {
        const drives = toolCalls(unit, (n) => toolByName.has(n)).length > 0;
        const checklist = /checklist — no automation/i.test(unit);
        if (!drives && !checklist) offenders.push(`${c.rel}: ${unit.split('\n')[0] ?? ''}`);
      }
    }
    expect(offenders).toEqual([]);
  });
});

describe('tool calls in commands and skills', () => {
  const docs = allDocs();

  it.each(docs.map((d) => [d.rel, d] as const))('%s: every call names a registered tool', (_rel, doc) => {
    const unknown = toolCalls(doc.text, isToolShaped)
      .filter((c) => !toolByName.has(c.tool))
      .map((c) => c.snippet);
    expect(unknown).toEqual([]);
  });

  it.each(docs.map((d) => [d.rel, d] as const))(
    '%s: every parameter and enum value exists in the tool schema',
    (_rel, doc: PluginDoc) => {
      const problems: string[] = [];
      for (const call of toolCalls(doc.text, (n) => toolByName.has(n))) {
        const tool = toolByName.get(call.tool);
        if (tool === undefined) continue;
        for (const { path, literals } of call.keys) {
          let shape: Record<string, ZodTypeAny> | null = tool.inputSchema;
          let field: ZodTypeAny | undefined;
          for (const seg of path) {
            field = shape?.[seg];
            if (field === undefined) break;
            shape = objectShape(field);
          }
          if (field === undefined) {
            problems.push(`${call.tool}: no parameter ${path.join('.')} — in ${call.snippet}`);
            continue;
          }
          const allowed = enumValues(field);
          if (allowed === null) continue;
          for (const lit of literals) {
            if (lit.startsWith('<')) continue; // a placeholder, not a value
            if (!allowed.includes(lit)) {
              problems.push(`${call.tool}: ${path.join('.')}="${lit}" not in [${allowed.join(', ')}]`);
            }
          }
        }
      }
      expect(problems).toEqual([]);
    },
  );

  it.each(docs.map((d) => [d.rel, d] as const))(
    '%s: every call passes the parameters the schema requires',
    (_rel, doc: PluginDoc) => {
      const missing: string[] = [];
      for (const call of toolCalls(doc.text, (n) => toolByName.has(n))) {
        const tool = toolByName.get(call.tool);
        if (tool === undefined) continue;
        const named = new Set(call.keys.map((k) => k.path.join('.')));
        // Top-level required keys always; a nested object's required keys
        // only when the call names that object.
        const check = (shape: Record<string, ZodTypeAny>, prefix: string[]): void => {
          for (const [key, field] of Object.entries(shape)) {
            const path = [...prefix, key].join('.');
            if (!field.isOptional() && !named.has(path)) missing.push(`${call.tool}: ${path} — in ${call.snippet}`);
            const nested = objectShape(field);
            if (nested !== null && named.has(path)) check(nested, [...prefix, key]);
          }
        };
        check(tool.inputSchema, []);
      }
      expect(missing).toEqual([]);
    },
  );

  it.each(docs.map((d) => [d.rel, d] as const))(
    '%s: every scanner offered to install_toolchain is in its catalogue',
    (_rel, doc: PluginDoc) => {
      // `tools` is a plain string[] in the schema, so the enum check above
      // cannot see a scanner the catalogue does not have.
      const unknown = toolCalls(doc.text, (n) => n === 'install_toolchain')
        .flatMap((c) => c.keys.filter((k) => k.path.join('.') === 'tools').flatMap((k) => k.literals))
        .filter((name) => !(name in TOOL_CATALOG));
      expect(unknown).toEqual([]);
    },
  );

  it.each(docs.map((d) => [d.rel, d] as const))(
    '%s: every backticked tool-shaped name is a tool or a parameter',
    (_rel, doc) => {
      const unknown = inlineCode(doc.text)
        .map((s) => s.trim())
        .filter((s) => /^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$/.test(s) && isToolShaped(s))
        .filter((s) => !toolByName.has(s) && !allParamNames.has(s) && !RESULT_FIELDS.has(s));
      expect([...new Set(unknown)]).toEqual([]);
    },
  );
});

describe('cross-references', () => {
  it('every /command a command, skill, the README or a hook message names exists', () => {
    const invocable = new Set([...commandDocs().map((c) => c.name), ...skillDocs().map((s) => s.name)]);
    const dangling: string[] = [];
    for (const { rel, text, checkAliases } of docsWithHook()) {
      const re = checkAliases
        ? /(?<![\w/.~-])\/(g[fgiqrs]?|guardian(?:-[a-z0-9]+)*)(?![\w-])/g
        : /(?<![\w/.~-])\/(guardian(?:-[a-z0-9]+)*)(?![\w-])/g;
      for (const m of text.matchAll(re)) {
        const name = m[1] ?? '';
        if (!invocable.has(name)) dangling.push(`${rel}: /${name}`);
      }
    }
    expect([...new Set(dangling)]).toEqual([]);
  });

  it('every guardian:// resource a command, skill or the README names is registered', () => {
    // A registered URI (or template) as a regex: `{?page,page_size}` query
    // templates are optional, `{scan_id}` path params match one segment — and
    // the doc may also spell the template literally.
    const patterns = RESOURCES.map((r) => {
      const base = r.uri.replace(/\{\?[^}]*\}$/, '');
      const source = base
        .split(/(\{[a-z_]+\})/)
        .map((part) => (/^\{[a-z_]+\}$/.test(part) ? '(?:[^/{}]+|\\{[a-z_]+\\})' : part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
        .join('');
      return new RegExp(`^${source}$`);
    });
    const texts = [
      ...allDocs().map((d) => [d.rel, d.text] as const),
      ...READMES.map((rel) => [rel, readFileSync(resolve(REPO_ROOT, rel), 'utf8')] as const),
    ];
    const seen: string[] = [];
    const unknown: string[] = [];
    for (const [rel, text] of texts) {
      for (const m of text.matchAll(/guardian:\/\/[A-Za-z0-9_/{}-]+/g)) {
        const uri = m[0].replace(/[/.]+$/, '');
        seen.push(uri);
        if (!patterns.some((p) => p.test(uri))) unknown.push(`${rel}: ${uri}`);
      }
    }
    expect(seen.length).toBeGreaterThan(0);
    expect([...new Set(unknown)]).toEqual([]);
  });

  it('the router skill lists every command', () => {
    const router = skillDocs().find((s) => s.name === 'guardian');
    expect(router).toBeDefined();
    const missing = EXPECTED_COMMANDS.filter((c) => !(router?.body ?? '').includes(`/${c}`));
    expect(missing).toEqual([]);
  });

  it('every ${CLAUDE_PLUGIN_ROOT}/… path exists (or is created by a named later task)', () => {
    const missing: string[] = [];
    for (const d of allDocs()) {
      for (const m of d.text.matchAll(/\$\{CLAUDE_PLUGIN_ROOT\}\/([^\s`"')]+)/g)) {
        const rel = (m[1] ?? '').replace(/[.,:;]+$/, '');
        if (NOT_YET_SHIPPED.has(rel)) continue;
        if (!existsSync(resolve(REPO_ROOT, rel))) missing.push(`${d.rel}: ${rel}`);
      }
    }
    expect(missing).toEqual([]);
  });

  it.each(allDocs().map((d) => [d.rel, d] as const))('%s: carries no known-dead reference', (_rel, doc) => {
    const hits = DEAD_REFERENCES.filter(([re]) => re.test(doc.text)).map(([re, why]) => `${re.source}: ${why}`);
    expect(hits).toEqual([]);
  });
});

describe('.guardian/budgets.yml examples', () => {
  const blocks = allDocs().flatMap((d) =>
    [...d.text.matchAll(/```ya?ml\r?\n(# \.guardian\/budgets\.yml[^\n]*\r?\n[\s\S]*?)```/g)].map(
      (m, i) => [`${d.rel}#${i + 1}`, m[1] ?? ''] as const,
    ),
  );

  it('at least one skill documents the budgets file', () => {
    expect(blocks.length).toBeGreaterThan(0);
  });

  it.each(blocks)('%s is a file loadBudgets accepts', (_where, yaml) => {
    const project = makeTempDir('dg-budget-doc-');
    mkdirSync(join(project, '.guardian'));
    writeFileSync(join(project, '.guardian', 'budgets.yml'), yaml, 'utf8');
    const loaded = loadBudgets(project);
    expect(loaded.kind === 'invalid' ? loaded.error : loaded.kind).toBe('loaded');
  });
});
