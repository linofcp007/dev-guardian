/**
 * Length and validity limits on everything a host loads into the model's
 * context before the user has asked for anything.
 *
 *   - MCP tool descriptions: at most 1500 characters. Claude Code truncates a
 *     description at 2048; this repo keeps a margin. `bug_hunt` once reached
 *     25 568 — a changelog carried in every session's tool list. Measurement
 *     history belongs in the rule packs' comments and CHANGELOG.md; the
 *     description says what the tool does, its key inputs, what it returns
 *     and its limits.
 *   - Skill `description`: at most 1024 characters, and valid YAML. The
 *     router's alone was 4 487 characters, and two skills
 *     (`guardian-grill`, `guardian-improve`) carried an unquoted `: ` that a
 *     strict YAML loader rejects — so the frontmatter is parsed here with the
 *     `yaml` package, not with a regex.
 */

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { RULES_BODY } from '../../../src/hostsetup/rulesTemplate.js';
import { RESOURCES } from '../../../src/resources/index.js';
import { TOOLS } from '../../../src/tools/index.js';
import { MCP_ROOT } from '../../helpers/tsxNode.js';
import { commandDocs, frontmatter, referenceDocs, skillDocs } from './pluginDocs.js';

beforeAll(async () => {
  await import('../../../src/registerAll.js');
});

const TOOL_DESCRIPTION_MAX = 1500;
const SKILL_DESCRIPTION_MAX = 1024;

describe('MCP tool descriptions', () => {
  it('every registered tool has a description of at most 1500 characters', () => {
    expect(TOOLS.length).toBeGreaterThan(0);
    const over = TOOLS.filter((t) => t.description.length > TOOL_DESCRIPTION_MAX).map(
      (t) => `${t.name}: ${t.description.length}`,
    );
    expect(over).toEqual([]);
  });

  it('every tool has a non-empty description', () => {
    expect(TOOLS.filter((t) => t.description.trim() === '').map((t) => t.name)).toEqual([]);
  });

  // NFR-3 of llm-scan: the limit above holds only for tools that exist, so
  // the three new ones are named — a description cannot be measured while
  // its tool is missing from the registry.
  it.each(['llm_scan_start', 'llm_scan_task', 'llm_scan_submit'])(
    'T-34 (NFR-3) %s is registered, with a description of at most 1500 characters',
    (name) => {
      const tool = TOOLS.find((t) => t.name === name);
      expect(tool, `${name} is registered`).toBeDefined();
      expect(tool?.description.trim() ?? '').not.toBe('');
      expect(tool?.description.length ?? Number.POSITIVE_INFINITY).toBeLessThanOrEqual(TOOL_DESCRIPTION_MAX);
    },
  );
});

// sarif-import (test plan T-23, NFR-1 and NFR-2): the new tool is held to the
// same limit by name, so it cannot pass the sweep above by not being there.
describe('T-23 import_sarif', () => {
  it('T-23 import_sarif is registered, with a non-empty description of at most 1500 characters (NFR-2)', () => {
    const tool = TOOLS.find((t) => t.name === 'import_sarif');
    expect(tool, 'import_sarif registered').toBeDefined();
    expect(tool?.description.trim()).not.toBe('');
    expect(tool?.description.length).toBeLessThanOrEqual(TOOL_DESCRIPTION_MAX);
  });

  // NFR-1: no new runtime dependency, and the parser reuses the scanner
  // parsers' helpers. Read from the source: every import of `src/sarif/` is a
  // node builtin or a module of this repository.
  it('T-23 src/sarif imports only node builtins and repository modules, and reuses runners/scannerParsers (NFR-1)', () => {
    const dir = join(MCP_ROOT, 'src', 'sarif');
    const files = readdirSync(dir).filter((f) => f.endsWith('.ts'));
    expect(files).toEqual(expect.arrayContaining(['importSarif.ts', 'persistImport.ts']));
    const specifiers = files.flatMap((f) =>
      [
        ...readFileSync(join(dir, f), 'utf8').matchAll(
          /^\s*(?:import\s+(?:[^;'"]*?\sfrom\s+)?|export\s+(?:type\s+)?(?:\*|\{[^}]*\})\s*from\s+)['"]([^'"]+)['"]/gm,
        ),
      ].map((m) => ({ file: f, from: m[1] ?? '' })),
    );
    expect(specifiers.filter((s) => !s.from.startsWith('.') && !s.from.startsWith('node:'))).toEqual([]);
    expect(
      specifiers.some((s) => s.file === 'importSarif.ts' && s.from === '../runners/scannerParsers/index.js'),
      'importSarif.ts reuses runners/scannerParsers/index.js',
    ).toBe(true);
  });
});

describe('skill frontmatter', () => {
  const skills = skillDocs();

  it('finds the skills', () => {
    expect(skills.length).toBeGreaterThanOrEqual(13);
  });

  it.each(skills.map((s) => [s.name, s] as const))('%s: frontmatter is valid YAML', (_name, skill) => {
    expect(() => frontmatter(skill)).not.toThrow();
  });

  it.each(skills.map((s) => [s.name, s] as const))('%s: name matches its directory', (name, skill) => {
    expect(frontmatter(skill)['name']).toBe(name);
  });

  it.each(skills.map((s) => [s.name, s] as const))(
    '%s: description is a string of at most 1024 characters',
    (_name, skill) => {
      const description = frontmatter(skill)['description'];
      expect(typeof description).toBe('string');
      expect(String(description).trim()).not.toBe('');
      expect(String(description).length).toBeLessThanOrEqual(SKILL_DESCRIPTION_MAX);
    },
  );
});

describe('command frontmatter', () => {
  it.each(commandDocs().map((c) => [c.name, c] as const))(
    '%s: frontmatter is valid YAML with a description',
    (_name, command) => {
      const fm = frontmatter(command);
      expect(typeof fm['description']).toBe('string');
      expect(String(fm['description']).length).toBeLessThanOrEqual(SKILL_DESCRIPTION_MAX);
    },
  );

  // Claude Code shows `argument-hint` beside the command in its picker; a
  // non-string (an unquoted `[a, b]` parses as a YAML list) shows nothing.
  it.each(commandDocs().map((c) => [c.name, c] as const))(
    '%s: argument-hint, when present, is a short single-line string',
    (_name, command) => {
      const hint = frontmatter(command)['argument-hint'];
      if (hint === undefined) return;
      expect(typeof hint).toBe('string');
      expect(String(hint)).not.toMatch(/\n/);
      expect(String(hint).length).toBeLessThanOrEqual(200);
    },
  );
});

// The skill and command listing — every model-invocable entry's name and
// description — is in the model's context in every session, in every
// project. It was 12 910 characters across 23 entries, two thirds of them
// trilingual trigger lists, with four commands ending in a doubled suffix
// ("Foco .NET. Foco .NET.") and no entry saying what it was NOT for, so the
// "is this safe to ship?" family had four owners. Now: each skill says what
// it does, when, and what it is not for, in at most 300 characters; each
// command in at most 100; entries the user starts (the `g` alias, grill,
// improve, init) are not model-invocable at all; and the whole listing has a
// budget. Claude understands a PT / ES request against an EN intent, so the
// per-language trigger lists went; "respond in the user's language" is said
// once, in each body.
describe('the skill and command listing', () => {
  const SKILL_LISTING_MAX = 300;
  const COMMAND_LISTING_MAX = 100;
  const LISTING_TOTAL_MAX = 4000;
  /** Started by the user, never by the model (`disable-model-invocation: true`). */
  const USER_ONLY = ['g', 'guardian-grill', 'guardian-improve', 'guardian-init'];

  const entries = [...skillDocs(), ...commandDocs()].map((d) => {
    const fm = frontmatter(d);
    return {
      doc: d,
      description: String(fm['description'] ?? ''),
      invocable: fm['disable-model-invocation'] !== true,
    };
  });

  it.each(entries.map((e) => [e.doc.rel, e] as const))('%s: description within its listing limit', (_rel, e) => {
    const max = e.doc.kind === 'command' ? COMMAND_LISTING_MAX : SKILL_LISTING_MAX;
    expect(e.description.length).toBeLessThanOrEqual(max);
  });

  it('the entries the user starts are not model-invocable, and every other one is', () => {
    expect(entries.filter((e) => !e.invocable).map((e) => e.doc.name).sort()).toEqual(USER_ONLY);
  });

  it(`the model-visible listing is at most ${LISTING_TOTAL_MAX} characters`, () => {
    const total = entries.filter((e) => e.invocable).reduce((n, e) => n + e.doc.name.length + e.description.length + 4, 0);
    expect(total).toBeLessThanOrEqual(LISTING_TOTAL_MAX);
  });

  it.each(entries.map((e) => [e.doc.rel, e] as const))(
    '%s: no repeated sentence, no language instruction, no per-language trigger list',
    (_rel, e) => {
      const sentences = e.description.split(/(?<=\.)\s+/).map((s) => s.trim()).filter((s) => s !== '');
      expect(sentences.filter((s, i) => sentences.indexOf(s) !== i)).toEqual([]);
      expect(e.description).not.toMatch(/user's language|idioma/i);
      expect(e.description).not.toMatch(/\b(?:EN|PT|ES) triggers?\b|\bPT —|\bES —/);
    },
  );

  it.each(entries.filter((e) => e.invocable && e.doc.kind === 'skill').map((e) => [e.doc.rel, e] as const))(
    '%s: says what it is not for',
    (_rel, e) => {
      expect(e.description).toMatch(/\bNot for\b/);
    },
  );

  it.each([...skillDocs(), ...commandDocs()].map((d) => [d.rel, d] as const))(
    "%s: the body says to answer in the user's language",
    (_rel, d) => {
      if (/^Alias of the `[a-z-]+` (?:router )?skill\b/m.test(d.body)) return;
      expect(d.body).toMatch(/user's language|idioma do utilizador/i);
    },
  );
});

// What a skill costs once it fires. guardian-bugfix was 58.9 KB — 87% of it
// the rule packs' design history — and loaded 64 KB into "find bugs" before
// any work; guardian-security was 22.7 KB, the router 13.2 KB. What only some
// runs need lives in the skill's references/, read on demand.
describe('SKILL.md and reference sizes', () => {
  const SKILL_MAX = 12 * 1024;
  const PER_SKILL_MAX: Record<string, number> = {
    guardian: 6 * 1024,
    'guardian-bugfix': 8 * 1024,
    'guardian-security': 10 * 1024,
  };
  const REFERENCE_MAX = 6 * 1024;

  it.each(skillDocs().map((d) => [d.name, d] as const))('%s: SKILL.md within its size budget', (name, d) => {
    expect(Buffer.byteLength(d.text, 'utf8')).toBeLessThanOrEqual(PER_SKILL_MAX[name] ?? SKILL_MAX);
  });

  it.each(referenceDocs().map((d) => [d.rel, d] as const))('%s: within the reference budget', (_rel, d) => {
    expect(Buffer.byteLength(d.text, 'utf8')).toBeLessThanOrEqual(REFERENCE_MAX);
  });

  it.each(referenceDocs().map((d) => [d.rel, d] as const))('%s: is linked from its SKILL.md', (rel, d) => {
    const [skillName, file] = d.name.split('/');
    const skill = skillDocs().find((s) => s.name === skillName);
    expect(skill?.body ?? '', rel).toContain(`references/${file ?? ''}.md`);
  });
});

// Resource descriptions reach the model's context the same way tool
// descriptions do; nothing bounded them.
describe('MCP resource descriptions', () => {
  it('every registered resource has a non-empty description of at most 1500 characters', () => {
    expect(RESOURCES.length).toBeGreaterThan(0);
    const bad = RESOURCES.filter((r) => r.description.trim() === '' || r.description.length > TOOL_DESCRIPTION_MAX).map(
      (r) => `${r.name}: ${r.description.length}`,
    );
    expect(bad).toEqual([]);
  });
});

// The host rules every AI host is given state how many tools and resources
// the server exposes. The number was a literal nobody checked, and it said 54
// tools while the server registered 57.
describe('the host rules name the real tool and resource counts', () => {
  it('RULES_BODY says N tools and M resources, as registered', () => {
    const m = /(\d+) tools and (\d+) resources/.exec(RULES_BODY);
    expect(m).not.toBeNull();
    expect([Number(m?.[1]), Number(m?.[2])]).toEqual([TOOLS.length, RESOURCES.length]);
  });
});
