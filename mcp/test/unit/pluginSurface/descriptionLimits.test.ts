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
import { commandDocs, frontmatter, skillDocs } from './pluginDocs.js';

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
