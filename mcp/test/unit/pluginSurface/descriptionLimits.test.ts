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

import { beforeAll, describe, expect, it } from 'vitest';
import { RULES_BODY } from '../../../src/hostsetup/rulesTemplate.js';
import { RESOURCES } from '../../../src/resources/index.js';
import { TOOLS } from '../../../src/tools/index.js';
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
