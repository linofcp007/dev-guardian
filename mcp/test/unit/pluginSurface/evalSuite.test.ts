/**
 * The plugin-eval suite (`evals/`, run with `claude plugin eval`) against the
 * plugin it grades.
 *
 * A paid eval run that fails because a grader names a skill that was renamed,
 * a tool that does not exist, or a user-started skill the model cannot invoke
 * teaches nothing. So, offline:
 *
 *   - every case has a `prompt.md` with the fields the harness needs and
 *     graders whose type it knows; every regex compiles;
 *   - every `dev-guardian:<name>` a grader matches is a skill or command, and a
 *     grader that expects one to FIRE names only model-invocable ones;
 *   - every MCP tool a grader names is registered (dev-spec-driven's, in its
 *     name fixture);
 *   - a behavioural case's scaffold script exists and sources the shared lib;
 *   - the README lists every case, and the suite covers EN, PT and ES.
 */

import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { parse as parseYaml } from 'yaml';
import { TOOLS } from '../../../src/tools/index.js';
import { DEV_SPEC_TOOLS } from './devSpecNames.js';
import { REPO_ROOT, commandDocs, frontmatter, skillDocs } from './pluginDocs.js';

beforeAll(async () => {
  await import('../../../src/registerAll.js');
});

const EVALS = resolve(REPO_ROOT, 'evals');
const NOT_CASES = new Set(['fixtures', 'results']);

interface Doc {
  fm: Record<string, unknown>;
  body: string;
}

function readDoc(path: string): Doc {
  const text = readFileSync(path, 'utf8');
  const m = /^---\r?\n([\s\S]*?)\r?\n---\r?\n([\s\S]*)$/.exec(text);
  if (m === null) throw new Error(`${path}: no frontmatter`);
  return { fm: parseYaml(m[1] ?? '') as Record<string, unknown>, body: m[2] ?? '' };
}

const cases = readdirSync(EVALS, { withFileTypes: true })
  .filter((d) => d.isDirectory() && !NOT_CASES.has(d.name))
  .map((d) => d.name)
  .sort();

function graders(name: string): [string, Doc][] {
  const dir = join(EVALS, name, 'graders');
  return readdirSync(dir)
    .filter((f) => f.endsWith('.md'))
    .map((f) => [f, readDoc(join(dir, f))]);
}

const invocable = new Map(
  [...skillDocs(), ...commandDocs()].map((d) => [d.name, frontmatter(d)['disable-model-invocation'] !== true]),
);

/** The `dev-guardian:<alternatives>` a pattern matches, expanded from `(?:a|b)`. */
function pluginNames(pattern: string): string[] {
  return [...pattern.matchAll(/dev-guardian:(?:\(\?:([\w|-]+)\)|([\w-]+))/g)].flatMap((m) =>
    m[1] !== undefined ? m[1].split('|') : m[2] === '[' || m[2] === undefined ? [] : [m[2]],
  );
}

describe('the plugin-eval suite', () => {
  it('has triggering, negative, routing and behavioural cases in EN, PT and ES', () => {
    const tags = cases.flatMap((c) => (readDoc(join(EVALS, c, 'prompt.md')).fm['tags'] as string[]) ?? []);
    for (const t of ['triggering', 'negative', 'near-miss', 'routing', 'behavior', 'en', 'pt', 'es']) {
      expect(tags, t).toContain(t);
    }
    expect(tags.filter((t) => t === 'triggering').length).toBeGreaterThanOrEqual(10);
  });

  it.each(cases)('%s: prompt.md has the fields the harness needs', (name) => {
    const { fm, body } = readDoc(join(EVALS, name, 'prompt.md'));
    expect(typeof fm['name']).toBe('string');
    expect(Array.isArray(fm['tags']) && (fm['tags'] as unknown[]).length > 0).toBe(true);
    expect(Number.isInteger(fm['runs'])).toBe(true);
    expect(Number.isInteger(fm['max_turns'])).toBe(true);
    expect(Array.isArray(fm['allowed_tools'])).toBe(true);
    for (const key of Object.keys(fm['env'] ?? {})) expect(key).toMatch(/^EVAL_[A-Z0-9_]*$/);
    expect(body.trim()).not.toBe('');
  });

  it.each(cases)('%s: graders are of a known type, and their patterns compile', (name) => {
    const gs = graders(name);
    expect(gs.length).toBeGreaterThan(0);
    for (const [file, { fm }] of gs) {
      expect(['tool_used', 'regex', 'llm'], file).toContain(fm['type']);
      if (fm['type'] === 'tool_used') expect(typeof fm['tool'], file).toBe('string');
      if (fm['type'] === 'regex') expect(['trace', 'last_message'], file).toContain(fm['target']);
      for (const key of ['input_match', 'pattern']) {
        const p = fm[key];
        if (p !== undefined) expect(() => new RegExp(String(p)), `${file}: ${key}`).not.toThrow();
      }
    }
  });

  it('the name matcher reads a grader the way the suite writes it (positive control)', () => {
    expect(pluginNames(String.raw`"skill":\s*"dev-guardian:(?:guardian-security|guardian-scan)"`)).toEqual([
      'guardian-security',
      'guardian-scan',
    ]);
    expect(pluginNames(String.raw`"skill":\s*"dev-guardian:[\w-]+"`)).toEqual([]);
    const fires = graders('trigger-release-en').flatMap(([, g]) => pluginNames(String(g.fm['input_match'] ?? '')));
    expect(fires).toEqual(['guardian-release']);
  });

  it.each(cases)('%s: names only real skills and commands, and expects only model-invocable ones to fire', (name) => {
    const problems: string[] = [];
    for (const [file, { fm }] of graders(name)) {
      const pattern = String(fm['input_match'] ?? fm['pattern'] ?? '');
      const expectsFire = fm['type'] === 'tool_used' ? fm['max'] !== 0 : fm['match'] !== 'not_contains';
      for (const n of pluginNames(pattern)) {
        if (!invocable.has(n)) problems.push(`${file}: dev-guardian:${n} is not a skill or command`);
        else if (expectsFire && invocable.get(n) !== true) problems.push(`${file}: dev-guardian:${n} is user-started`);
      }
    }
    expect(problems).toEqual([]);
  });

  it.each(cases)('%s: every MCP tool it names exists', (name) => {
    const ours = new Set(TOOLS.map((t) => t.name));
    const spec = new Set(DEV_SPEC_TOOLS);
    const problems: string[] = [];
    for (const [file, { fm }] of graders(name)) {
      const text = `${String(fm['tool'] ?? '')}\n${String(fm['input_match'] ?? '')}\n${String(fm['pattern'] ?? '')}`;
      for (const m of text.matchAll(/mcp__plugin_dev-guardian_dev-guardian__([a-z_]+)/g)) {
        if (!ours.has(m[1] ?? '')) problems.push(`${file}: ${m[1] ?? ''}`);
      }
      for (const m of text.matchAll(/mcp__plugin_dev-spec-driven_spec-driven__([a-z_]+)/g)) {
        // `spec_(?:next_action|create)` style alternations are checked by their stem
        const stem = m[1] ?? '';
        if (!spec.has(stem) && ![...spec].some((t) => t.startsWith(stem))) problems.push(`${file}: ${stem}`);
      }
    }
    expect(problems).toEqual([]);
  });

  it.each(cases.filter((c) => existsSync(join(EVALS, c, 'case.yaml'))))(
    '%s: its scaffold script exists and sources the shared fixtures lib',
    (name) => {
      const yaml = parseYaml(readFileSync(join(EVALS, name, 'case.yaml'), 'utf8')) as { context?: { scaffold_script?: string } };
      const script = yaml.context?.scaffold_script ?? '';
      expect(script).not.toBe('');
      const text = readFileSync(join(EVALS, name, script), 'utf8');
      expect(text).toMatch(/\.\.\/fixtures\/lib\.sh/);
    },
  );

  it('the README lists every case', () => {
    const readme = readFileSync(join(EVALS, 'README.md'), 'utf8');
    expect(cases.filter((c) => !readme.includes(`\`${c}\``) && !readme.includes(c))).toEqual([]);
  });
});
