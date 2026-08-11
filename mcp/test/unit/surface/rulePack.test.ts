import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse } from 'yaml';

const PACK_PATH = join(__dirname, '../../../../configs/semgrep/routes.yml');

interface Rule {
  id?: string;
  languages?: string[];
  severity?: string;
  message?: string;
  metadata?: Record<string, unknown> & { guardian_kind?: string; method?: unknown };
  pattern?: unknown;
  patterns?: unknown;
  'pattern-either'?: unknown;
}

/** Metavariables a rule constrains with `metavariable-regex`, at any depth. */
function guardedMetavars(rule: Rule): Set<string> {
  const found = new Set<string>();
  const walk = (node: unknown): void => {
    if (Array.isArray(node)) {
      for (const child of node) walk(child);
      return;
    }
    if (node === null || typeof node !== 'object') return;
    const record = node as Record<string, unknown>;
    const guard = record['metavariable-regex'];
    if (guard !== null && typeof guard === 'object') {
      const name = (guard as Record<string, unknown>)['metavariable'];
      if (typeof name === 'string') found.add(name);
    }
    for (const value of Object.values(record)) walk(value);
  };
  walk(rule.patterns ?? rule['pattern-either'] ?? rule.pattern);
  return found;
}

function rules(): Rule[] {
  const doc = parse(readFileSync(PACK_PATH, 'utf8')) as { rules?: Rule[] };
  return doc.rules ?? [];
}

const KINDS = new Set(['route', 'mount', 'import', 'env']);

describe('configs/semgrep/routes.yml', () => {
  it('parses and is non-empty', () => {
    expect(rules().length).toBeGreaterThan(0);
  });

  it('gives every rule a unique guardian- prefixed id', () => {
    const ids = rules().map((r) => r.id);
    expect(ids.every((id) => typeof id === 'string' && id.startsWith('guardian-'))).toBe(true);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('tags every rule with a known guardian_kind — the extractor contract', () => {
    for (const rule of rules()) {
      expect(KINDS.has(String(rule.metadata?.guardian_kind))).toBe(true);
    }
  });

  it('gives every route rule a framework and a confidence', () => {
    for (const rule of rules().filter((r) => r.metadata?.guardian_kind === 'route')) {
      expect(typeof rule.metadata?.framework).toBe('string');
      expect(['high', 'medium', 'low']).toContain(rule.metadata?.confidence);
    }
  });

  it('keeps every rule at INFO severity so it never reads as a finding', () => {
    for (const rule of rules()) {
      expect(rule.severity).toBe('INFO');
    }
  });

  it('declares metadata.method only as a real HTTP verb the extractor knows', () => {
    const declared = rules()
      .filter((r) => r.metadata?.guardian_kind === 'route')
      .map((r) => r.metadata?.method)
      .filter((m) => m !== undefined);
    expect(declared.length).toBeGreaterThan(0);
    for (const method of declared) {
      expect(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']).toContain(method);
    }
  });

  it('carries the verb per rule for the frameworks that encode it in the pattern', () => {
    // Semgrep never reports which pattern-either alternative fired, so these
    // families must be one rule per verb, each declaring metadata.method.
    // Collapsing them back into a single pattern-either loses the method.
    const byFramework = new Map<string, Set<unknown>>();
    for (const rule of rules().filter((r) => r.metadata?.guardian_kind === 'route')) {
      const framework = String(rule.metadata?.framework);
      const methods = byFramework.get(framework) ?? new Set();
      if (rule.metadata?.method !== undefined) methods.add(rule.metadata.method);
      byFramework.set(framework, methods);
    }
    for (const framework of ['nestjs', 'spring', 'aspnet', 'actix']) {
      const methods = byFramework.get(framework);
      expect(methods?.has('GET'), `${framework} has no GET rule`).toBe(true);
      expect(methods?.has('POST'), `${framework} has no POST rule`).toBe(true);
      expect(methods?.has('DELETE'), `${framework} has no DELETE rule`).toBe(true);
    }
  });

  it('constrains $PATH to a literal on exactly the two rules that need it', () => {
    // A $PATH literal guard DROPS the match, so the extractor never sees it —
    // and a route registered with a computed path (@GetMapping(Paths.ORDERS),
    // path(settings.ADMIN_URL, ...)) is still surface. Dropping it makes
    // `coverage` report no_matches for the language, i.e. "this application
    // exposes nothing" — the falsehood the tool exists to prevent. The
    // extractor's isLiteralPath keeps those routes and flags them
    // path_partial instead.
    //
    // The guard is correct ONLY where the pattern does not identify a route on
    // its own, so the literal disambiguates rather than discards. Two rules
    // qualify. If you are adding a third, the bar is: does a match on this
    // pattern, with a non-literal path, mean "not a route" (guard) or "a route
    // whose path is computed" (no guard)?
    const guarded = rules()
      .filter((r) => r.metadata?.guardian_kind === 'route')
      .filter((r) => guardedMetavars(r).has('$PATH'))
      .map((r) => r.id)
      .sort();
    expect(guarded).toEqual(['guardian-route-express', 'guardian-route-rails']);
  });

  it('covers all 8 supported stacks with at least one route rule', () => {
    const covered = new Set(
      rules()
        .filter((r) => r.metadata?.guardian_kind === 'route')
        .flatMap((r) => r.languages ?? []),
    );
    for (const lang of ['javascript', 'typescript', 'python', 'php', 'go', 'rust', 'ruby', 'java', 'csharp']) {
      expect(covered.has(lang), `no route rule covers ${lang}`).toBe(true);
    }
  });
});
