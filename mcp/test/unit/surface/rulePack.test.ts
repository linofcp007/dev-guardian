import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse } from 'yaml';
import { ATTRIBUTE_ANCHORED_FRAMEWORKS } from '../../../src/surface/recoverMetavars.js';

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

/** Every `pattern:` string a rule declares, at any nesting depth. */
function patternsOf(rule: Rule): string[] {
  const found: string[] = [];
  const walk = (node: unknown): void => {
    if (Array.isArray(node)) {
      for (const child of node) walk(child);
      return;
    }
    if (node === null || typeof node !== 'object') return;
    for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
      if (key === 'pattern' && typeof value === 'string') found.push(value);
      else walk(value);
    }
  };
  if (typeof rule.pattern === 'string') found.push(rule.pattern);
  walk(rule.patterns ?? rule['pattern-either'] ?? []);
  return found;
}

/**
 * Does this pattern swallow a brace-delimited declaration body?
 *
 * Structural, so `{ ... }`, `{ $BODY }`, `{}` and `{ ...; }` all count. A
 * brace inside a string literal in the pattern does not.
 */
function hasBracedBody(pattern: string): boolean {
  let inString: string | undefined;
  for (let i = 0; i < pattern.length; i += 1) {
    const ch = pattern[i];
    if (ch === undefined) continue;
    if (inString !== undefined) {
      if (ch === '\\') i += 1;
      else if (ch === inString) inString = undefined;
      continue;
    }
    if (ch === '"' || ch === "'") inString = ch;
    else if (ch === '{') return true;
  }
  return false;
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
    for (const framework of ['nestjs', 'spring', 'aspnet']) {
      const methods = byFramework.get(framework);
      expect(methods?.has('GET'), `${framework} has no GET rule`).toBe(true);
      expect(methods?.has('POST'), `${framework} has no POST rule`).toBe(true);
      expect(methods?.has('DELETE'), `${framework} has no DELETE rule`).toBe(true);
    }
  });

  it('keeps the Rust rule single, with the verb in $METHOD', () => {
    // actix used to be in the list above: five per-verb rules, one per
    // attribute. Measured against Semgrep 1.86.0 they all matched the SAME
    // spans — every node in the file — and bound `metavars: {}`, so one real
    // `#[get("/x")]` produced five routes: the correct GET plus four
    // fabricated verbs, some anchored on function bodies rather than routes.
    //
    // Semgrep's Rust engine does bind the attribute name once the pattern
    // includes the item the attribute is attached to, and an actix/Rocket
    // attribute name IS the HTTP verb, so one rule with a $METHOD guard is
    // both correct and sufficient. The other attribute families cannot do
    // this: `@$DEC($PATH)` is not a parseable TypeScript pattern, and C#'s
    // `HttpGet` is not a verb the extractor's normalizeMethod knows.
    const actix = rules().filter((r) => r.metadata?.framework === 'actix');
    expect(actix).toHaveLength(1);
    const rule = actix[0];
    expect(rule?.metadata?.method).toBeUndefined();
    expect(rule === undefined ? new Set() : guardedMetavars(rule)).toContain('$METHOD');
  });

  it('anchors every route rule whose pattern spans the decorated declaration', () => {
    // The lock-step that would have caught a shipped Critical defect.
    //
    // A pattern ending in `{ ... }` matches the attribute PLUS the declaration
    // it decorates, so Semgrep's reported span starts at the FIRST attribute on
    // that declaration — not necessarily the route one. `recoverMetavars.ts`
    // must then locate the route attribute by name; if it instead reads the
    // first argument list in the span it recovers a *different* attribute's
    // argument, and because that usually succeeds the real route is silently
    // replaced rather than reported missing:
    //
    //   #[allow(dead_code)] / #[get("/d")]  ->  a resolved route `dead_code`
    //
    // Widening another family's pattern this way without adding its framework
    // to ATTRIBUTE_ANCHORED_FRAMEWORKS reintroduces exactly that bug, so the
    // two lists are asserted equal here rather than merely compatible.
    //
    // The detector keys on a brace-delimited BODY appearing in the pattern,
    // not on the literal text `{ ... }`. Sniffing for that exact string passed
    // green when the same rule was written `{ $BODY }` — a spelling difference
    // Semgrep treats as equivalent — and fabricated exactly as before. No
    // pattern in this pack that matches a call or an annotation alone contains
    // a brace; every one that swallows a declaration does.
    const spansDeclaration = new Set<string>();
    for (const rule of rules().filter((r) => r.metadata?.guardian_kind === 'route')) {
      if (patternsOf(rule).some(hasBracedBody)) {
        spansDeclaration.add(String(rule.metadata?.framework));
      }
    }
    expect(spansDeclaration.size).toBeGreaterThan(0);
    expect([...spansDeclaration].sort()).toEqual([...ATTRIBUTE_ANCHORED_FRAMEWORKS].sort());
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
