import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse } from 'yaml';
import { FOCUS_METADATA_KEY, FOCUS_PATH } from '../../../src/surface/recoverMetavars.js';

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

/** The metavariables a rule narrows its reported range to, at any depth. */
function focusedMetavars(rule: Rule): Set<string> {
  const found = new Set<string>();
  const walk = (node: unknown): void => {
    if (Array.isArray(node)) {
      for (const child of node) walk(child);
      return;
    }
    if (node === null || typeof node !== 'object') return;
    const record = node as Record<string, unknown>;
    const focus = record['focus-metavariable'];
    if (typeof focus === 'string') found.add(focus);
    else if (Array.isArray(focus)) {
      for (const name of focus) if (typeof name === 'string') found.add(name);
    }
    for (const value of Object.values(record)) walk(value);
  };
  walk(rule.patterns ?? rule['pattern-either'] ?? rule.pattern);
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
    // actix is here too, and was not always: it was one rule binding the
    // attribute name to $METHOD. `focus-metavariable: $PATH` narrows the
    // reported range to the path and discards every other capture, $METHOD
    // included, so the verb has to come from the rule identity again.
    for (const framework of ['nestjs', 'spring', 'aspnet', 'actix']) {
      const methods = byFramework.get(framework);
      expect(methods?.has('GET'), `${framework} has no GET rule`).toBe(true);
      expect(methods?.has('POST'), `${framework} has no POST rule`).toBe(true);
      expect(methods?.has('DELETE'), `${framework} has no DELETE rule`).toBe(true);
    }
  });

  it('gives every focused route rule its own verb, since focusing discards $METHOD', () => {
    // A focused rule reports only $PATH, so a `$METHOD` metavariable in its
    // pattern would bind nothing readable on a redacting Semgrep while binding
    // correctly on an old one — the two versions would disagree about the verb.
    // Declaring the verb per rule is what makes them agree.
    for (const rule of rules().filter((r) => r.metadata?.[FOCUS_METADATA_KEY] !== undefined)) {
      expect(rule.metadata?.method, `${rule.id} declares no metadata.method`).toBeDefined();
      expect(guardedMetavars(rule), `${rule.id} still guards $METHOD`).not.toContain('$METHOD');
      expect(patternsOf(rule).join('\n'), `${rule.id} still binds $METHOD`).not.toContain(
        '$METHOD',
      );
    }
  });

  it('keeps `focus-metavariable` and the guardian_focus flag in lock-step', () => {
    // The successor to the UNREADABLE_UNDER_REDACTION assertion, and the reason
    // it can be simpler: recovery for a focused rule is "the span is the value",
    // so there is no list of frameworks to keep current and no fail-open default
    // for an unlisted one to fall into. What must hold is only that the flag
    // `recoverMetavars.ts` reads and the operator Semgrep acts on travel
    // together — in BOTH directions.
    //
    // Declaring the flag without the operator is the dangerous direction: the
    // span would then be the whole decorated declaration and "the span is the
    // value" would emit a route whose path is a function body. Declaring the
    // operator without the flag is merely lossy — the span is the path literal
    // and the scanner would refuse it — but it means a rule silently stopped
    // being recovered, so it fails too.
    for (const rule of rules()) {
      const declared = rule.metadata?.[FOCUS_METADATA_KEY];
      const focused = focusedMetavars(rule);
      if (declared !== undefined) {
        expect(declared, `${rule.id}: unknown ${FOCUS_METADATA_KEY} value`).toBe(FOCUS_PATH);
        expect(rule.metadata?.guardian_kind, `${rule.id}: focus is a route concept`).toBe('route');
        expect([...focused], `${rule.id} declares the flag but focuses nothing`).toEqual(['$PATH']);
      } else {
        expect([...focused], `${rule.id} focuses but declares no flag`).toEqual([]);
      }
    }
  });

  it('focuses every route rule whose pattern spans the declaration', () => {
    // The lock-step that would have caught a shipped Critical defect, restated
    // for the fix that removed the defect class.
    //
    // A pattern containing a brace-delimited body matches the attribute PLUS the
    // declaration it decorates, so Semgrep's reported span starts at the FIRST
    // attribute on that declaration — not necessarily the route one:
    //
    //   #[allow(dead_code)] / #[get("/d")]  ->  a resolved route `dead_code`
    //   // [HttpGet("/orders/legacy")] / [HttpGet("/orders")]  ->  /orders/legacy
    //
    // Four generations of "find the route attribute in the span" produced routes
    // like those, silently, because reconstruction SUCCEEDED and isLiteralPath
    // accepts a fabrication as readily as the truth. No local predicate can tell
    // code from a comment from a string, so the answer is not to read the span
    // better but to make Semgrep report a narrower one. Widening a fourth family
    // to span its declaration without focusing it reintroduces the whole class,
    // which is why this is an equality and not a compatibility check.
    //
    // The detector keys on a brace-delimited BODY appearing in the pattern, not
    // on the literal text `{ ... }`. Sniffing for that exact string passed green
    // when the same rule was written `{ $BODY }` — a spelling difference Semgrep
    // treats as equivalent — and fabricated exactly as before.
    const spansDeclaration = new Set<string>();
    const focusedFrameworks = new Set<string>();
    for (const rule of rules().filter((r) => r.metadata?.guardian_kind === 'route')) {
      const framework = String(rule.metadata?.framework);
      if (patternsOf(rule).some(hasBracedBody)) spansDeclaration.add(framework);
      if (rule.metadata?.[FOCUS_METADATA_KEY] !== undefined) focusedFrameworks.add(framework);
    }
    expect(spansDeclaration.size).toBeGreaterThan(0);
    expect([...spansDeclaration].sort()).toEqual(['actix', 'aspnet', 'nestjs']);
    expect([...focusedFrameworks].sort()).toEqual([...spansDeclaration].sort());
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
