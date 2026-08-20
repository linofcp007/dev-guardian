/**
 * WRITTEN BY THE AUDITOR (probes/p03_catch_returns_null.ts), not by the rule
 * author, and it is a `hits/` file on purpose: every function below is
 * textbook-correct, idiomatic JavaScript whose DOCUMENTED contract is
 * null-on-failure, and this rule fires on all of them.
 *
 * That is not a defect this wave repaired, because there is no syntactic
 * difference between these and a genuine swallow: `safeJsonParse` and a
 * function that loses a database error are the same AST. It is the reason
 * the rule sits at INFO instead of ERROR, and pinning the behaviour here
 * makes the trade explicit -- if someone re-promotes the tier, the severity
 * assertion in bugfixRulesJs.test.ts goes red with this file as the evidence
 * of what would then be reported as `high`.
 *
 * Independent measurement, for the record: across the auditor's corpus this
 * rule produced FIVE instances of correct code and ZERO true positives.
 */

// Safe JSON parse -- the single most common shape in any JS codebase.
export function safeJsonParse(raw: string): unknown {
  try { return JSON.parse(raw); } catch (e) { return null; }
}

// Optional-dependency probe.
export function tryRequire(name: string): unknown {
  try { return require(name); } catch (e) { return null; }
}

// Validity probe: null means "not a URL", which is the entire point.
export function parseUrl(raw: string): URL | null {
  try { return new URL(raw); } catch (e) { return null; }
}

// Reading an optional config file -- [] means "none configured".
export function readPluginList(): string[] {
  try { return JSON.parse('[]') as string[]; } catch (e) { return []; }
}
