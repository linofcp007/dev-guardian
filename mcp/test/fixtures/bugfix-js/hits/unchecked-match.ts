export function firstGroup(s: string): string {
  return s.match(/x(\d)/)[1];
}

interface PatternSource {
  patterns?: string[];
}

// Regression: an earlier version of this rule excluded any match whose
// snippet contained '?.[' ANYWHERE, including inside match()'s own
// argument -- not just at the outer index. Here '?.[0]' belongs to reading
// an optional config array for the PATTERN, not to the outer index, which
// is still genuinely unguarded. Must still fire.
export function firstGroupFromConfig(s: string, source: PatternSource | undefined): string {
  return s.match(source?.patterns?.[0] ?? '.*')[1];
}

// RegExp#exec has the identical null-on-no-match contract, indexed just as
// unguarded, and was invisible because the rule only knew String#match.
// Auditor's p10 FN-3.
export function firstGroupViaExec(s: string): string {
  return /x(\d)/.exec(s)[1];
}
