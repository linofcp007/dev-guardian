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
