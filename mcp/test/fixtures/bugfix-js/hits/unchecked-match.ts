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

// The `exec` counterpart of `firstGroupFromConfig` above, and the shape the
// guarded-`exec` exclusion has to reason its way past. `exec`'s argument is
// the SUBJECT STRING, and here that string is pulled out of an optional
// config array, so the `?.[0]` belongs to fetching the subject — not to the
// outer index, which is still completely unguarded and still throws the
// moment the pattern does not match.
//
// The exclusion reasons from "`?.[` appears in the snippet but not in the
// argument, so it must be the outer optional-chaining connector". Drop the
// argument half of that reasoning and this real bug is silently excluded,
// exactly as its `match` twin was before `firstGroupFromConfig` was added.
const SUBJECT_RE = /x(\d)/;
export function firstGroupViaExecOfConfigValue(source: PatternSource | undefined): string {
  return SUBJECT_RE.exec(source?.patterns?.[0] ?? '')[1];
}
