export function firstGroupOptional(s: string): string | undefined {
  return s.match(/x(\d)/)?.[1];
}

export function firstGroupGuarded(s: string): string {
  const m = s.match(/x(\d)/);
  if (m) {
    return m[1] ?? '';
  }
  return '';
}

// FOUND BY SCANNING THIS REPO'S OWN `mcp/src` (183 files of TypeScript nobody
// wrote as a fixture), not by any probe corpus. The audit wave added a
// `$RE.exec($S)[$I]` branch to this rule and it did NOT inherit the optional-
// chaining exclusion the `match` branch already had, so guarded `exec` became
// a false positive: 13 of them in `recoverMetavars.ts` alone, every one of the
// form below, against the ONE true positive the branch was added for.
//
// Both shapes below are here because they fail differently: the first has a
// bare argument, the second has an argument containing a call. The exclusion
// reasons from "`?.[` appears in the match but not in the argument, so it must
// be the outer connector", so an argument that is itself complex is the case
// most likely to break it.
const GROUP_RE = /x(\d)/;
export function firstGroupExecOptional(s: string): string | undefined {
  return GROUP_RE.exec(s)?.[1];
}
export function firstGroupExecOptionalComputedArg(s: string): string | undefined {
  return GROUP_RE.exec(s.slice(2))?.[1];
}
