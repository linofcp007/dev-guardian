import { useEffect } from 'react';

// On the boundary, not well inside it: the same genuinely-safe interval as
// below, but now sitting beside a SIBLING function that also calls
// clearInterval on an unrelated handle sharing the same variable name `t`.
// Must stay silent because of ITS OWN clear, not because a clearInterval
// merely exists somewhere in the file -- proves the scope search is
// function-scoped, not file-scoped, from the safe side too. Companion of
// the leak+decoy pair in hits/interval-without-clear.ts.
export function unrelatedCleanup(existingHandle: number): void {
  const t = existingHandle;
  clearInterval(t);
}
export function startAndStopPolling(tick: () => void): void {
  const t = setInterval(tick, 1000);
  clearInterval(t);
}

// Arrow components, deliberately NOT `function` declarations (bugfix-rules-
// jsts fix wave): the interval rule's first pattern-not-inside clause
// excludes any `function $F(...) { ... clearInterval($T); ... }` on its
// own, so a declaration-shaped near-miss here would be silenced by that
// clause regardless of what the useEffect clause below does — proving
// nothing about it. Writing these as arrow components forces both to rely
// solely on the useEffect-cleanup clause, so deleting it makes both fire.
export const PollingEffectExprCleanup = (tick: () => void): void => {
  useEffect(() => {
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, []);
};

export const PollingEffectBlockCleanup = (tick: () => void): void => {
  useEffect(() => {
    const t = setInterval(tick, 1000);
    return () => {
      clearInterval(t);
    };
  }, []);
};
