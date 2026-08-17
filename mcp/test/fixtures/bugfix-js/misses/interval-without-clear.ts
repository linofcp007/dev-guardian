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

export function PollingEffectExprCleanup(tick: () => void): void {
  useEffect(() => {
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, []);
}

export function PollingEffectBlockCleanup(tick: () => void): void {
  useEffect(() => {
    const t = setInterval(tick, 1000);
    return () => {
      clearInterval(t);
    };
  }, []);
}
