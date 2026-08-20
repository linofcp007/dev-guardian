import { useEffect, useRef } from 'react';

export function startPolling(tick: () => void): void {
  const t = setInterval(tick, 1000);
}

// On the boundary the rule's scope choice actually turns on, not well
// inside it: a genuine leak sitting beside a SIBLING function that also
// calls clearInterval (sharing the handle's variable name, not its scope).
// "Same function" must mean same function, not same file — this decoy
// must not excuse the leak below. Companion of the safe-side boundary case
// in misses/interval-without-clear.ts's own sibling-decoy pair.
export function unrelatedCleanup(existingHandle: number): void {
  const t = existingHandle;
  clearInterval(t);
}
export function startsPollingWithoutClearing(tick: () => void): void {
  const t = setInterval(tick, 1000);
}

// NO HANDLE AT ALL -- the strongest version of this bug, and the one the
// rule missed, because `const $T = ` was mandatory. Nobody can ever clear
// this interval. Auditor's p13 FN-1, isolated in iso/i1.ts [C''].
export function startsUnclearablePolling(tick: () => void): void {
  setInterval(tick, 1000);
}

// `let` instead of `const` -- the shape written whenever the handle is
// reassigned. p13 FN-2.
export function startsPollingLet(tick: () => void): void {
  let t = setInterval(tick, 1000);
  void t;
}

// Stored on a ref, never cleared. p13 FN-3.
export function RefPoller(tick: () => void): void {
  const ref = useRef<number | undefined>(undefined);
  useEffect(() => {
    ref.current = setInterval(tick, 1000) as unknown as number;
  }, []);
}

// Stored on a class field, never cleared. p13 FN-4.
export class Leaky {
  private t: unknown;
  start(tick: () => void): void {
    this.t = setInterval(tick, 1000);
  }
}
