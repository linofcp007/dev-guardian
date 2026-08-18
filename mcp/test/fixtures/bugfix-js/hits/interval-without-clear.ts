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
