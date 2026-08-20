export function swallows(): void {
  try { risky(); } catch (e) { }
}

// Optional catch binding (ES2019). The dominant modern shape in TS, because
// `catch (e)` with an unused `e` trips noUnusedLocals/noUnusedParameters.
// Auditor's p01 FN-1: invisible to the single `catch ($E) { }` pattern.
export function swallowsNoBinding(): void {
  try { risky(); } catch { }
}

// A `finally` clause does not un-swallow anything, but it did silence the
// rule: `try { ... } catch ($E) { }` does not match a try statement that
// also has a finalizer. Auditor's p01 FN-2, isolated in iso/i1.ts [A].
export function swallowsWithFinally(): void {
  try { risky(); } catch (e) { } finally { done(); }
}

// Both at once — the branch that neither of the two above can cover.
export function swallowsNoBindingWithFinally(): void {
  try { risky(); } catch { } finally { done(); }
}

function risky(): void { throw new Error('x'); }
function done(): void {}
