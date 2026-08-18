import { useEffect } from 'react';

export function ResizeWatcher(onResize: () => void): void {
  useEffect(() => {
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, []);
}

// Module scope, no enclosing useEffect anywhere in the file — proves the
// rule's `pattern-inside: useEffect(...)` clause is load-bearing (bugfix-
// rules-jsts fix wave: it was previously untested in this direction).
// Without it, this rule would fire on every addEventListener in a
// codebase, useEffect or not.
window.addEventListener('online', () => {
  console.log('back online');
});
