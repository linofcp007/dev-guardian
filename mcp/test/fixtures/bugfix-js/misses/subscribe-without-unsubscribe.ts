import { useEffect } from 'react';

interface Subscription {
  unsubscribe(): void;
}
interface Observable {
  subscribe(cb: () => void): Subscription;
}

export function Watcher(source: Observable, onNext: () => void): void {
  useEffect(() => {
    const sub = source.subscribe(onNext);
    return () => sub.unsubscribe();
  }, []);
}

// Module scope, no enclosing useEffect anywhere in the file — proves the
// rule's `pattern-inside: useEffect(...)` clause is load-bearing (bugfix-
// rules-jsts fix wave: it was previously untested in this direction).
// Without it, this rule would fire on every .subscribe() in a codebase,
// useEffect or not.
declare const globalSource: Observable;
globalSource.subscribe(() => {
  console.log('tick');
});
