import { useEffect } from 'react';

interface Subscription {
  unsubscribe(): void;
}
interface Observable {
  subscribe(cb: () => void): Subscription;
}

export function Watcher(source: Observable, onNext: () => void): void {
  useEffect(() => {
    source.subscribe(onNext);
  }, []);
}

// Branch suppression: a cleanup returned from ONE branch used to silence an
// uncleaned subscription in the OTHER, because the exclusion asked only
// whether a `return` existed ANYWHERE in the effect. It now has to come
// after a subscribe on the SAME receiver, so the store's cleanup no longer
// covers for the stream's leak. Auditor's p14 FN-1.
//
// The limitation this fixture also draws the boundary of: `pattern-not-
// inside` cannot be made relative to the occurrence being judged, only to
// the enclosing node. If both subscriptions were on `source`, the cleaned
// one would satisfy the ordering on the leaked one's behalf and this would
// go silent again — see the rule's own comment.
export function BranchWatcher(
  source: Observable,
  store: { subscribe(cb: () => void): () => void },
  onNext: () => void,
  flag: boolean,
): void {
  useEffect(() => {
    if (flag) {
      const stop = store.subscribe(onNext);
      return () => stop();
    }
    source.subscribe(onNext);
  }, [flag]);
}

// A piped subscription whose operator does NOT complete the stream. `map`
// transforms every value and passes it through; the stream runs until
// somebody unsubscribes, and nobody does, so this leaks exactly as much as an
// unpiped `subscribe`.
//
// It is here because ablation measured the pipe-operator exclusion's
// OPERATOR-NAME constraint dead. The exclusion covers
// `.pipe(...).subscribe(...)` wholesale; what stops it swallowing a
// non-completing operator is the name constraint on the piped argument, and
// deleting that left every fixture unchanged — `misses/subscribe-
// autocomplete.ts`'s `take(1)` stays silent whether the constraint is there
// or not, because the wider exclusion still covers it. A near-miss can only
// prove an exclusion EXISTS. Proving it is the right WIDTH needs a hit.
//
// The operator is a named function on purpose, and this cost a measurement to
// learn: written the obvious way, `map((x) => x)`, this fixture is silent —
// not because of the pipe exclusion but because of the CLEANUP exclusion two
// clauses above. An expression-bodied arrow is a `return`, and that clause
// asks only whether a return exists anywhere inside the effect, so any nested
// callback satisfies it on the leak's behalf. `map((x) => { return x; })`
// goes silent too. That is the same "cannot be made relative to the
// occurrence being judged" limitation the BranchWatcher note above describes,
// one level further in — recorded here, not fixed here.
interface Piped {
  pipe(op: unknown): { subscribe(cb: () => void): Subscription };
}
declare function map(f: unknown): unknown;
declare function normalise(x: number): number;
export function MappedWatcher(source: Piped, onNext: () => void): void {
  useEffect(() => {
    source.pipe(map(normalise)).subscribe(onNext);
  }, []);
}
