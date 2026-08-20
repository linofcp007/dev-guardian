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
