/**
 * WRITTEN BY THE AUDITOR (probes/p14_subscribe.ts). Two subscriptions that
 * need no unsubscribe, and both fired.
 */

import { useEffect } from 'react';
declare function onNext(): void;

// take(1) / takeUntil complete the stream themselves — the idiomatic RxJS
// way to subscribe without ever unsubscribing. Silent because of the
// pipe-operator exclusion, and only because of it.
declare const finite$: { pipe(op: unknown): { subscribe(cb: () => void): unknown } };
declare function take(n: number): unknown;
export function AutoComplete(): void {
  useEffect(() => {
    finite$.pipe(take(1)).subscribe(onNext);
  }, []);
}

// A `.subscribe()` that is not a subscription at all — a mailing-list
// registration, explicitly voided. Name collision only. Silent because of
// the `void` exclusion.
declare const mailingList: { subscribe(email: string): Promise<void> };
export function NameCollision(): void {
  useEffect(() => {
    void mailingList.subscribe('a@b.c');
  }, []);
}
