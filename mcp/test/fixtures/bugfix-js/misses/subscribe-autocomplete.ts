/**
 * WRITTEN BY THE AUDITOR (probes/p14_subscribe.ts). Two subscriptions that
 * need no unsubscribe, and both fired.
 */

import { useEffect } from 'react';
declare function onNext(): void;

// take(1) / takeUntil complete the stream themselves — the idiomatic RxJS
// way to subscribe without ever unsubscribing. Silent because of the
// pipe-operator exclusion.
//
// It is NOT silent "only because of it", which is what this comment used to
// claim: measured by ablation, deleting the operator-name `metavariable-
// regex` leaves this file completely silent, because the `pattern-not` around
// it still excludes every `.pipe(...).subscribe(...)`. The regex is what keeps
// that exclusion NARROW, and a fixture that stays silent either way cannot
// show it doing anything. The one that can is `MappedWatcher` in
// `hits/subscribe-without-unsubscribe.ts`: `map` does not complete the
// stream, so it must still fire, and it stops firing the moment the regex
// goes. A near-miss proves an exclusion exists; only a hit proves it is the
// right width.
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
