/**
 * WRITTEN BY THE AUDITOR (probes/p12_listener.ts). The counterpart to the
 * three new cases in hits/listener-without-cleanup.ts: widening the rule's
 * arity from exactly two arguments to `(...)` must not start flagging the
 * modern registrations that DO clean up after themselves.
 *
 * Each is silent because the effect returns a cleanup AFTER the
 * registration — the ordering the exclusion now requires. Delete that
 * clause and all three fire.
 */

import { useEffect, useRef } from 'react';
declare function onResize(): void;
declare function onKey(e: unknown): void;

// AbortController signal — the modern removal idiom, three arguments.
export function AbortWatcher(): void {
  useEffect(() => {
    const c = new AbortController();
    window.addEventListener('resize', onResize, { signal: c.signal });
    return () => c.abort();
  }, []);
}

// Options object plus an explicit removeEventListener.
export function PassiveWatcher(): void {
  useEffect(() => {
    window.addEventListener('scroll', onResize, { passive: true });
    return () => window.removeEventListener('scroll', onResize);
  }, []);
}

// Ref-scoped listener whose cleanup is returned after an early guard
// return — the guard returns nothing, so it is not a cleanup.
export function RefWatcher(on: boolean): void {
  const ref = useRef<HTMLElement | null>(null);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    el.addEventListener('click', onKey);
    return () => el.removeEventListener('click', onKey);
  }, [on]);
}
