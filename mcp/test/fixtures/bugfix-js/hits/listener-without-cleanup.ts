import { useEffect } from 'react';

export function ResizeWatcher(onResize: () => void): void {
  useEffect(() => {
    window.addEventListener('resize', onResize);
  }, []);
}

// Three-argument form with an options object. The rule's pattern took
// EXACTLY two arguments, so `{ passive: true }` / `{ capture: true }` /
// `{ once: true }` -- the dominant modern shape -- were all invisible.
// Auditor's p12 FN-1, isolated in iso/i1.ts [B].
export function ScrollWatcher(onScroll: () => void): void {
  useEffect(() => {
    window.addEventListener('scroll', onScroll, { passive: true });
  }, []);
}

// Legacy boolean capture argument -- same arity gap. p12 FN-2.
export function ClickWatcher(onKey: (e: unknown) => void): void {
  useEffect(() => {
    document.addEventListener('click', onKey, true);
  }, []);
}

// Branch suppression: an early `return` of a cleanup used to silence the
// registration that follows it -- the guard on the `if` suppressed the
// branch where the bug is. The exclusion now requires the `return` to come
// AFTER the registration. Auditor's p12 FN-4.
export function ConditionalWatcher(onResize: () => void, enabled: boolean): void {
  useEffect(() => {
    if (enabled) {
      return () => undefined;
    }
    window.addEventListener('resize', onResize);
  }, [enabled]);
}
