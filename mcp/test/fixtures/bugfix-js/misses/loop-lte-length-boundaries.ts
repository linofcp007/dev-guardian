/**
 * WRITTEN BY THE AUDITOR (probes/p04_loop_lte_length.ts). `<=` against
 * `.length` is deliberately correct whenever the loop is NOT indexing the
 * array with the loop variable, and the rule fired at ERROR on all of these.
 *
 * The last one was the sharpest: `for (let n = 0; n <= pages.length; n++)`
 * that never indexes anything at all still got the message "a última
 * iteração lê $A[$A.length], que é sempre undefined" — a statement about
 * code that does not exist.
 *
 * The rule now matches the READ (`$A[$I]`) and uses the loop only as the
 * containing context, so all of these are silent for the same single
 * reason: delete the `pattern-inside` and they stay silent, but delete the
 * requirement that the body index `$A` with `$I` — by matching the loop
 * itself again — and every one of them fires.
 */

declare const items: number[];
declare const pages: string[];
declare function insertAt(i: number): void;
declare function emit(s: string): void;

// 1-based iteration, indexing with i-1. Classic report/pagination loop.
export function oneBased(): void {
  for (let i = 1; i <= pages.length; i++) {
    emit(`page ${i}: ${pages[i - 1]}`);
  }
}

// Iterating over INSERTION POSITIONS — there are length+1 of them.
export function insertionSlots(): void {
  for (let i = 0; i <= items.length; i++) {
    insertAt(i);
  }
}

// Iterating over PREFIXES / slice boundaries — length+1 of them.
export function prefixes(s: string): string[] {
  const out: string[] = [];
  for (let i = 0; i <= s.length; i++) {
    out.push(s.slice(0, i));
  }
  return out;
}

// `$A.length` belongs to a different array than the one being emitted; the
// loop never indexes anything.
export function parallelCounter(): void {
  for (let n = 0; n <= pages.length; n++) { emit(String(n)); }
}

// A WRITE at the trailing index is an append, not an out-of-range read —
// the same distinction the index-at-length rule already draws. Silent
// because of the `$A[$I] = ...` exclusion, and only because of it.
export function fillsOneExtraSlot(): void {
  for (let i = 0; i <= items.length; i++) { items[i] = 0; }
}
