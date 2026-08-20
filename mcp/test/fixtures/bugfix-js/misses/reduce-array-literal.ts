/**
 * WRITTEN BY THE AUDITOR (probes/p07_reduce_parseint.ts). `reduce` without
 * an initial value throws only on an EMPTY array; an array literal with
 * elements provably is not one, so this cannot throw and must not be
 * reported. Silent because of the array-literal exclusion, and only
 * because of it.
 */
declare function add(a: number, b: number): number;
export const total = [1, 2, 3].reduce(add);
