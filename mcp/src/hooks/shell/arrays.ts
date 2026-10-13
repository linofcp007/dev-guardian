/**
 * Appending a user-sized array to another, for the shell guard's modules: a
 * command line decides how many elements there are, and the spread
 * (`into.push(...from)`) throws past about 125 000 of them. Moved out of
 * `bashGuard.ts` with the modules that need it.
 *
 * Pure functions. No I/O. No dependencies.
 */

/**
 * `into.push(...from)` without the spread: a spread passes every element as an
 * argument, and past ~125 000 of them (`rm a a a … /`, 245 KB) the engine
 * throws RangeError — which the hook turned into no decision at all (fix
 * round 3, I-1). Every append of a user-sized array in the shell guard goes here.
 */
export function pushAll<T>(into: T[], from: readonly T[]): void {
  for (const x of from) into.push(x);
}
