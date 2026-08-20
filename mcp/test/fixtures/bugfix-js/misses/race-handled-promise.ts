/**
 * WRITTEN BY THE AUDITOR (probes/p06_race_condition.ts). Every call below is
 * a genuine promise from a genuine repository — the receiver passes this
 * rule's `$O` name check — and every one of them is DELIBERATELY not
 * awaited on its own line, in a way that hands the promise to something
 * that does await or handle it.
 *
 * The first one matters beyond itself: `void repo.save(a)` is the fix this
 * rule's own message prescribes ("torne-o explícito com void"), and it did
 * not silence the rule. A rule whose prescribed fix does not work teaches
 * people to ignore it.
 *
 * One exclusion clause per function, so each clause is independently
 * load-bearing: delete any single `pattern-not-inside` and exactly one
 * function here starts firing.
 */

declare const repo: { save(v: unknown): Promise<void>; update(v: unknown): Promise<void> };
declare function handle(e: unknown): void;
declare function done(): void;

// `void` — the rule's own prescribed remedy.
export async function voided(a: unknown): Promise<void> {
  void repo.save(a);
}

// Gathered by Promise.all and awaited as a batch.
export async function gathered(a: unknown, b: unknown): Promise<void> {
  await Promise.all([repo.save(a), repo.save(b)]);
}

// Handled fire-and-forget.
export async function caught(a: unknown): Promise<void> {
  repo.save(a).catch(handle);
}

// Continued with .then.
export async function chainedThen(a: unknown): Promise<void> {
  repo.save(a).then(done);
}

// Continued with .finally.
export async function chainedFinally(a: unknown): Promise<void> {
  repo.save(a).finally(done);
}

// Captured, then awaited later — deliberate concurrency.
export async function deferred(a: unknown, b: unknown): Promise<void> {
  const pa = repo.save(a);
  const pb = repo.update(b);
  await pa;
  await pb;
}

// Returned from an expression-bodied arrow: the value IS propagated, to
// whoever consumes the array of promises. Deliberately NOT written as
// `await Promise.all(ids.map(...))` — inside a `Promise.all(...)` call the
// Promise clause above would already exclude it, so that spelling would
// prove nothing about anything else.
//
// Written this way, it is covered by the `return $O.$M(...)` clause rather
// than by a clause of its own: Semgrep treats an expression-bodied arrow's
// body AS a return, which is why the dedicated `(...) => $O.$M(...)` clause
// drafted for this case turned out to be dead and was removed.
export async function mappedReturn(ids: string[]): Promise<void> {
  const pending = ids.map((id) => repo.save(id));
  await Promise.all(pending);
}
