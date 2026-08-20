/**
 * WRITTEN BY THE AUDITOR (probes/p09_unchecked_find.ts), not by the rule
 * author. Every function here fired at ERROR under the shipped rule
 * `$A.find(...).$PROP`, and NONE of them is a bug: `Array.prototype.find` is
 * one of many `.find(` APIs in the JS ecosystem, and Semgrep OSS has no type
 * inference to tell them apart.
 *
 * The discriminator the rule now uses is the ARGUMENT: Array#find is the
 * only one of these that takes a single literal callback. Mongoose and the
 * Mongo driver take a query OBJECT, jQuery/Cheerio and locator APIs take a
 * SELECTOR STRING, and Immutable#find takes three arguments. So every
 * function below is silent for a reason a mutation can reach: broaden the
 * argument back to `...` and all nine fire again.
 */

// Mongoose: `Model.find(q)` returns a Query, never undefined, and chaining
// is the documented idiom. In any Node backend this fired on every query.
declare const User: {
  find(q: unknown): { sort(s: unknown): unknown; lean(): unknown; exec(): Promise<unknown> };
};
export function mongooseSort(): unknown {
  return User.find({ active: true }).sort({ name: 1 });
}
export function mongooseLean(): unknown {
  return User.find({}).lean();
}
export async function mongooseExec(): Promise<unknown> {
  return User.find({}).exec();
}

// Native MongoDB driver cursor.
declare const collection: { find(q: unknown): { toArray(): Promise<unknown[]> } };
export async function mongoToArray(): Promise<unknown[]> {
  return collection.find({}).toArray();
}

// jQuery / Cheerio: `.find()` returns a collection object.
declare function $(sel: string): {
  find(sel: string): { addClass(c: string): void; text(): string };
};
export function jqueryAddClass(): void {
  $('#root').find('.item').addClass('active');
}
export function cheerioText(): string {
  return $('body').find('h1').text();
}

// Locator APIs (Playwright / testing-library shaped).
declare const page: { find(sel: string): { click(): Promise<void> } };
export async function locatorClick(): Promise<void> {
  await page.find('button').click();
}

// Repository "find all" returning an array — `.length` is always safe.
declare const repo: { find(q: unknown): unknown[] };
export function findAllLength(): number {
  return repo.find({}).length;
}

// Immutable.js `find(fn, ctx, notSetValue)` — a callback, but three
// arguments, and it returns the supplied default rather than undefined.
declare const imm: { find(f: (x: number) => boolean, c?: unknown, n?: number): number };
export function immutableWithDefault(): string {
  return imm.find((x) => x > 0, undefined, 0).toFixed(2);
}
