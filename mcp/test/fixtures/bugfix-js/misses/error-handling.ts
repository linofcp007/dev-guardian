export function rethrows(): void {
  try { risky(); } catch (e) { throw e; }          // handled, not swallowed
}
export function logsAndHandles(): void {
  try { risky(); } catch (e) { console.error(e); recover(); }
}
function risky(): void { throw new Error('x'); }
function recover(): void {}

// The escape hatch, such as it is. An empty catch whose binding NAME declares
// the intent is excluded — `_`, `_e` and friends (ESLint's
// `caughtErrorsIgnorePattern`, conventionally `^_`, and TypeScript's
// leading-underscore convention for a deliberately unused binding), plus
// `ignore`/`ignored`/`expected`, the Checkstyle/IntelliJ names the Java pack
// already honours and which some JS codebases carry over.
//
// Read the rule's own comment before assuming this makes the rule precise: it
// removed ZERO of the 45 findings this pack produces on this repo's own
// `mcp/src`, because ES2019 optional catch binding took away the identifier a
// naming convention attaches to, and 41 of those 42 are written `catch {`.
export function deliberateUnderscore(): void {
  try { risky(); } catch (_) { }
}
export function deliberateUnderscorePrefixed(): void {
  try { risky(); } catch (_err) { }
}
export function deliberateIgnored(): void {
  try { risky(); } catch (ignored) { }
}
export function deliberateExpected(): void {
  try { risky(); } catch (expected) { }
}

// The same declared intent, with a finalizer attached. A `finally` makes this
// a different AST node — `try { ... } catch ($E) { }` does not match a try
// statement that has one — but it does not make the swallow any less
// deliberate, and the binding still says so. Written from the shape: a
// best-effort cleanup that must run whether or not the risky call threw.
export function deliberateIgnoredWithFinally(): void {
  try { risky(); } catch (ignored) { } finally { releaseLock(); }
}
function releaseLock(): void {}
