export function logsError(p: Promise<void>): void {
  p.catch((err) => { console.error(err); });        // handled, not swallowed
}
export function rethrowsError(p: Promise<void>): void {
  p.catch((err) => { throw err; });                  // re-raised, not swallowed
}
