export function rethrows(): void {
  try { risky(); } catch (e) { throw e; }          // handled, not swallowed
}
export function logsAndHandles(): void {
  try { risky(); } catch (e) { console.error(e); recover(); }
}
function risky(): void { throw new Error('x'); }
function recover(): void {}
