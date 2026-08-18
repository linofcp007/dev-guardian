export function swallows(): void {
  try { risky(); } catch (e) { }
}
function risky(): void { throw new Error('x'); }
