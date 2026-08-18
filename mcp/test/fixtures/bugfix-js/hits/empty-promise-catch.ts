export function fireAndIgnore(p: Promise<void>): void {
  p.catch(() => {});
}
export function fireAndIgnoreNamed(p: Promise<void>): void {
  p.catch(function (err) {});
}
// Regression: an earlier version of this file's comment claimed the arrow
// branch only matches a zero-parameter `() => {}`. It does not stop there —
// confirmed directly against this exact rule: a one-parameter arrow with an
// unused error parameter (the more common real-world shape) fires too.
export function fireAndIgnoreArrowWithParam(p: Promise<void>): void {
  p.catch((err) => {});
}
