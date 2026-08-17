export function fireAndIgnore(p: Promise<void>): void {
  p.catch(() => {});
}
export function fireAndIgnoreNamed(p: Promise<void>): void {
  p.catch(function (err) {});
}
