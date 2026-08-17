export function firstGroup(s: string): string {
  return s.match(/x(\d)/)[1];
}
