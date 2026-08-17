export function firstGroupOptional(s: string): string | undefined {
  return s.match(/x(\d)/)?.[1];
}

export function firstGroupGuarded(s: string): string {
  const m = s.match(/x(\d)/);
  if (m) {
    return m[1] ?? '';
  }
  return '';
}
