export function toNumberWithRadix(raw: string): number {
  return parseInt(raw, 10);
}
export function toNumberViaNumber(raw: string): number {
  return Number(raw);
}
