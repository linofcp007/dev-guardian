/**
 * Exact decimals for the METRIC judge (`metric-lines/1`: "values compare as
 * exact decimals"). A value is `coef × 10^exp`, the coefficient a BigInt, so
 * the boundary of a tolerance is the decimal the line printed: 2% of 120 is
 * 2.4 exactly, and 122.4 − 120 is 2.4 exactly — in binary floating point it
 * is 2.4000000000000057, which put a value printed exactly at its tolerance
 * past it.
 *
 * The inputs are bounded by the line's grammar (at most 15 integer digits, 9
 * fraction digits and a 3-digit exponent) or are finite JavaScript numbers,
 * so a coefficient never grows past a few thousand digits.
 */

export interface Decimal {
  readonly coef: bigint;
  readonly exp: number;
}

/** A printed decimal: `-12.5`, `1.5e3`, `0`, `2.4e-7` — the forms `String(number)` and the line's grammar write. */
const DECIMAL = /^(-?)([0-9]+)(?:\.([0-9]+))?(?:[eE]([-+]?[0-9]+))?$/;

const pow10Cache = new Map<number, bigint>();
function pow10(n: number): bigint {
  const hit = pow10Cache.get(n);
  if (hit !== undefined) return hit;
  const v = 10n ** BigInt(n);
  if (pow10Cache.size < 4096) pow10Cache.set(n, v);
  return v;
}

/** The exact value of a printed decimal, or null when `text` is not one. */
export function parseDecimal(text: string): Decimal | null {
  const m = DECIMAL.exec(text);
  if (m === null) return null;
  const int = m[2] ?? '0';
  const frac = m[3] ?? '';
  const exp = Number(m[4] ?? '0') - frac.length;
  if (!Number.isSafeInteger(exp)) return null;
  const coef = BigInt(int + frac);
  return { coef: m[1] === '-' ? -coef : coef, exp };
}

/** A finite JavaScript number, exactly as it prints (`String(n)`). */
export function decimalOfNumber(n: number): Decimal | null {
  return Number.isFinite(n) ? parseDecimal(String(n)) : null;
}

function aligned(a: Decimal, b: Decimal): [bigint, bigint, number] {
  const exp = Math.min(a.exp, b.exp);
  return [a.coef * pow10(a.exp - exp), b.coef * pow10(b.exp - exp), exp];
}

export function subtract(a: Decimal, b: Decimal): Decimal {
  const [x, y, exp] = aligned(a, b);
  return { coef: x - y, exp };
}

export function add(a: Decimal, b: Decimal): Decimal {
  const [x, y, exp] = aligned(a, b);
  return { coef: x + y, exp };
}

export function multiply(a: Decimal, b: Decimal): Decimal {
  return { coef: a.coef * b.coef, exp: a.exp + b.exp };
}

/** `a × 10^-n`: a percentage of `a` is `multiply(a, n)` shifted by 2. */
export function shift(a: Decimal, n: number): Decimal {
  return { coef: a.coef, exp: a.exp + n };
}

export function negate(a: Decimal): Decimal {
  return { coef: -a.coef, exp: a.exp };
}

export function absolute(a: Decimal): Decimal {
  return a.coef < 0n ? negate(a) : a;
}

/** -1, 0 or 1. */
export function compare(a: Decimal, b: Decimal): number {
  const [x, y] = aligned(a, b);
  return x < y ? -1 : x > y ? 1 : 0;
}

export function minimum(a: Decimal, b: Decimal): Decimal {
  return compare(a, b) <= 0 ? a : b;
}

export function maximum(a: Decimal, b: Decimal): Decimal {
  return compare(a, b) >= 0 ? a : b;
}

/** Half of `a`, exactly (`× 5 × 10^-1`): the median of an even count. */
export function half(a: Decimal): Decimal {
  return { coef: a.coef * 5n, exp: a.exp - 1 };
}

/** The plain decimal digits of `a`, no exponent and no trailing zeros: `2.4`, `-10`, `0`. */
export function decimalString(a: Decimal): string {
  let coef = a.coef;
  let exp = a.exp;
  if (coef === 0n) return '0';
  while (exp < 0 && coef % 10n === 0n) {
    coef /= 10n;
    exp += 1;
  }
  const negative = coef < 0n;
  const digits = (negative ? -coef : coef).toString();
  let body: string;
  if (exp >= 0) body = digits + '0'.repeat(exp);
  else {
    const point = digits.length + exp;
    body = point > 0 ? `${digits.slice(0, point)}.${digits.slice(point)}` : `0.${'0'.repeat(-point)}${digits}`;
  }
  return negative ? `-${body}` : body;
}

/** The nearest JavaScript number — the exact decimal read with `Number()`, as the fixture reads one. */
export function decimalNumber(a: Decimal): number {
  return Number(decimalString(a));
}
