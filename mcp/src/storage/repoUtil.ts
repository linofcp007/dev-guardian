/**
 * Helpers shared across repository modules.
 *
 * - `nowIso()` is the single source of truth for timestamps written to the DB
 *   so tests can stub it in one place.
 * - `boolToInt` / `intToBool` translate SQLite's 0/1 ints to JS booleans.
 * - `parseJsonArray` / `parseJsonObject` defend against migration drift by
 *   tolerating malformed stored JSON instead of throwing.
 */

export function nowIso(): string {
  return new Date().toISOString();
}

export function boolToInt(value: boolean | undefined): 0 | 1 {
  return value ? 1 : 0;
}

export function intToBool(value: number | null | undefined): boolean {
  return value === 1;
}

export function parseJsonArray<T>(raw: string | null | undefined, fallback: T[] = []): T[] {
  if (raw === null || raw === undefined || raw === '') return fallback;
  try {
    const parsed = JSON.parse(raw) as unknown;
    return Array.isArray(parsed) ? (parsed as T[]) : fallback;
  } catch {
    return fallback;
  }
}

export function parseJsonObject<T extends Record<string, unknown>>(
  raw: string | null | undefined,
  fallback: T,
): T {
  if (raw === null || raw === undefined || raw === '') return fallback;
  try {
    const parsed = JSON.parse(raw) as unknown;
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as T)
      : fallback;
  } catch {
    return fallback;
  }
}
