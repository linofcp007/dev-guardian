/**
 * Environment variables the code reads, harvested from the same Semgrep run
 * that produces routes (rules tagged `guardian_kind: 'env'`).
 *
 * Deduplicated by name: a variable read in twelve places is one piece of
 * configuration, and the inventory is about what the app depends on, not how
 * often it asks for it.
 */

export function collectEnvVars(
  semgrepJson: unknown,
): { name: string; file: string; line: number }[] {
  const results = prop(semgrepJson, 'results');
  if (!Array.isArray(results)) return [];

  const seen = new Set<string>();
  const out: { name: string; file: string; line: number }[] = [];

  for (const raw of results) {
    const extra = prop(raw, 'extra');
    if (str(prop(extra, 'metadata'), 'guardian_kind') !== 'env') continue;

    const captured = str(prop(prop(extra, 'metavars'), '$NAME'), 'abstract_content');
    const file = str(raw, 'path');
    if (captured === undefined || file === undefined) continue;

    const name = captured.replace(/^['"`]|['"`]$/g, '');
    if (name.length === 0 || seen.has(name)) continue;
    seen.add(name);

    const line = numProp(prop(raw, 'start'), 'line') ?? 0;
    out.push({ name, file, line });
  }

  return out;
}

function prop(value: unknown, key: string): unknown {
  if (value === null || typeof value !== 'object') return undefined;
  return (value as Record<string, unknown>)[key];
}

function str(value: unknown, key: string): string | undefined {
  const v = prop(value, key);
  return typeof v === 'string' ? v : undefined;
}

function numProp(value: unknown, key: string): number | undefined {
  const v = prop(value, key);
  return typeof v === 'number' ? v : undefined;
}
