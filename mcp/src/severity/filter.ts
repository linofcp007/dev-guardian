/**
 * Severity filter.
 *
 * Every tool that accepts `severity_min` runs its raw findings through
 * `filterFindings()` before persistence. `passes()` is exported separately
 * for callers that need the predicate without building an array.
 */

import type { Severity } from '../types.js';
import { SEVERITY_ORDER } from '../types.js';

export function passes(severity: Severity, min?: Severity): boolean {
  if (!min) return true;
  return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[min];
}

export function filterFindings<T extends { severity: Severity }>(
  items: T[],
  min?: Severity,
): T[] {
  if (!min) return items;
  return items.filter((item) => passes(item.severity, min));
}
