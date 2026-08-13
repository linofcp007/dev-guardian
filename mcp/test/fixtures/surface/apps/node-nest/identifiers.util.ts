/**
 * Hop 2 of the three-hop import chain — see slug.util.ts's doc comment for
 * the full chain and which test depends on it.
 */
import { toSafeSlug } from './slug.util.js';

export function normalizeId(id: string): string {
  return toSafeSlug(id);
}
