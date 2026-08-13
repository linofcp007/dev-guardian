/**
 * Hop 3 of the three-hop import chain `validate_finding`'s e2e test measures:
 * users.controller.ts (root, hop 0) -> users.service.ts (hop 1) ->
 * identifiers.util.ts (hop 2) -> slug.util.ts (hop 3, this file).
 *
 * This is the file mcp/test/e2e/validateFindingFixture.test.ts seeds a
 * finding in and asserts the verdict comes back `reachable` with
 * `hops === 3`. Do not shorten or lengthen the chain without updating that
 * test AND the pinned import-edge list in
 * mcp/test/e2e/rulePackFixture.test.ts ("reports env vars, ports and
 * per-language coverage from the same run").
 */
export function toSafeSlug(id: string): string {
  return id.trim().toLowerCase();
}
