/**
 * Deliberately unreferenced. No file in this fixture imports it, and it
 * imports nothing itself, so it must never appear anywhere in
 * `AttackSurfaceSnapshot.imports` — neither as an importer nor as a target.
 *
 * This is the "genuinely orphaned file" fixture for `validate_finding`'s e2e
 * test (mcp/test/e2e/validateFindingFixture.test.ts), which seeds a finding
 * here and asserts the verdict comes back `unreachable`.
 *
 * If a future change makes anything import this file, add a NEW orphan file
 * for that test instead of repurposing this one — it depends on this file
 * staying unreferenced.
 */
export function describeLegacyExport(name: string): string {
  return `legacy export: ${name}`;
}
