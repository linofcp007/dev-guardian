/**
 * Types for `create_fix_pr` — deciding which findings are fixable at all,
 * and how they group into one candidate pull request per ecosystem or
 * scanner (design doc `docs/superpowers/specs/2026-08-16-create-fix-pr-design.md`).
 *
 * `UpgradeStep` mirrors `depsUpdatePlan.ts`'s interface of the same name.
 * It is declared here, not imported, because that interface has no `export`
 * — this feature reads the shape off `deps_update_plan`'s JSON result, the
 * way `auditExecutive` already treats other sub-tools' results.
 */
export {};
//# sourceMappingURL=types.js.map