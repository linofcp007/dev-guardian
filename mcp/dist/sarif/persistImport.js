/**
 * Writes a SARIF import (`./importSarif.ts`) to the project's history: one
 * `sarif_import` scan per run, its findings, and the identities of those the
 * log gave no fingerprints for (feature `sarif-import`).
 *
 * PHASE 4 STUB — throws until it is implemented. The failing tests that pin
 * its behaviour are `test/integration/importSarif.test.ts` and
 * `test/integration/importSarifOpenSet.test.ts`.
 */
/** The scans written, one per run, in run order. */
export function persistSarifImport(_storage, _projectPath, _result, _opts) {
    throw new Error('NotImplemented: persistSarifImport');
}
//# sourceMappingURL=persistImport.js.map