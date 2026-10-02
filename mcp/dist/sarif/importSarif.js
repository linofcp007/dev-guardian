/**
 * SARIF 2.1.0 log → canonical findings and counts (feature `sarif-import`).
 *
 * PHASE 4 STUB — the types are the design's data model; `importSarif` throws
 * until it is implemented. The failing tests that pin its behaviour are
 * `test/unit/sarif/importSarif.test.ts` (and the integration/e2e files named
 * in the feature's test plan).
 *
 * Contract the tests hold it to:
 *   - pure: text in, result out — no file, URL or process is opened for
 *     anything the log names (US-1.AC-15); paths are resolved textually
 *     against `ctx.projectPath`;
 *   - a log that is not JSON, does not declare `version: "2.1.0"`, or has no
 *     `runs` array (an empty file included) is refused by THROWING an Error
 *     whose `code` is `'invalid_sarif'` and whose message names the field or
 *     index at fault — never content of the log (US-1.AC-10, US-1.AC-18);
 *   - one `SarifImportRun` per `runs[]` entry, in order.
 */
export function importSarif(_text, _ctx) {
    throw new Error('NotImplemented: importSarif');
}
//# sourceMappingURL=importSarif.js.map