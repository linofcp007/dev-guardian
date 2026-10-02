/**
 * Writes a SARIF import (`./importSarif.ts`) to the project's history: one
 * `sarif_import` scan per run, its findings, and the identities of those the
 * log gave no fingerprints for (feature `sarif-import`).
 *
 * PHASE 4 STUB — throws until it is implemented. The failing tests that pin
 * its behaviour are `test/integration/importSarif.test.ts` and
 * `test/integration/importSarifOpenSet.test.ts`.
 */

import type { Storage } from '../storage/index.js';
import type { SarifImportResult } from './importSarif.js';

export interface PersistSarifImportOptions {
  /** The log's path relative to the project, or its basename when it was outside it. */
  sourceFile: string;
}

/** The scans written, one per run, in run order. */
export function persistSarifImport(
  _storage: Storage,
  _projectPath: string,
  _result: SarifImportResult,
  _opts: PersistSarifImportOptions,
): Array<{ scan_id: string }> {
  throw new Error('NotImplemented: persistSarifImport');
}
