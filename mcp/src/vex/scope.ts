/**
 * What a VEX document is about: the scan `export_vex` states the
 * vulnerabilities of — the project's newest usable scan of a CVE-source type
 * (`CVE_SOURCE_SCAN_TYPES`: scan_deps, deps_audit, security_scan_full),
 * judged on its `deps` slot, the read the dashboard and `risk_score` make.
 *
 * One function, so that `suppress_finding` promises `exportable` and names
 * the copies of a statement over exactly the findings `export_vex` will
 * read. It judged them over every scan type: a container image's CVE
 * (`scan_containers`' trivy-image) was promised `exportable: true` and never
 * exported, and a dependency copy suppressed beside it got a warning about
 * the image's copy.
 */

import { findLatestUsable, type UsableScan } from '../history/openSet.js';
import type { Storage } from '../storage/index.js';
import { CVE_SOURCE_SCAN_TYPES } from '../types.js';

export function vexSourceScan(storage: Storage, projectPath: string): UsableScan {
  return findLatestUsable(storage, projectPath, CVE_SOURCE_SCAN_TYPES, { slot: 'deps' });
}
