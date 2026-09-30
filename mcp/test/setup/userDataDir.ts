/**
 * Points dev-guardian's per-user data directory at a temp directory in every
 * vitest worker (and every process a test spawns, which inherits the
 * environment).
 *
 * The database fallback and the registry of databases dev-guardian created
 * live there (`storage/userData.ts`): `%LOCALAPPDATA%\dev-guardian` on
 * Windows, `$XDG_DATA_HOME/dev-guardian` or `~/.local/share/dev-guardian`
 * elsewhere. A test must never create databases or registry entries in the
 * real one. `GUARDIAN_DATA_DIR` is used rather than LOCALAPPDATA /
 * XDG_DATA_HOME themselves because scanners the tests spawn keep their caches
 * under those (Trivy's vulnerability database among them), and moving them
 * would make every such test download again.
 *
 * The run's own directory is made by the global setup
 * (`test/setup/tempLeftovers.ts`, which also removes it afterwards); this is
 * only the fallback for a worker started without it, and it is per process.
 */

import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

process.env['GUARDIAN_DATA_DIR'] ??= mkdtempSync(join(tmpdir(), 'dev-guardian-test-data-'));
