/**
 * Points dev-guardian's per-user data directory at a temp directory in every
 * vitest worker (and every process a test spawns, which inherits the
 * environment).
 *
 * The database fallback lives there (`storage/db.ts#userDataDir`):
 * `%LOCALAPPDATA%\dev-guardian` on Windows, `$XDG_DATA_HOME/dev-guardian` or
 * `~/.local/share/dev-guardian` elsewhere. A test that exercises the fallback
 * must never create databases in the real one. `GUARDIAN_DATA_DIR` is used
 * rather than LOCALAPPDATA / XDG_DATA_HOME themselves because scanners the
 * tests spawn keep their caches under those (Trivy's vulnerability database
 * among them), and moving them would make every such test download again.
 *
 * One directory per run is shared by the workers: every database under it
 * is keyed by the hash of a test's own temp project, so they never meet.
 */

import { tmpdir } from 'node:os';
import { join } from 'node:path';

process.env['GUARDIAN_DATA_DIR'] ??= join(tmpdir(), 'dev-guardian-test-data');
