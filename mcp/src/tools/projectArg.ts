/**
 * A tool's `project_path`, resolved — the opening about forty handlers each
 * spelt out as its own try / catch (dg-maint finding 14):
 *
 *     const projectPath = toolProjectPath(inp.project_path);
 *     if (typeof projectPath !== 'string') return projectPath;
 *
 * An unusable path is answered the same way by every tool: the code
 * `projectPathErrorCode` gives (`target_not_found` for a path that does not
 * exist, `unsupported_target` otherwise), so hosts and skills handle one
 * failure. A tool that answers it otherwise — a WordPress install's own
 * code, a wrapper that lets the scan pipeline report it — keeps its own.
 */

import { projectPathErrorCode, resolveProjectPath } from '../platform/projectPath.js';
import type { DomainError } from '../types.js';

/** What a tool returns, as it is, for an unusable `project_path`. */
interface ProjectPathRefusal {
  ok: false;
  error: DomainError;
}

/** `raw` resolved (`platform/projectPath.ts#resolveProjectPath`), or the refusal the tool returns. */
export function toolProjectPath(raw: string | undefined): string | ProjectPathRefusal {
  try {
    return resolveProjectPath(raw).path;
  } catch (e) {
    return { ok: false, error: { code: projectPathErrorCode(e), message: (e as Error).message } };
  }
}
