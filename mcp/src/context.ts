/**
 * Per-server and per-call contexts.
 *
 * `PluginContext` is constructed once at startup and shared by every tool
 * and resource handler. It carries the persistent dependencies (storage,
 * detected shell, scripts directory, and a way to send MCP notifications).
 *
 * `ToolContext` is constructed per tool invocation by the scan-tool
 * factory and carries the per-call concerns (resolved project path,
 * scan_id, AbortSignal, progress emitter).
 */

import type { ShellChoice } from './platform/shellProbe.js';
import type { ProgressEmitter, ProgressNotifier } from './progress/progressEmitter.js';
import type { Storage } from './storage/index.js';

export interface PluginContext {
  storage: Storage;
  /** Detected shell, or null when no usable shell was found on the host. */
  shell: ShellChoice | null;
  /** Absolute path to `dev-guardian/scripts/`. */
  scriptsDir: string;
  /** Sends `notifications/progress` over the active transport. */
  progressNotifier: ProgressNotifier;
  /** Warning surfaced when the DB had to fall back to a temp location. */
  storageWarning?: string;
}

export interface ToolContext {
  plugin: PluginContext;
  scanId: string;
  /** Absolute path to the project being scanned. Resolved by the factory. */
  projectPath: string;
  /** Honoured by `shellRunner.run`; tools should pass it through. */
  signal: AbortSignal;
  progress: ProgressEmitter;
  /** Optional structured logging callback; tools forward stderr lines here. */
  onLog?: (line: string) => void;
}
