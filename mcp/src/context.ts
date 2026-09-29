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
  /**
   * Set when the project's database was not used (foreign, not writable,
   * untrusted schema, or no usable per-user data directory): why, and where
   * the history goes. `health_status.storage_warning` and every scan's
   * `warnings` carry it.
   */
  storageWarning?: string;
  /**
   * The CI gate's `--rules-ref` only (`ci/runScans.ts`) — never the MCP
   * server, whose tools' inputs a model fills: the repository configuration
   * copied from that ref (`ci/refConfig.ts#copyConfigFromRef`). Every scan in
   * this context reads the project's Semgrep rules, `.guardianignore`,
   * `.trivyignore` and `.bandit` from `root` instead of the scanned tree
   * (`InvokeContext.rulesProjectPath` and `configRoot`).
   */
  repoConfigFromRef?: {
    /** The directory holding the copies, at their project-relative paths. */
    root: string;
    /** The ref as given, and the commit it named. */
    ref: string;
    commit: string;
  };
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
