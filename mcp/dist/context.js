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
export {};
//# sourceMappingURL=context.js.map