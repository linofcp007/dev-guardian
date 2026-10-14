/**
 * A part of the hooks bundle (`src/hooksEntry.ts` says why it is split): what
 * a write runs — the secret scan, the Claude Code settings guard and the
 * database registry guard. Built into `dist/hooksWrite.js`.
 */
export * as secretScan from './hooks/secretScan.js';
export * as settingsGuard from './hooks/settingsGuard.js';
export * as dataRegistry from './hooks/dataRegistry.js';
