/**
 * A part of the hooks bundle (`src/hooksEntry.ts` says why it is split): what
 * every PreToolUse on Bash / PowerShell runs — the catastrophic-command guard
 * and the install vetting's cheap gate. Built into `dist/hooksBash.js`.
 */
export * as bashGuard from './hooks/bashGuard.js';
export * as installGate from './pkgvet/mayInstall.js';
