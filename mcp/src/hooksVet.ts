/**
 * A part of the hooks bundle (`src/hooksEntry.ts` says why it is split):
 * install-time package vetting, loaded only for a command that may install.
 * Built into `dist/hooksVet.js`.
 */
export * as installVetting from './pkgvet/hookDecision.js';
