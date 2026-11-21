/**
 * A part of the hooks bundle (`src/hooksEntry.ts` says why it is split): the
 * question "does this network folder answer?", asked in a process of its own.
 * Loaded only by a call whose session or project folder is on the network, so
 * that no other event parses it or its `node:child_process`. Built into
 * `dist/hooksProbe.js` (from task 2 of bugfix `hook-unc-cwd-hang`).
 */
export * as folderProbe from './hooks/folderProbe.js';
