/**
 * A part of the hooks bundle (`src/hooksEntry.ts` says why it is split): what
 * SessionStart alone runs — hardened git for the briefing, whether the
 * project's database is registered, whether the engine bundle is whole, and
 * the session mark it leaves for `health_status` (the one thing a hook
 * writes). Built into `dist/hooksSession.js`.
 */
export * as gitSafety from './platform/gitSafety.js';
export * as dbRegistry from './storage/dbRegistry.js';
export * as distCheck from './hooks/distCheck.js';
export * as heartbeat from './hooks/heartbeat.js';
