/**
 * The pairs a lockfile pins, asked of OSV at their exact version.
 *
 * Only a malicious-package advisory (`MAL-`) counts: a lockfile pin is never
 * a reason to warn of a known vulnerability, a publish age or an install
 * script. No registry document is fetched. Every batch answers for itself —
 * an advisory received stands even when another batch fails — and a pin
 * without a complete answer is `malicious: null` with a reason, never `[]`.
 *
 * It shares the network budget and the deadline of `vetPackages` (same
 * `VetOptions`, same `GUARDIAN_OFFLINE`), so the hook's one deadline holds.
 * Imports nothing from `node_modules`: the hooks' bundle has no dependencies.
 */

import { queryOsv } from '../runners/osv.js';
import type { Pin } from './lockfile.js';
import { TOOL_BUDGET_MS, type VetOptions } from './vet.js';

/** Pairs asked per call of the hook, the lockfiles of every command of the line together. */
export const MAX_PINS = 8000;
/** Pairs per OSV request. */
const BATCH = 500;
/** Requests in flight at once: MAX_PINS / BATCH, so every batch of a call is open together. */
const IN_FLIGHT = 16;

/** `malicious === null`: no complete answer for the pin, and `unknown` says why. */
export interface PinVerdict {
  pin: Pin;
  malicious: string[] | null;
  unknown?: string;
}

const keyOf = (p: Pin): string => `${p.name}@${p.version}`;

/**
 * The first {@link MAX_PINS} of `pins`: those of the `direct` dependencies
 * first, then the names `popular` rejects (the likelier carriers of a worm),
 * then the rest; file order within each. A pair seen twice is kept once.
 */
export function choosePins(
  pins: readonly Pin[],
  opts: { direct: ReadonlySet<string>; popular: (name: string) => boolean },
): { chosen: Pin[]; left: number } {
  const seen = new Set<string>();
  const first: Pin[] = [];
  const second: Pin[] = [];
  const third: Pin[] = [];
  for (const pin of pins) {
    const key = keyOf(pin);
    if (seen.has(key)) continue;
    seen.add(key);
    if (opts.direct.has(pin.name)) first.push(pin);
    else if (!opts.popular(pin.name)) second.push(pin);
    else third.push(pin);
  }
  const all = [...first, ...second, ...third];
  return { chosen: all.slice(0, MAX_PINS), left: Math.max(0, all.length - MAX_PINS) };
}

/** Every pin without an answer, with the one reason. */
function allUnknown(pins: readonly Pin[], unknown: string): PinVerdict[] {
  return pins.map((pin) => ({ pin, malicious: null, unknown }));
}

/**
 * One OSV querybatch request per 500 pins, all in flight at once (16 at most).
 * Never throws for a network failure: those become `malicious: null`.
 */
export async function vetPins(pins: readonly Pin[], opts: VetOptions = {}): Promise<PinVerdict[]> {
  if (pins.length === 0) return [];
  const offline = opts.offline ?? process.env['GUARDIAN_OFFLINE'] === '1';
  if (offline) return allUnknown(pins, 'network disabled (GUARDIAN_OFFLINE=1)');
  const fetchImpl = opts.fetchImpl ?? (typeof fetch === 'function' ? fetch : undefined);
  if (fetchImpl === undefined) return allUnknown(pins, 'no fetch implementation available');
  const left = opts.deadlineAt === undefined ? Number.POSITIVE_INFINITY : opts.deadlineAt - Date.now();
  if (left <= 0) return allUnknown(pins, 'vetting time budget exhausted');
  const budgetMs = Math.max(1, Math.min(opts.budgetMs ?? TOOL_BUDGET_MS, left));
  const deadline = Date.now() + budgetMs;
  // A plain, ref'd timer, as in vetPackages: an unref'd one lets a hook whose
  // only pending work is a request that never answers exit before it fires.
  const budget = new AbortController();
  const timer = setTimeout(() => budget.abort(new Error('network budget exhausted')), budgetMs);
  const signal = opts.signal === undefined ? budget.signal : AbortSignal.any([opts.signal, budget.signal]);
  try {
    const osv = await queryOsv(
      pins.map((p) => ({ ecosystem: 'npm', name: p.name, version: p.version })),
      { fetchImpl, signal, timeoutMs: Math.max(1, deadline - Date.now()), chunk: BATCH, inFlight: IN_FLIGHT, maxQueries: MAX_PINS },
    );
    const mal = new Map<string, string[]>();
    for (const g of osv.vulnerable_packages) {
      const ids = g.vuln_ids.filter((id) => id.startsWith('MAL-'));
      if (ids.length > 0 && g.version !== undefined) mal.set(`${g.name}@${g.version}`, ids);
    }
    const unanswered = new Set(osv.unanswered.map((q) => `${q.name}@${q.version ?? ''}`));
    const why = signal.aborted ? 'network budget exhausted before OSV answered' : (osv.error ?? 'OSV gave no complete answer');
    const asked = new Set(pins.slice(0, MAX_PINS).map(keyOf));
    return pins.map((pin): PinVerdict => {
      const key = keyOf(pin);
      // An advisory received stands even when the rest of its batch is cut short.
      const ids = mal.get(key);
      if (ids !== undefined) return { pin, malicious: ids };
      if (!asked.has(key)) return { pin, malicious: null, unknown: `not asked: more than ${MAX_PINS} pins in one call` };
      if (unanswered.has(key)) return { pin, malicious: null, unknown: why };
      return { pin, malicious: [] };
    });
  } finally {
    clearTimeout(timer);
  }
}
