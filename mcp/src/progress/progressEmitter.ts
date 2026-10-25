/**
 * MCP `notifications/progress` emitter.
 *
 * Tools instantiate one per long-running invocation. The emitter:
 *  - is a no-op when the host did not include a progressToken
 *  - posts on every `emit()` call (boundary events)
 *  - re-posts the last payload every 10 s as a heartbeat, with the elapsed
 *    time and the latest `note()` in its message, so the host UI never looks
 *    frozen and a host that resets its request timeout on progress keeps a
 *    long scan alive
 *
 * ---- Progress only ever increases, per token ----
 *
 * The MCP spec requires `progress` to increase with every notification for a
 * token. One token can be shared by several emitters: `audit_executive` runs
 * four sub-scans in parallel under its caller's token, and `create_fix_pr`
 * runs its re-scans one after another under its own — each sub-scan counting
 * its steps from 1 again. Every notification therefore goes through
 * {@link sendMonotonic}, which remembers the last value sent per (notifier,
 * token) and nudges a value that would not increase just above it.
 *
 * The emitter is decoupled from the SDK via the `ProgressNotifier`
 * interface so tests can verify exactly what would be sent without
 * spinning up an MCP transport.
 */

import { untrustedText } from '../platform/untrustedText.js';

export interface ProgressPayload {
  progressToken: string | number;
  /**
   * The step reached, in the same unit as `total` when that is known (at
   * most `total`), else a monotonically increasing counter. It used to be a
   * percentage beside a `total` in steps — `{ progress: 60, total: 5 }` —
   * which a host divides into 1200 % (review of 3.6, finding 11).
   */
  progress: number;
  /** How many steps there are; never below `progress` when sent. */
  total?: number;
  message?: string;
}

export interface ProgressNotifier {
  send: (payload: ProgressPayload) => void;
}

export interface ProgressEmitter {
  emit: (input: { step: number; total?: number; message?: string }) => void;
  /**
   * Replace the message the next heartbeat carries, without sending anything
   * now — for high-frequency sources such as a scanner's stderr, which would
   * otherwise flood the host with one notification per line.
   */
  note: (message: string) => void;
  dispose: () => void;
}

export interface ProgressEmitterOptions {
  token: string | number | undefined;
  notifier: ProgressNotifier;
  /** Heartbeat interval in ms. Default 10 000. */
  heartbeatMs?: number;
  /** Injectable timer factory for tests. */
  setIntervalImpl?: typeof setInterval;
  clearIntervalImpl?: typeof clearInterval;
}

const NOOP: ProgressEmitter = {
  emit: () => {},
  note: () => {},
  dispose: () => {},
};

/** How far a non-increasing value is nudged past the last one sent. */
const MIN_INCREMENT = 0.001;
/** Tokens remembered per notifier before the oldest is forgotten. */
const MAX_TRACKED_TOKENS = 1000;

const lastSent = new WeakMap<ProgressNotifier, Map<string | number, number>>();

/**
 * Sends `payload` with a `progress` strictly greater than the last one sent
 * for the same token through the same notifier. Exported for tests.
 */
export function sendMonotonic(notifier: ProgressNotifier, payload: ProgressPayload): void {
  let perToken = lastSent.get(notifier);
  if (perToken === undefined) {
    perToken = new Map();
    lastSent.set(notifier, perToken);
  }
  const previous = perToken.get(payload.progressToken);
  let progress = payload.progress;
  if (previous !== undefined && !(progress > previous)) {
    progress = Math.round((previous + MIN_INCREMENT) * 1000) / 1000;
  }
  perToken.delete(payload.progressToken);
  perToken.set(payload.progressToken, progress);
  if (perToken.size > MAX_TRACKED_TOKENS) {
    const oldest = perToken.keys().next();
    if (oldest.done !== true) perToken.delete(oldest.value);
  }
  // A message can be a scanner's stderr line (`note()`) or name a file of
  // the scanned repository: the host shows it as it is, so its control, bidi
  // and zero-width characters — and line breaks: a progress message is one
  // line — are written as visible `\u{XXXX}` (`platform/untrustedText.ts`),
  // as in every tool result.
  // A token several emitters share can be nudged past one emitter's own
  // total (a second sub-scan counting from 1 again): the total is then left
  // out — the spec makes it optional — rather than sent below the progress.
  const { total, ...rest } = payload;
  notifier.send({
    ...rest,
    progress,
    ...(total !== undefined && progress <= total ? { total } : {}),
    ...(payload.message !== undefined ? { message: untrustedText(payload.message, { multiline: false }) } : {}),
  });
}

export function makeProgressEmitter(options: ProgressEmitterOptions): ProgressEmitter {
  if (options.token === undefined || options.token === null) return NOOP;

  const setI = options.setIntervalImpl ?? setInterval;
  const clearI = options.clearIntervalImpl ?? clearInterval;
  const heartbeat = options.heartbeatMs ?? 10_000;
  const token = options.token;
  const startedAt = Date.now();

  let lastPayload: ProgressPayload | null = null;
  let noted: string | null = null;
  let heartbeatCounter = 0;

  const interval = setI(() => {
    if (!lastPayload) return;
    heartbeatCounter += 1;
    const elapsedS = Math.round((Date.now() - startedAt) / 1000);
    const base = noted ?? lastPayload.message;
    const payload: ProgressPayload = {
      ...lastPayload,
      // Heartbeat: re-send the last step but with a bumped progress value so
      // the host knows the server is alive even if no boundary happened.
      progress:
        typeof lastPayload.total === 'number'
          ? lastPayload.progress
          : lastPayload.progress + heartbeatCounter / 1000,
    };
    payload.message = base !== undefined ? `${base} (${elapsedS}s elapsed)` : `${elapsedS}s elapsed`;
    sendMonotonic(options.notifier, payload);
  }, heartbeat);
  // Don't keep the event loop alive just for this timer.
  if (typeof (interval as { unref?: () => void }).unref === 'function') {
    (interval as { unref: () => void }).unref();
  }

  return {
    emit: ({ step, total, message }) => {
      heartbeatCounter = 0; // reset; we just got a real event
      noted = null;
      const payload: ProgressPayload = {
        progressToken: token,
        progress: total ? Math.min(total, step) : step,
      };
      if (total !== undefined) payload.total = total;
      if (message !== undefined) payload.message = message;
      lastPayload = payload;
      sendMonotonic(options.notifier, payload);
    },
    note: (message) => {
      noted = message;
    },
    dispose: () => {
      clearI(interval);
    },
  };
}
