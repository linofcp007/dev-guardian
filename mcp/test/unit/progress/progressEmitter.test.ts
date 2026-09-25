import { describe, expect, it, vi } from 'vitest';
import {
  makeProgressEmitter,
  type ProgressPayload,
} from '../../../src/progress/progressEmitter.js';

function recordingNotifier() {
  const sent: ProgressPayload[] = [];
  return {
    notifier: { send: (p: ProgressPayload) => sent.push(p) },
    sent,
  };
}

describe('makeProgressEmitter', () => {
  it('is a no-op when no token is provided', () => {
    const { notifier, sent } = recordingNotifier();
    const emitter = makeProgressEmitter({ token: undefined, notifier });
    emitter.emit({ step: 1, message: 'x' });
    emitter.dispose();
    expect(sent).toHaveLength(0);
  });

  it('sends a payload on every emit() call with progressToken set', () => {
    const { notifier, sent } = recordingNotifier();
    const emitter = makeProgressEmitter({ token: 'tok-1', notifier });
    emitter.emit({ step: 1, total: 5, message: 'a' });
    emitter.emit({ step: 3, total: 5, message: 'b' });
    emitter.dispose();

    expect(sent).toHaveLength(2);
    expect(sent[0]?.progressToken).toBe('tok-1');
    expect(sent[0]?.message).toBe('a');
    expect(sent[1]?.progress).toBeCloseTo(60); // 3/5*100
  });

  it('heartbeats with the last payload at the configured interval', () => {
    vi.useFakeTimers();
    try {
      const { notifier, sent } = recordingNotifier();
      const emitter = makeProgressEmitter({
        token: 'tok-x',
        notifier,
        heartbeatMs: 1_000,
      });
      emitter.emit({ step: 1, message: 'going' });
      // Trigger 3 heartbeats.
      vi.advanceTimersByTime(3_000);
      emitter.dispose();

      // 1 real emit + 3 heartbeats
      expect(sent.length).toBeGreaterThanOrEqual(4);
      for (const payload of sent) {
        expect(payload.progressToken).toBe('tok-x');
      }
    } finally {
      vi.useRealTimers();
    }
  });

  it('note() changes what the next heartbeat says, without sending anything itself', () => {
    vi.useFakeTimers();
    try {
      const { notifier, sent } = recordingNotifier();
      const emitter = makeProgressEmitter({ token: 'tok-n', notifier, heartbeatMs: 1_000 });
      emitter.emit({ step: 1, message: 'bug_hunt: scanning' });
      emitter.note('bug_hunt: Scanning 140 files with 312 rules');
      expect(sent).toHaveLength(1);
      vi.advanceTimersByTime(1_000);
      emitter.dispose();
      expect(sent).toHaveLength(2);
      expect(sent[1]?.message).toContain('Scanning 140 files with 312 rules');
      expect(sent[1]?.message).toMatch(/\d+s elapsed/);
    } finally {
      vi.useRealTimers();
    }
  });

  it('never lets progress go backwards for a token shared by several emitters', () => {
    // audit_executive runs four sub-scans under its caller's token, each
    // counting its own steps from 1. The spec requires progress to increase
    // with every notification for a token.
    const { notifier, sent } = recordingNotifier();
    const a = makeProgressEmitter({ token: 'shared', notifier });
    const b = makeProgressEmitter({ token: 'shared', notifier });
    a.emit({ step: 1 });
    a.emit({ step: 2 });
    b.emit({ step: 1 });
    a.emit({ step: 3 });
    b.emit({ step: 2 });
    a.dispose();
    b.dispose();
    for (let i = 1; i < sent.length; i++) {
      const prev = sent[i - 1];
      const cur = sent[i];
      if (prev === undefined || cur === undefined) continue;
      expect(cur.progress).toBeGreaterThan(prev.progress);
    }
    // Another token through the same notifier is tracked on its own.
    const c = makeProgressEmitter({ token: 'other', notifier });
    c.emit({ step: 1 });
    c.dispose();
    expect(sent[sent.length - 1]?.progress).toBe(1);
  });

  it('stops heartbeating after dispose()', () => {
    vi.useFakeTimers();
    try {
      const { notifier, sent } = recordingNotifier();
      const emitter = makeProgressEmitter({
        token: 'tok',
        notifier,
        heartbeatMs: 500,
      });
      emitter.emit({ step: 1 });
      vi.advanceTimersByTime(500);
      const countAtDispose = sent.length;
      emitter.dispose();
      vi.advanceTimersByTime(5_000);
      expect(sent.length).toBe(countAtDispose);
    } finally {
      vi.useRealTimers();
    }
  });
});
