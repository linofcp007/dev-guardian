/**
 * WRITTEN BY THE AUDITOR (probes/p06_race_condition.ts). Every call below
 * has a method name in this rule's verb list (`save|update|delete|create|
 * insert|commit|send`) and sits, un-awaited, inside an async container — so
 * every one of them fired. None returns a promise: they are all synchronous
 * methods that merely share a name.
 *
 * `res.send(...)` is the headline case: the most common line in an Express
 * app, flagged on essentially every route handler.
 *
 * These are silent because of the RECEIVER constraint, and nothing else —
 * delete the `$O` metavariable-regex and all five fire again. That is the
 * mutation this file exists to catch.
 */

declare const app: { get(p: string, h: unknown): void; post(p: string, h: unknown): void };

// Express: `send` is synchronous and returns the response object.
app.get('/users', async (req: unknown, res: { send(b: unknown): void }) => {
  res.send([]);
});

// Same, through a chain — the receiver is a call expression, not a name.
app.post('/a', async (req: unknown, res: { status(c: number): { send(b: unknown): void } }) => {
  res.status(200).send({ ok: true });
});

// crypto hash: `update` is synchronous.
export const hashChunk = async (h: { update(d: string): void }): Promise<void> => {
  h.update('data');
};

// Map#delete: synchronous, returns a boolean.
export const evict = async (cache: Map<string, number>): Promise<void> => {
  cache.delete('k');
};

// A DOM-ish factory whose verb is exact (`create`, not `createElement`).
export const build = async (ui: { create(tag: string): unknown }): Promise<void> => {
  ui.create('div');
};
