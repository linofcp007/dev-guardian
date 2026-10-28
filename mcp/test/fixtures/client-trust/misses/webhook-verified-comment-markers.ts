/**
 * Verified handlers whose verifier shares its line with what only LOOKS like
 * a comment: a `/*` inside a string (`'*' + '/' + '*'` as a MIME type, a
 * route pattern ending in a slash and a star), a `//` inside a string, a
 * `/*` with no close in the middle of a line (a regex literal), a CLOSED
 * `/* ... *\/` before it, or the `*\/` that closes a block at the start of
 * the line — and a signature header named only inside a string. Only a
 * comment hides a verifier: nothing fires (fix round 4 of the review, item 1).
 */

declare const app: { post(path: string, ...handlers: Array<(...args: any[]) => unknown>): void };
declare const express: { raw(o: { type: string }): (...args: any[]) => void };
declare const stripe: { webhooks: { constructEvent(b: unknown, s: unknown, k: string): { type: string; data: { object: unknown } } } };
declare function verifyStripe(req: unknown, res: unknown, next: () => void): void;
declare function verifyWebhook(req: unknown, path?: string): boolean;
declare function isValid(body: unknown, sig: unknown): boolean;
declare function grant(x: unknown): Promise<void>;
declare const SIG_HEADER: string;
declare const WEBHOOK_SECRET: string;

app.post('/webhook', express.raw({ type: '*/*' }), verifyStripe, (req: { body: any }, res: { end(): void }) => {
  if (req.body.type === 'invoice.paid') void grant(req.body.data.object);
  res.end();
});

app.post('/webhooks/*', verifyStripe, (req: { body: any }, res: { end(): void }) => {
  if (req.body.type === 'checkout.session.completed') void grant(req.body.data.object);
  res.end();
});

app.post('/webhooks/stripe-inline', express.raw({ type: 'application/json' }), (req: { body: any; headers: any }, res: { end(): void }) => {
  /* raw body */ const event = stripe.webhooks.constructEvent(req.body, req.headers[SIG_HEADER], WEBHOOK_SECRET);
  if (event.type === 'payment_intent.succeeded') void grant(event.data.object);
  res.end();
});

app.post('/webhooks/ping-first', async (req: { body: any }, res: { end(): void }) => {
  const ok = await fetch('//hooks.internal/ping').then(() => verifyWebhook(req));
  if (ok && req.body.type === 'invoice.paid') void grant(req.body.data.object);
  res.end();
});

app.post('/webhooks/trailing', (req: { body: any; path: string }, res: { end(): void }) => {
  const path = req.path.replace(/\/*$/, ''); if (!verifyWebhook(req, path)) return res.end();
  if (req.body.type === 'invoice.paid') void grant(req.body.data.object);
  res.end();
});

app.post('/webhooks/closing', express.raw({ type: 'application/json' }), (req: { body: any; headers: any }, res: { end(): void }) => {
  /*
   * The raw body, never parsed.
   */ const event = stripe.webhooks.constructEvent(req.body, req.headers[SIG_HEADER], WEBHOOK_SECRET);
  if (event.type === 'charge.refunded') void grant(event.data.object);
  res.end();
});

app.post('/webhooks/header', (req: { body: any; headers: any }, res: { end(): void }) => {
  const sig = req.headers['stripe-signature'];
  if (!isValid(req.body, sig)) return res.end();
  if (req.body.type === 'invoice.paid') void grant(req.body.data.object);
  res.end();
});
