/**
 * Handlers that verify nothing, with a call or a comment that only LOOKS like
 * a verification: the app's own `events` table or KV namespace read by the
 * event's id (`db.events.get`, `env.EVENTS.get`), a calendar API's
 * `events.get` — and a comment that says "verify" or names the signature.
 * Only Stripe's re-fetch, `stripe.events.retrieve(id)` (case-sensitive), and
 * code, never a comment, silence the rule (fix round 3 of the review, item 1
 * and the comments; round 4: a block comment opened at a line's start, and
 * a quote inside a line comment).
 */

declare const db: { events: { get(id: string): Promise<unknown> } };
declare const env: { EVENTS: { get(id: string): Promise<unknown>; retrieve(id: string): Promise<unknown> } };
declare const calendar: { events: { get(q: { eventId: string }): Promise<unknown> } };
declare const app: { post(path: string, handler: (...args: any[]) => unknown): void };
declare function grant(x: unknown): Promise<void>;

export async function POST(req: Request) { // BUG: client-webhook-unverified -- db.events.get is the app's own table, no re-fetch
  const event = await req.json();
  if (await db.events.get(event.id)) return new Response('already seen');
  if (event.type === 'checkout.session.completed') await grant(event.data.object);
  return new Response('ok');
}

export async function PUT(req: Request) { // BUG: client-webhook-unverified -- env.EVENTS.get, a KV namespace (the old (?i) read it as events.get)
  const event = await req.json();
  await env.EVENTS.get(event.id);
  switch (event.type) {
    case 'invoice.paid':
      await grant(event.data.object);
  }
  return new Response('ok');
}

export const PATCH = async (req: Request) => { // BUG: client-webhook-unverified -- calendar.events.get, not a payment gateway
  const event = await req.json();
  await calendar.events.get({ eventId: event.data.object.id });
  if (event.type === 'payment_intent.succeeded') await grant(event.data.object);
  return new Response('ok');
};

app.post('/webhooks/stripe', async (req: { body: any }, res: { end(): void }) => { // BUG: client-webhook-unverified -- verify and signature only in comments
  // TODO: verify (later), with the Stripe signature
  /* the signature check comes in the next sprint */
  /* verifyStripe(req) will be mounted
     on the router */
  const note = 'unchecked'; // don't verify (later): the quote in a comment opens no string
  const event = { ...req.body, note };
  if (event.type === 'customer.subscription.updated') await grant(event.data.object);
  res.end();
});

app.post('/webhooks/stripe-kv', async (req: { body: any }, res: { end(): void }) => { // BUG: client-webhook-unverified -- EVENTS.retrieve, the app's own store: the re-fetch is read case-sensitively
  const event = req.body;
  if (await env.EVENTS.retrieve(event.id)) return res.end();
  if (event.type === 'invoice.payment_succeeded') await grant(event.data.object);
  res.end();
});
