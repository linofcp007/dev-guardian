/**
 * client-webhook-unverified in every request-handler shape the rule reads —
 * a Next.js route function, a Next.js route const, a pages/api default
 * export, an Express / Hono route callback (arrow or function) — taking the
 * event from the request (`req.body`, `req.json()`, `c.req.json()`,
 * `JSON.parse(... text())`) and branching on its type (`switch` on the
 * field, `switch` on a destructured `type`, a comparison of either). None
 * verifies a signature.
 */

declare const app: { post(path: string, handler: (...args: any[]) => unknown): void };
declare const router: { post(path: string, handler: (...args: any[]) => unknown): void };
declare function grant(x: unknown): Promise<void>;

export const PATCH = async (req: Request) => { // BUG: client-webhook-unverified -- route const, JSON.parse(req.text()), if on a destructured type
  const { type, data } = JSON.parse(await req.text());
  if (type === 'customer.subscription.created') await grant(data);
  return new Response('ok');
};

export default async function handler(req: { body: any }, res: { end(): void }) { // BUG: client-webhook-unverified -- pages/api, req.body, switch on a destructured type
  const { type, data } = req.body;
  switch (type) {
    case 'invoice.payment_succeeded':
      await grant(data);
  }
  res.end();
}

app.post('/hono/stripe', async (c: any) => { // BUG: client-webhook-unverified -- Hono, c.req.json(), switch on event.type
  const event = await c.req.json();
  switch (event.type) {
    case 'payment_intent.succeeded':
      await grant(event);
  }
  return c.text('ok');
});

router.post('/paypal', function (req: { body: any }, res: { end(): void }) { // BUG: client-webhook-unverified -- route function, req.body, event_type comparison
  if (req.body.event_type === 'PAYMENT.CAPTURE.COMPLETED') void grant(req.body.resource);
  res.end();
});

app.post('/hono/lemon', async (c: any) => { // BUG: client-webhook-unverified -- Hono, JSON.parse(c.req.text()), Lemon Squeezy event_name
  const payload = JSON.parse(await c.req.text());
  if (payload.meta.event_name === 'subscription_payment_success') await grant(payload.data);
  return c.text('ok');
});

export async function PUT(req: Request) { // BUG: client-webhook-unverified -- the raw body read, then JSON.parse of it (the real starters' shape with the check removed)
  const body = await req.text();
  const event = JSON.parse(body);
  if (event.type === 'charge.refunded') await grant(event.data);
  return new Response('ok');
}
