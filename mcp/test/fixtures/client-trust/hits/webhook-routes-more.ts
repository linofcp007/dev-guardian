/**
 * More route shapes that receive a body: Hono's `app.on('POST', path, h)`
 * (one method or a list), a router whose methods are upper-case
 * (`router.POST(...)`), and a handler mounted with `app.use` on a path that
 * names a webhook. None verifies a signature (fix round 3 of the review,
 * item 7).
 */

declare const app: {
  on(method: string | string[], path: string, handler: (...args: any[]) => unknown): void;
  use(path: string, handler: (...args: any[]) => unknown): void;
};
declare const router: { POST(path: string, handler: (...args: any[]) => unknown): void };
declare function grant(x: unknown): Promise<void>;

app.on('POST', '/webhooks/stripe', async (c: any) => { // BUG: client-webhook-unverified -- Hono app.on('POST', ...)
  const event = await c.req.json();
  if (event.type === 'checkout.session.completed') await grant(event.data.object);
  return c.text('ok');
});

app.on(['PUT', 'POST'], '/webhooks/paypal', async (c: any) => { // BUG: client-webhook-unverified -- Hono app.on with a method list
  const event = await c.req.json();
  if (event.event_type === 'PAYMENT.CAPTURE.COMPLETED') await grant(event.resource);
  return c.text('ok');
});

router.POST('/billing/stripe', async (req: { body: any }, res: { end(): void }) => { // BUG: client-webhook-unverified -- an upper-case router method
  switch (req.body.type) {
    case 'invoice.paid':
      await grant(req.body.data.object);
  }
  res.end();
});

app.use('/api/stripe-webhook', async (req: { body: any }, res: { end(): void }) => { // BUG: client-webhook-unverified -- app.use on a path that names a webhook
  const event = req.body;
  if (event.type === 'charge.refunded') await grant(event.data.object);
  res.end();
});
