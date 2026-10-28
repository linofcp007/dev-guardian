/**
 * The route shapes of fix round 3 (item 7), where they are no webhook: a
 * Hono `app.on` for GET (no body), a listener's two-argument `on`, an
 * `app.use` middleware on a path that names no webhook — and the real
 * re-fetch through a client of another name, `getStripe().events.retrieve`,
 * and a verifier on the route's own line inside a function. Nothing fires.
 */

declare const app: {
  on(method: string | string[], path: string, handler: (...args: any[]) => unknown): void;
  use(path: string, handler: (...args: any[]) => unknown): void;
  post(path: string, ...handlers: Array<(...args: any[]) => unknown>): void;
};
declare const emitter: { on(event: string, handler: (...args: any[]) => unknown): void };
declare function getStripe(): { events: { retrieve(id: string): Promise<{ type: string; data: { object: unknown } }> } };
declare function verifyStripe(req: unknown, res: unknown, next: () => void): void;
declare function grant(x: unknown): Promise<void>;

app.on('GET', '/webhooks/stripe', async (c: any) => {
  const event = await c.req.json();
  if (event.type === 'checkout.session.completed') await grant(event.data.object);
  return c.text('ok');
});

emitter.on('POST', async (req: { body: any }) => {
  if (req.body.type === 'invoice.paid') await grant(req.body);
});

app.use('/api', async (req: { body: any }, res: { end(): void }) => {
  if (req.body.type === 'invoice.paid') await grant(req.body);
  res.end();
});

app.on('POST', '/webhooks/refetch', async (c: any) => {
  const { id } = await c.req.json();
  const event = await getStripe().events.retrieve(id);
  if (event.type === 'invoice.paid') await grant(event.data.object);
  return c.text('ok');
});

export function register() {
  app.post('/webhooks/express', verifyStripe, async (req: { body: any }, res: { end(): void }) => {
    if (req.body.type === 'invoice.paid') await grant(req.body.data.object);
    res.end();
  });
}
