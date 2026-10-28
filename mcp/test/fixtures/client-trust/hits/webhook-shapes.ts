/**
 * client-webhook-unverified in every handler shape the rule reads: an
 * Express-style route, a function declaration and an arrow function, each
 * deciding by `switch` on the event's field, `switch` on a destructured
 * `type`, or `if` on `type`. None verifies a signature.
 */

declare const app: { post(path: string, handler: (req: { body: any }, res: { end(): void }) => unknown): void };
declare function grant(x: unknown): Promise<void>;

app.post('/hooks/a', (req, res) => { // BUG: client-webhook-unverified -- route, switch on event.type
  const event = req.body;
  switch (event.type) {
    case 'invoice.paid':
      void grant(event);
  }
  res.end();
});

app.post('/hooks/b', (req, res) => { // BUG: client-webhook-unverified -- route, switch on a destructured type
  const { type, data } = req.body;
  switch (type) {
    case 'payment_intent.succeeded':
      void grant(data);
  }
  res.end();
});

app.post('/hooks/c', (req, res) => { // BUG: client-webhook-unverified -- route, if on a destructured type
  const { type, data } = req.body;
  if (type === 'subscription_created') void grant(data);
  res.end();
});

export async function fn(body: { type: string; data: unknown }) { // BUG: client-webhook-unverified -- function, if on type
  const { type, data } = body;
  if (type === 'transaction.completed') await grant(data);
}

export const arrowSwitchField = async (event: { type: string; data: unknown }) => { // BUG: client-webhook-unverified -- arrow, switch on event.type
  switch (event.type) {
    case 'customer.subscription.created':
      await grant(event.data);
  }
};

export const arrowSwitchType = async (event: { type: string; data: unknown }) => { // BUG: client-webhook-unverified -- arrow, switch on type
  const { type, data } = event;
  switch (type) {
    case 'charge.refunded':
      await grant(data);
  }
};

export const arrowIfType = async (payload: { eventType: string; data: unknown }) => { // BUG: client-webhook-unverified -- arrow, if on type
  const { eventType: type, data } = payload;
  if (type === 'BILLING.SUBSCRIPTION.ACTIVATED') await grant(data);
};
