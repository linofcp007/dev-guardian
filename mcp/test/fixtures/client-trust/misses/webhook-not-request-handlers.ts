/**
 * Payment event types handled OUTSIDE a request handler: a dispatcher called
 * after constructEvent, a Redux reducer, a socket handler, a class method, a
 * plain function — and generic event names (`order_*`, `subscription.*`,
 * `transaction.*`) inside a real request handler. None is a webhook that
 * trusts the request: nothing fires (fix round 1 of the review, item 1).
 */

declare const stripe: { webhooks: { constructEvent(b: string, s: string, k: string): { type: string; data: { object: unknown } } } };
declare const socket: { on(ev: string, cb: (msg: { type: string }) => void): void };
declare function grant(x: unknown): Promise<void>;
declare function toast(x: string): void;

// The usual dispatcher: verified by the route that calls it.
export async function handleStripeEvent(event: { type: string; data: { object: unknown } }) {
  switch (event.type) {
    case 'checkout.session.completed':
      await grant(event.data.object);
      break;
  }
}

export async function POST(req: Request) {
  const event = stripe.webhooks.constructEvent(await req.text(), req.headers.get('stripe-signature') ?? '', 'whsec');
  await handleStripeEvent(event);
  return new Response('ok');
}

// A Redux reducer and a UI socket handler share the names.
export function billing(state = { paid: false }, action: { type: string }) {
  switch (action.type) {
    case 'invoice.paid':
      return { ...state, paid: true };
    default:
      return state;
  }
}

socket.on('message', (msg) => {
  if (msg.type === 'invoice.paid') toast('paid');
});

export class PaddleHooks {
  async handle(req: Request) {
    const { type, data } = await req.json();
    switch (type) {
      case 'transaction.completed':
        await grant(data);
        break;
    }
  }
}

export async function paypal(body: { event_type: string; resource: unknown }) {
  if (body.event_type === 'PAYMENT.CAPTURE.COMPLETED') await grant(body.resource);
}

// Generic names in a request handler: a queue, an app's own events.
export async function PUT(req: Request) {
  const event = await req.json();
  if (event.type === 'order_created') await grant(event);
  if (event.type === 'subscription.created') await grant(event);
  switch (event.type) {
    case 'transaction.completed':
      await grant(event);
  }
  return new Response('ok');
}
