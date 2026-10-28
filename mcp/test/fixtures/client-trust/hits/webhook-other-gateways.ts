/**
 * client-webhook-unverified for Lemon Squeezy (meta.event_name), Paddle
 * (a destructured `type`), PayPal (event_type) -- arrow functions, a
 * method and a function declaration.
 */

declare function grant(x: unknown): Promise<void>;

export const POST = async (req: Request) => { // BUG: client-webhook-unverified -- Lemon Squeezy, arrow
  const payload = await req.json();
  if (payload.meta.event_name === 'order_created') {
    await grant(payload.data);
  }
  return new Response(null, { status: 200 });
};

export class PaddleHooks {
  async handle(req: Request) { // BUG: client-webhook-unverified -- Paddle, a method
    const { type, data } = await req.json();
    switch (type) {
      case 'transaction.completed':
        await grant(data);
        break;
    }
  }
}

export async function paypal(body: { event_type: string; resource: unknown }) { // BUG: client-webhook-unverified -- PayPal
  if (body.event_type === 'PAYMENT.CAPTURE.COMPLETED') await grant(body.resource);
}
