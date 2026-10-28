/**
 * client-webhook-unverified: a Next.js route handler that grants on a Stripe
 * event read straight from the request body. Anyone can POST one.
 */

declare function grantPlan(session: unknown): Promise<void>;
declare function revokePlan(sub: unknown): Promise<void>;

export async function POST(req: Request) { // BUG: client-webhook-unverified -- switch on event.type
  const event = await req.json();
  switch (event.type) {
    case 'ping':
      break;
    case 'checkout.session.completed':
      await grantPlan(event.data.object);
      break;
    case 'customer.subscription.deleted':
      await revokePlan(event.data.object);
      break;
  }
  return new Response('ok');
}
