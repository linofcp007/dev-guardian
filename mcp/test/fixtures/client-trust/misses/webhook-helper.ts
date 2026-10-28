/**
 * Verification delegated to the project's own helper (a name that says so),
 * and a Paddle SDK `unmarshal`, which verifies the signature. Nothing fires.
 */

declare function verifyPaddleWebhook(req: Request): Promise<{ eventType: string; data: unknown }>;
declare const paddle: { webhooks: { unmarshal(body: string, secret: string, sig: string): Promise<{ eventType: string; data: unknown }> } };
declare function grant(x: unknown): Promise<void>;

export async function POST(req: Request) {
  const event = await verifyPaddleWebhook(req);
  if (event.eventType === 'transaction.completed') await grant(event.data);
  return new Response('ok');
}

export async function sdk(req: Request) {
  const event = await paddle.webhooks.unmarshal(await req.text(), 'secret', req.headers.get('paddle-signature') ?? '');
  switch (event.eventType) {
    case 'subscription.activated':
      await grant(event.data);
  }
}
