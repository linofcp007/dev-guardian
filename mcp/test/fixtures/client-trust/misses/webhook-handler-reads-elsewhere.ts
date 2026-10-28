/**
 * A request handler whose event does NOT come from its request (a queue, a
 * stored record), and a GET handler: not a webhook that trusts the request.
 * Nothing fires.
 */

declare const queue: { json(): Promise<{ type: string }> };
declare function grant(x: unknown): Promise<void>;

export async function POST(req: Request) {
  const event = await queue.json();
  if (event.type === 'invoice.paid') await grant(event);
  return new Response(String(req.url));
}

export async function GET(req: Request) {
  const event = await req.json();
  if (event.type === 'invoice.paid') return new Response('paid');
  return new Response('no');
}
