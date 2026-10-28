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

declare const kv: { get(key: string): Promise<string> };

// The text parsed is not the request's (a cached copy).
export async function PATCH(req: Request) {
  const raw = await kv.get(new URL(req.url).pathname);
  const event = JSON.parse(raw);
  if (event.type === 'invoice.paid') await grant(event);
  return new Response('ok');
}

// A field that is not an event type, compared with a name that looks like one (a queue).
export async function PUT(req: Request) {
  const job = await req.json();
  if (job.queue === 'invoice.reminders') await grant(job);
  return new Response('ok');
}

// An exported arrow that is no route (a helper a route calls): its name says so.
export const handleInvoice = async (req: Request) => {
  const event = await req.json();
  if (event.type === 'invoice.paid') await grant(event);
};
