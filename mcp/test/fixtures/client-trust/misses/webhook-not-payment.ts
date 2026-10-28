/**
 * A handler that branches on event types that are not payments (a GitHub
 * push, an auth provider's user.created): not this rule's business.
 */

declare function sync(x: unknown): Promise<void>;

export async function POST(req: Request) {
  const event = await req.json();
  switch (event.type) {
    case 'user.created':
      await sync(event.data);
      break;
    case 'push':
      break;
  }
  if (event.type === 'session.ended') await sync(event);
  return new Response('ok');
}
