/**
 * client-identity-from-request, safe: the owner comes from the authenticated
 * session (Passport's `req.user`, an Express `res.locals.user`, Koa's
 * `ctx.state.user`, a session object, Auth.js's `auth()`), while the rest of
 * the record still comes from the request.
 */

router.post('/orders', requireAuth, async (req, res) => {
  const order = await prisma.order.create({ data: { userId: req.user.id, items: req.body.items } });
  res.json(order);
});

router.get('/orders', requireAuth, async (req, res) => {
  res.json(await prisma.order.findMany({ where: { userId: res.locals.user.id, status: req.query.status } }));
});

router.get('/notes', async (ctx) => {
  ctx.body = await Note.find({ owner: ctx.state.user.id, archived: ctx.query.archived === 'true' });
});

export async function POST(req) {
  const session = await auth();
  const { title } = await req.json();
  await prisma.post.create({ data: { title, authorId: session.user.id } });
  return Response.json({ ok: true });
}

export async function GET(req) {
  const session = await auth();
  const { searchParams } = new URL(req.url);
  const page = Number(searchParams.get('page') ?? '1');
  return Response.json(await prisma.invoice.findMany({ where: { tenantId: session.user.tenantId }, skip: (page - 1) * 20 }));
}

router.delete('/notes/:id', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  await prisma.note.deleteMany({ where: { id: req.params.id, userId } });
  res.sendStatus(204);
});
