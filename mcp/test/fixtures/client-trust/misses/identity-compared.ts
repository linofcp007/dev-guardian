/**
 * client-identity-from-request, safe: the claimed owner id is compared with
 * the session's, and the handler leaves when they differ, before the call.
 * Either order, `!==` or `!=`, a `return` or a `throw`, alone or ending a
 * block; the claimed value a variable or the request member itself.
 */

router.get('/orders', requireAuth, async (req, res) => {
  const { userId } = req.query;
  if (userId !== req.user.id) return res.sendStatus(403);
  res.json(await prisma.order.findMany({ where: { userId } }));
});

router.get('/orders/:userId', requireAuth, async (req, res) => {
  if (req.params.userId !== req.user.id) return res.sendStatus(403);
  res.json(await prisma.order.findMany({ where: { userId: req.params.userId } }));
});

router.post('/notes', requireAuth, async (req, res) => {
  const { ownerId } = req.body;
  if (session.user.id != ownerId) throw new Error('forbidden');
  await prisma.note.create({ data: { ownerId, text: req.body.text } });
  res.sendStatus(201);
});

router.put('/accounts/:accountId', requireAuth, async (req, res) => {
  const accountId = req.params.accountId;
  if (!req.user || req.user.accountId !== accountId) {
    res.status(403).json({ error: 'not your account' });
    return;
  }
  await prisma.account.update({ where: { id: req.params.id }, data: { name: req.body.name, accountId } });
  res.sendStatus(204);
});

export async function DELETE(req: Request) {
  const session = await auth();
  const { tenantId } = await req.json();
  if (tenantId != session?.user?.tenantId) {
    console.warn('tenant mismatch');
    throw new Response(null, { status: 403 });
  }
  await prisma.upload.deleteMany({ where: { tenantId } });
  return new Response(null, { status: 204 });
}
