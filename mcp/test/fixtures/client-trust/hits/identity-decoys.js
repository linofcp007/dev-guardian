/**
 * client-identity-from-request: the checks that do NOT make a claimed owner
 * id the caller's, so the rule still fires. A presence or type check; a
 * comparison with another field of the same request (consistency, not
 * authorization); a comparison whose branch does not leave (a warning, an
 * Express response with no `return`). And the known false positives the
 * pack header states: a role check or an authorization helper the rule does
 * not read, a task assigned to another user, a positive comparison around the
 * call, a guestbook author that is only a display name, a parameter that is
 * not a request.
 */

router.post('/orders', auth, async (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.sendStatus(400);
  await prisma.order.create({ data: { userId, total: req.body.total } }); // BUG: client-identity-from-request -- a presence check
  res.sendStatus(201);
});

router.post('/orders/typed', auth, async (req, res) => {
  const { userId } = req.body;
  if (userId !== undefined && typeof userId !== 'string') return res.sendStatus(400);
  await prisma.order.create({ data: { userId } }); // BUG: client-identity-from-request -- a type check against a literal
  res.sendStatus(201);
});

router.post('/users/:userId/orders', auth, async (req, res) => {
  const { userId } = req.body;
  if (userId !== req.params.userId) return res.sendStatus(400);
  await prisma.order.create({ data: { userId } }); // BUG: client-identity-from-request -- the body against the route: both are the caller's claim
  res.sendStatus(201);
});

router.post('/orders/warned', auth, async (req, res) => {
  const { userId } = req.body;
  if (userId !== req.user.id) console.warn('order placed for another user', userId);
  await prisma.order.create({ data: { userId } }); // BUG: client-identity-from-request -- the branch only logs
  res.sendStatus(201);
});

router.post('/orders/no-return', auth, async (req, res) => {
  const { userId } = req.body;
  if (userId !== req.user.id) res.sendStatus(403);
  await prisma.order.create({ data: { userId } }); // BUG: client-identity-from-request -- Express's missing return: the create still runs
  res.sendStatus(201);
});

// Known false positives (the pack header): the rule does not read these checks.
router.post('/admin/orders', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  await prisma.order.create({ data: { userId: req.body.userId } }); // BUG: client-identity-from-request -- an admin acting for a user
  res.sendStatus(201);
});

router.post('/teams/:teamId/notes', auth, async (req, res) => {
  const { ownerId } = req.body;
  await assertMember(req.user.id, req.params.teamId, ownerId);
  await prisma.note.create({ data: { ownerId, teamId: req.params.teamId } }); // BUG: client-identity-from-request -- an authorization helper
  res.sendStatus(201);
});

router.post('/tasks', auth, async (req, res) => {
  const { assignee } = req.body;
  await prisma.task.create({ data: { title: req.body.title, userId: assignee } }); // BUG: client-identity-from-request -- assigned to someone else
  res.sendStatus(201);
});

router.post('/orders/mine', auth, async (req, res) => {
  const { userId } = req.body;
  if (userId === req.user.id) {
    await prisma.order.create({ data: { userId } }); // BUG: client-identity-from-request -- a positive comparison around the call
  }
  res.sendStatus(201);
});

router.post('/guestbook', async (req, res) => {
  await Entry.create({ author: req.body.author, text: req.body.text }); // BUG: client-identity-from-request -- a display name under a bare owner key
  res.sendStatus(201);
});

// A parameter named like a request is read as one.
function saveFromOptions(opts) {
  return prisma.export.create({ data: { userId: opts.query.userId } }); // BUG: client-identity-from-request -- a parameter that is not a request
}

module.exports = { saveFromOptions };
