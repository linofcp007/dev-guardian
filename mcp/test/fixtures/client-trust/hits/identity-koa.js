/**
 * client-identity-from-request in Koa: the context is the handler's
 * parameter, and the request is `ctx.request` (`ctx.request.body` from
 * koa-body, `ctx.request.query`), or `ctx.query` and `ctx.params`
 * (koa-router) directly.
 */

const Router = require('@koa/router');
const { Document, Folder, Membership } = require('./models');

const router = new Router();

router.post('/documents', async (ctx) => {
  const doc = await Document.create({ title: ctx.request.body.title, userId: ctx.request.body.userId }); // BUG: client-identity-from-request -- koa-body
  ctx.body = doc;
});

router.get('/documents', async (ctx) => {
  ctx.body = await Document.findAll({ where: { userId: ctx.request.query.userId } }); // BUG: client-identity-from-request -- ctx.request.query
});

router.put('/documents/:id', async (ctx) => {
  const ownerId = ctx.request.body.ownerId;
  await Document.update({ title: ctx.request.body.title }, { where: { id: ctx.params.id, ownerId } }); // BUG: client-identity-from-request -- a variable from koa-body
  ctx.status = 204;
});

router.post('/folders', async (ctx) => {
  const { accountId, name } = ctx.request.body;
  ctx.body = await Folder.create({ name, accountId }); // BUG: client-identity-from-request -- destructured from koa-body
});

router.delete('/teams/:teamId/members/:accountId', async (ctx, next) => {
  await Membership.destroy({ where: { teamId: ctx.params.teamId, accountId: ctx.params.accountId } }); // BUG: client-identity-from-request -- koa-router params
  await next();
});

module.exports = router;
