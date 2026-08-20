import Router from '@koa/router';
import { Hono } from 'hono';

const koaRouter = new Router();
// L20 koa-router
koaRouter.get('/koa/items', async (ctx) => { ctx.body = []; });

const app = new Hono();
// L21 hono fluent chaining across lines
app
  .get('/hono/a', (c) => c.text('a'))
  .post('/hono/b', (c) => c.text('b'));

// L22 hono route with a prefix mount
app.route('/hono/sub', new Hono());
