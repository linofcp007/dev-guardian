const express = require('express');
const helmet = require('helmet');
const { Router } = require('express');
const usersRouter = require('./users');
const authMw = require('./auth');

const app = express();

// L01 plain route (control)
app.get('/health', (req, res) => res.send('ok'));

// L02 template-literal path
const V = 'v1';
app.get(`/api/${V}/ping`, (req, res) => res.send('pong'));

// L03 chained router.route() — extremely common Express idiom
const router = Router();
router.route('/widgets').get(listWidgets).post(createWidgets);

// L04 chained app.get().post() (Hono / Express-5 style fluent)
app.get('/chain-a', h).post('/chain-b', h);

// L05 mount with middleware between prefix and router — very common
app.use('/api/users', authMw, usersRouter);

// L06 plain 2-arg mount (control)
app.use('/admin', usersRouter);

// L07 mount with no prefix (should NOT be a mount)
app.use(helmet());

// L08 app.all
app.all('/any', h);

function h(req, res) { res.end(); }
function listWidgets() {}
function createWidgets() {}
