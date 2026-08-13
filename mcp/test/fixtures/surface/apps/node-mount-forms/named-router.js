import express from 'express';

export const namedRouter = express.Router();

namedRouter.get('/status', (req, res) => res.json({ ok: true }));
