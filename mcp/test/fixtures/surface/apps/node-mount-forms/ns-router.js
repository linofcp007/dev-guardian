import express from 'express';

export const router = express.Router();

router.get('/ns-status', (req, res) => res.json({ ok: true }));
