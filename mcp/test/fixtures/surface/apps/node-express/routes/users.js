import express from 'express';

const router = express.Router();

router.get('/list', (req, res) => res.json([]));
router.post('/create', (req, res) => res.status(201).json(req.body));
router.delete('/:id', (req, res) => res.status(204).end());

export default router;
