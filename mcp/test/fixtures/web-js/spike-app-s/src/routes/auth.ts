import { Router } from 'express';
import { z } from 'zod';
import { config } from '../config.js';
import { HttpError, asyncHandler } from '../middleware/errors.js';
import { signSession } from '../middleware/auth.js';
import * as users from '../repositories/users.js';
import { completeReset, requestReset } from '../services/passwordReset.js';
import { verifyPassword } from '../services/passwords.js';

export const authRouter = Router();

const loginBody = z.object({
  email: z.string().email(),
  password: z.string().min(1).max(200),
});

authRouter.post(
  '/login',
  asyncHandler((req, res) => {
    const { email, password } = loginBody.parse(req.body);
    const user = users.findByEmail(email);
    if (!user || !user.active || !verifyPassword(password, user.password_hash)) {
      throw new HttpError(401, 'Wrong email or password');
    }
    const token = signSession({ sub: user.id, clinicId: user.clinic_id, role: user.role });
    res.json({ token, user: users.toPublic(user) });
  }),
);

const forgotBody = z.object({ email: z.string().email() });

authRouter.post(
  '/forgot',
  asyncHandler((req, res) => {
    const { email } = forgotBody.parse(req.body);
    requestReset(email);
    res.status(202).json({ ok: true });
  }),
);

const resetBody = z.object({
  email: z.string().email(),
  token: z.string().min(4).max(64),
  password: z.string().min(10).max(200),
});

authRouter.post(
  '/reset',
  asyncHandler((req, res) => {
    const { email, token, password } = resetBody.parse(req.body);
    completeReset(email, token, password);
    res.json({ ok: true });
  }),
);

authRouter.get('/return', (req, res) => {
  const next = String(req.query.next ?? '');
  if (config.returnUrls.includes(next)) {
    res.redirect(next);
    return;
  }
  res.redirect('/');
});
