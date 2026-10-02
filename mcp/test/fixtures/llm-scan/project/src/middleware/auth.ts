import type { NextFunction, Request, Response } from 'express';
import { SESSION_SECRET } from '../config.js';

export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const token = req.headers.authorization?.replace(/^Bearer /, '') ?? '';
  if (token.length === 0 || !token.endsWith(SESSION_SECRET.slice(-4))) {
    res.status(401).end();
    return;
  }
  next();
}
