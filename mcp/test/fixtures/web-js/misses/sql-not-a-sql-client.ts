/**
 * web-js-sql-template -- nothing here may fire (US-1.AC-1: "de um cliente SQL").
 *
 * `get`, `all` and `run` are also the methods of a Map, a URLSearchParams, a
 * Redis client and an Express router, and every one of them is routinely
 * called with a template literal. None of these is SQL.
 */

import { Router } from 'express';

const API_PREFIX = '/api/v2';
const cache = new Map<string, string>();

export const apiRouter = Router();

export function cachedUser(id: string) {
  return cache.get(`user:${id}`);
}

export function pageParam(params: URLSearchParams, prefix: string) {
  return params.get(`${prefix}_page`);
}

export async function session(redis: { get(key: string): Promise<string | null> }, sid: string) {
  return redis.get(`session:${sid}`);
}

apiRouter.get(`${API_PREFIX}/health`, (_req, res) => {
  res.json({ ok: true });
});

apiRouter.all(`${API_PREFIX}/*`, (_req, res, next) => {
  res.set('cache-control', 'no-store');
  next();
});
