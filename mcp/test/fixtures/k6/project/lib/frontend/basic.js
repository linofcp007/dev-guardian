// The requests a visitor makes, as quickpizza's lib/frontend/basic.js groups them.
import { check } from 'k6';
import { recommendationBody } from './util.js';

export function getHome(http, base) {
  const res = http.get(`${base}/`);
  check(res, { 'home is 200': (r) => r.status === 200 });
}

export function getRecommendation(http, base, token) {
  const res = http.post(`${base}/api/pizza`, recommendationBody(), {
    headers: { Authorization: `Token ${token}`, 'Content-Type': 'application/json' },
  });
  check(res, { 'pizza is 200': (r) => r.status === 200 });
}
