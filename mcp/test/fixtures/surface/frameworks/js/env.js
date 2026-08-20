// L50 member access
const a = process.env.DATABASE_URL;
// L51 index access
const b = process.env['REDIS_URL'];
// L52 destructured — common in modern config modules
const { STRIPE_KEY, SENTRY_DSN } = process.env;
// L53 nullish default
const c = process.env.PORT ?? 3000;
// L54 vite/import.meta
const d = import.meta.env.VITE_API_URL;
