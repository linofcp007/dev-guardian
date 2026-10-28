/**
 * Public by design: every value here is meant for the browser (a Supabase
 * anon or publishable key, Stripe's pk_, Firebase's web config, a Sentry
 * DSN, a reCAPTCHA site key, a Maps key restricted by referrer). And a
 * secret WITHOUT a browser prefix stays on the server. Nothing fires.
 */

export const browser = {
  supabaseUrl: process.env.NEXT_PUBLIC_SUPABASE_URL,
  anon: process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
  publishable: import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY,
  stripe: process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY,
  firebase: process.env.NEXT_PUBLIC_FIREBASE_API_KEY,
  firebaseAuth: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN,
  sentry: process.env.NEXT_PUBLIC_SENTRY_DSN,
  recaptcha: process.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY,
  maps: process.env.EXPO_PUBLIC_GOOGLE_MAPS_API_KEY,
  posthog: process.env.NEXT_PUBLIC_POSTHOG_KEY,
  clerk: process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY,
};

// Server-only: no browser prefix, the bundler never inlines these.
export const server = {
  stripe: process.env.STRIPE_SECRET_KEY,
  serviceRole: process.env.SUPABASE_SERVICE_ROLE_KEY,
  openai: process.env.OPENAI_API_KEY,
  db: process.env.DATABASE_URL,
};

// A name assembled at run time is not read (a documented gap).
export function lookup(name: string) {
  return process.env[`NEXT_PUBLIC_${name}`];
}
