/**
 * client-public-env-secret in a Next.js component -- every `// BUG` line fires
 * the rule exactly once. NEXT_PUBLIC_ variables are inlined into the browser
 * bundle at build time, so a secret named here ships to every visitor.
 */

export function Checkout() {
  const stripe = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY; // BUG: client-public-env-secret -- dot access
  const ai = process.env['NEXT_PUBLIC_OPENAI_API_KEY']; // BUG: client-public-env-secret -- string key
  const hook = process.env.NEXT_PUBLIC_STRIPE_WEBHOOK_SECRET; // BUG: client-public-env-secret -- webhook signing secret
  return { stripe, ai, hook };
}

const { NEXT_PUBLIC_DATABASE_URL } = process.env; // BUG: client-public-env-secret -- destructured
export const db = NEXT_PUBLIC_DATABASE_URL;

export const admin = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY; // BUG: client-public-env-secret -- service role
export const wallet = process.env.NEXT_PUBLIC_WALLET_PASSPHRASE; // BUG: client-public-env-secret -- a passphrase, a secret a person chose
