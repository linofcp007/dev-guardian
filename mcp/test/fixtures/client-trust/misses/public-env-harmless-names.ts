/**
 * Names that only PASS THROUGH a secret word: a length, a reset URL, the
 * localStorage key a token is kept under, a feature flag. Not secrets, and
 * public by design. Nothing fires (fix round 1 of the review, item 2).
 */

export const settings = {
  minLength: Number(process.env.NEXT_PUBLIC_PASSWORD_MIN_LENGTH ?? 8),
  resetUrl: process.env.NEXT_PUBLIC_PASSWORD_RESET_URL,
  tokenKey: import.meta.env.VITE_AUTH_TOKEN_KEY,
  santa: process.env.PUBLIC_SECRET_SANTA_MODE === 'true',
  keyName: process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY_NAME,
};
