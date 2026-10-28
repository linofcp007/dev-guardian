/**
 * client-public-env-secret in a Vite SPA -- VITE_ variables are written into
 * the bundle by `import.meta.env`.
 */

export const serviceRole = import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY; // BUG: client-public-env-secret -- import.meta.env
export const anthropic = import.meta.env['VITE_ANTHROPIC_API_KEY']; // BUG: client-public-env-secret -- import.meta.env string key
export const groq = import.meta.env.VITE_GROQ_KEY; // BUG: client-public-env-secret -- a paid API's _KEY
