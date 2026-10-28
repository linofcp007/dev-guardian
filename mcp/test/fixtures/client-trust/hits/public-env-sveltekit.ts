/**
 * client-public-env-secret in SvelteKit: `$env/static/public` and
 * `$env/dynamic/public` hold the PUBLIC_ variables, which reach the browser.
 */

import { PUBLIC_STRIPE_SECRET_KEY } from '$env/static/public'; // BUG: client-public-env-secret -- static import
import { env } from '$env/dynamic/public';

export const stripe = PUBLIC_STRIPE_SECRET_KEY;
export const claude = env.PUBLIC_ANTHROPIC_API_KEY; // BUG: client-public-env-secret -- dynamic env
