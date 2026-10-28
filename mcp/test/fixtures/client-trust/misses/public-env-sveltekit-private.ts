/**
 * SvelteKit's PRIVATE modules never reach the browser.
 */

import { STRIPE_SECRET_KEY } from '$env/static/private';
import { env } from '$env/dynamic/private';
import { PUBLIC_SUPABASE_ANON_KEY } from '$env/static/public';

export const keys = [STRIPE_SECRET_KEY, env.OPENAI_API_KEY, PUBLIC_SUPABASE_ANON_KEY];
