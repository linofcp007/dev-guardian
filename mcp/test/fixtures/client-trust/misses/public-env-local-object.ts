/**
 * An `env` that is not SvelteKit's `$env/dynamic/public`: a server-side
 * secrets object whose keys happen to start with PUBLIC_. It never reaches a
 * bundle. Nothing fires.
 */

declare function loadSecrets(): { PUBLIC_STRIPE_SECRET_KEY: string };

export function stripeKey(): string {
  const env = loadSecrets();
  return env.PUBLIC_STRIPE_SECRET_KEY;
}
