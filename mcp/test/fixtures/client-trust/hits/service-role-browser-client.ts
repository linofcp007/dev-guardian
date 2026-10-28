/**
 * client-supabase-service-role: `createBrowserClient` (@supabase/ssr) only
 * ever runs in the browser, whatever the file says.
 */

import { createBrowserClient } from '@supabase/ssr';

export const supabase = createBrowserClient( // BUG: client-supabase-service-role -- the new secret key name
  'https://example.supabase.co',
  import.meta.env.SUPABASE_SECRET_KEY,
);

export function admin() {
  return createBrowserClient('https://example.supabase.co', process.env.SUPABASE_SERVICE_KEY ?? ''); // BUG: client-supabase-service-role -- legacy service key name
}
