"use client";
/**
 * client-supabase-service-role with the directive in double quotes: the same
 * client component, the same leak.
 */

import { createClient } from '@supabase/supabase-js';

export function Admin() {
  return createClient('https://example.supabase.co', import.meta.env.SUPABASE_SERVICE_ROLE_KEY); // BUG: client-supabase-service-role -- "use client"
}
