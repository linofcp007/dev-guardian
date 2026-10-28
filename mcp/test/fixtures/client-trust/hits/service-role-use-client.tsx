'use client';
/**
 * client-supabase-service-role: a service-role Supabase client in a Next.js
 * client component. The service-role key bypasses every RLS policy.
 */

import { createClient } from '@supabase/supabase-js';

const url = process.env.NEXT_PUBLIC_SUPABASE_URL ?? '';

export function AdminPanel() {
  const supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY ?? ''); // BUG: client-supabase-service-role -- env key in a 'use client' file
  return supabase;
}

export function useAdmin(serviceRoleKey: string) {
  return createClient(url, serviceRoleKey); // BUG: client-supabase-service-role -- a key named service role
}
