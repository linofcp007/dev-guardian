'use client';
/**
 * A client component with the anon key: what the browser should hold.
 */

import { createClient } from '@supabase/supabase-js';

export function useSupabase(anonKey: string) {
  return createClient(process.env.NEXT_PUBLIC_SUPABASE_URL ?? '', anonKey);
}

export const publishable = createClient('https://example.supabase.co', process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY ?? '');
