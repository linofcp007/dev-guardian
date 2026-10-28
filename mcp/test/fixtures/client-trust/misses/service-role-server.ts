/**
 * The service-role key where it belongs: a server-only module (no 'use
 * client' directive, no createBrowserClient). And a browser client with the
 * anon key. Nothing fires.
 */

import 'server-only';
import { createClient } from '@supabase/supabase-js';
import { createBrowserClient } from '@supabase/ssr';

export const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL ?? '', process.env.SUPABASE_SERVICE_ROLE_KEY ?? '');

export const browser = createBrowserClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL ?? '',
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? '',
);
