/**
 * server/lib/supabase.ts
 *
 * Supabase client for serverless functions.
 *
 * Required env vars (set in Vercel dashboard):
 *   SUPABASE_URL          — from Supabase project settings → API
 *   SUPABASE_SERVICE_KEY  — service_role key (bypasses RLS for server-side ops)
 *
 * The service_role key is used server-side only and never exposed to clients.
 * All requests are still scoped to the authenticated user via their JWT.
 */

import { createClient } from "@supabase/supabase-js";

export function getSupabase() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_KEY;
  if (!url || !key) {
    throw new Error("SUPABASE_URL and SUPABASE_SERVICE_KEY must be set.");
  }
  return createClient(url, key, {
    auth: { persistSession: false },
  });
}

/**
 * Create a Supabase client that acts as the authenticated user.
 * Pass the JWT from the Authorization header to scope all queries to that user.
 */
export function getSupabaseForUser(jwt: string) {
  const url = process.env.SUPABASE_URL!;
  const anonKey = process.env.SUPABASE_ANON_KEY!;
  return createClient(url, anonKey, {
    global: { headers: { Authorization: `Bearer ${jwt}` } },
    auth: { persistSession: false },
  });
}

/** Extract Bearer token from Authorization header. */
export function extractToken(
  headers: Record<string, string | string[] | undefined>
): string | null {
  const auth = headers["authorization"] as string | undefined;
  if (!auth?.startsWith("Bearer ")) return null;
  return auth.slice("Bearer ".length);
}
