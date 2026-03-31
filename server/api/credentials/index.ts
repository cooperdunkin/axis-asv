/**
 * GET  /api/credentials  — list credentials (metadata only, no ciphertext)
 * POST /api/credentials  — store a new encrypted credential
 */

import type { VercelRequest, VercelResponse } from "@vercel/node";
import { getSupabaseForUser, extractToken } from "../../lib/supabase.js";

const FREE_TIER_LIMIT = 3;

export default async function handler(req: VercelRequest, res: VercelResponse) {
  const token = extractToken(req.headers as Record<string, string>);
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  const supabase = getSupabaseForUser(token);

  // Verify the token and get the user
  const { data: { user }, error: authError } = await supabase.auth.getUser();
  if (authError || !user) return res.status(401).json({ error: "Unauthorized" });

  if (req.method === "GET") {
    const { data, error } = await supabase
      .from("credentials")
      .select("id, service, label, created_at, updated_at")
      .order("created_at", { ascending: true });

    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ credentials: data });
  }

  if (req.method === "POST") {
    const { service, ciphertext, salt, iv, auth_tag, label } = req.body as {
      service?: string;
      ciphertext?: string;
      salt?: string;
      iv?: string;
      auth_tag?: string;
      label?: string;
    };

    if (!service || !ciphertext || !salt || !iv || !auth_tag) {
      return res.status(400).json({
        error: "service, ciphertext, salt, iv, and auth_tag are required",
      });
    }

    // Check free tier limit
    const { data: sub } = await supabase
      .from("subscriptions")
      .select("tier")
      .eq("user_id", user.id)
      .single();

    const tier = sub?.tier ?? "free";

    if (tier === "free") {
      const { count } = await supabase
        .from("credentials")
        .select("*", { count: "exact", head: true })
        .eq("user_id", user.id);

      if ((count ?? 0) >= FREE_TIER_LIMIT) {
        return res.status(402).json({
          error: `Free tier limit reached (${FREE_TIER_LIMIT} services). Upgrade to Pro at axisproxy.com`,
          upgradeRequired: true,
          currentCount: count,
          limit: FREE_TIER_LIMIT,
        });
      }
    }

    const { data, error } = await supabase
      .from("credentials")
      .upsert(
        {
          user_id: user.id,
          service,
          label: label ?? service,
          ciphertext,
          salt,
          iv,
          auth_tag,
          updated_at: new Date().toISOString(),
        },
        { onConflict: "user_id,service" }
      )
      .select("id, service, label, created_at, updated_at")
      .single();

    if (error) return res.status(500).json({ error: error.message });
    return res.status(201).json({ credential: data });
  }

  return res.status(405).json({ error: "Method not allowed" });
}
