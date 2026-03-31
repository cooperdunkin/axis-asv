/**
 * GET  /api/audit-logs   — paginated audit log for current user
 * POST /api/audit-logs   — append an entry (called by MCP server)
 */

import type { VercelRequest, VercelResponse } from "@vercel/node";
import { getSupabaseForUser, extractToken } from "../lib/supabase.js";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  const token = extractToken(req.headers as Record<string, string>);
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  const supabase = getSupabaseForUser(token);
  const { data: { user }, error: authError } = await supabase.auth.getUser();
  if (authError || !user) return res.status(401).json({ error: "Unauthorized" });

  if (req.method === "GET") {
    const limit = Math.min(Number(req.query.limit ?? 50), 200);
    const offset = Number(req.query.offset ?? 0);

    const { data, error, count } = await supabase
      .from("audit_logs")
      .select("id, service, action, decision, identity, latency_ms, error, request_id, created_at", { count: "exact" })
      .eq("user_id", user.id)
      .order("created_at", { ascending: false })
      .range(offset, offset + limit - 1);

    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ logs: data, total: count, limit, offset });
  }

  if (req.method === "POST") {
    const { service, action, decision, identity, latency_ms, error: logError, request_id } =
      req.body as {
        service: string;
        action: string;
        decision: string;
        identity?: string;
        latency_ms?: number;
        error?: string;
        request_id?: string;
      };

    if (!service || !action || !decision) {
      return res.status(400).json({ error: "service, action, and decision are required" });
    }

    const { data, error } = await supabase
      .from("audit_logs")
      .insert({
        user_id: user.id,
        service,
        action,
        decision,
        identity: identity ?? null,
        latency_ms: latency_ms ?? null,
        error: logError ?? null,
        request_id: request_id ?? null,
      })
      .select("id, created_at")
      .single();

    if (error) return res.status(500).json({ error: error.message });
    return res.status(201).json(data);
  }

  return res.status(405).json({ error: "Method not allowed" });
}
