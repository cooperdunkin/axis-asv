/**
 * GET    /api/credentials/:id  — fetch one credential including ciphertext (for MCP server)
 * DELETE /api/credentials/:id  — delete a credential
 */

import type { VercelRequest, VercelResponse } from "@vercel/node";
import { getSupabaseForUser, extractToken } from "../../lib/supabase.js";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  const token = extractToken(req.headers as Record<string, string>);
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  const supabase = getSupabaseForUser(token);
  const { data: { user }, error: authError } = await supabase.auth.getUser();
  if (authError || !user) return res.status(401).json({ error: "Unauthorized" });

  const { id } = req.query as { id: string };

  if (req.method === "GET") {
    const { data, error } = await supabase
      .from("credentials")
      .select("id, service, label, ciphertext, salt, iv, auth_tag, created_at, updated_at")
      .eq("id", id)
      .single();

    if (error || !data) return res.status(404).json({ error: "Credential not found" });
    return res.status(200).json({ credential: data });
  }

  if (req.method === "DELETE") {
    const { data, error } = await supabase
      .from("credentials")
      .delete()
      .eq("id", id)
      .select("id, service")
      .single();

    if (error || !data) return res.status(404).json({ error: "Credential not found" });
    return res.status(200).json({ deleted: true, service: data.service });
  }

  return res.status(405).json({ error: "Method not allowed" });
}
