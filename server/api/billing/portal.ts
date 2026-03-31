/**
 * GET /api/billing/portal
 * Returns: { url } — Stripe Customer Portal session URL
 *
 * Required env vars:
 *   STRIPE_SECRET_KEY   sk_live_... or sk_test_...
 *   APP_URL             https://app.axisproxy.com
 */

import type { VercelRequest, VercelResponse } from "@vercel/node";
import Stripe from "stripe";
import { getSupabase, getSupabaseForUser, extractToken } from "../../lib/supabase.js";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: "2025-02-24.acacia",
});

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

  const token = extractToken(req.headers as Record<string, string>);
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  const supabase = getSupabaseForUser(token);
  const {
    data: { user },
    error: authError,
  } = await supabase.auth.getUser();
  if (authError || !user) return res.status(401).json({ error: "Unauthorized" });

  const admin = getSupabase();
  const { data: sub } = await admin
    .from("subscriptions")
    .select("stripe_customer_id")
    .eq("user_id", user.id)
    .single();

  const customerId = sub?.stripe_customer_id as string | undefined;
  if (!customerId) {
    return res.status(400).json({ error: "No billing account found. Subscribe first." });
  }

  const session = await stripe.billingPortal.sessions.create({
    customer: customerId,
    return_url: `${process.env.APP_URL}/dashboard/billing`,
  });

  return res.status(200).json({ url: session.url });
}
