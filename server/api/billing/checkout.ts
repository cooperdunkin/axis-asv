/**
 * POST /api/billing/checkout
 * Body: { tier: "pro" | "team", seats?: number }
 * Returns: { url } — Stripe Checkout session URL
 *
 * Required env vars:
 *   STRIPE_SECRET_KEY       sk_live_... or sk_test_...
 *   STRIPE_PRO_PRICE_ID     price_... for Pro tier
 *   STRIPE_TEAM_PRICE_ID    price_... for Team tier
 *   APP_URL                 https://app.axisproxy.com
 */

import type { VercelRequest, VercelResponse } from "@vercel/node";
import Stripe from "stripe";
import { getSupabase, getSupabaseForUser, extractToken } from "../../lib/supabase.js";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: "2025-02-24.acacia",
});

const PRICE_IDS: Record<string, string> = {
  pro: process.env.STRIPE_PRO_PRICE_ID!,
  team: process.env.STRIPE_TEAM_PRICE_ID!,
};

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const token = extractToken(req.headers as Record<string, string>);
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  const supabase = getSupabaseForUser(token);
  const { data: { user }, error: authError } = await supabase.auth.getUser();
  if (authError || !user) return res.status(401).json({ error: "Unauthorized" });

  const { tier, seats } = req.body as { tier?: string; seats?: number };
  if (!tier || !PRICE_IDS[tier]) {
    return res.status(400).json({ error: "Invalid tier. Must be 'pro' or 'team'" });
  }

  // Get or create Stripe customer
  const admin = getSupabase();
  const { data: sub } = await admin
    .from("subscriptions")
    .select("stripe_customer_id")
    .eq("user_id", user.id)
    .single();

  let customerId = sub?.stripe_customer_id as string | null;
  if (!customerId) {
    const customer = await stripe.customers.create({ email: user.email });
    customerId = customer.id;
    await admin
      .from("subscriptions")
      .upsert({ user_id: user.id, stripe_customer_id: customerId, tier: "free", status: "active" });
  }

  const session = await stripe.checkout.sessions.create({
    customer: customerId,
    mode: "subscription",
    payment_method_types: ["card"],
    line_items: [{ price: PRICE_IDS[tier], quantity: tier === "team" ? (seats ?? 3) : 1 }],
    success_url: `${process.env.APP_URL}/dashboard/billing?success=true`,
    cancel_url: `${process.env.APP_URL}/dashboard/billing?canceled=true`,
    metadata: { userId: user.id, tier },
  });

  return res.status(200).json({ url: session.url });
}
