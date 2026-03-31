/**
 * server/api/stripe-webhook.ts
 *
 * Stripe webhook — updates subscription tier in Supabase.
 *
 * Required env vars:
 *   STRIPE_SECRET_KEY       sk_live_... or sk_test_...
 *   STRIPE_WEBHOOK_SECRET   whsec_...
 *   SUPABASE_URL            from Supabase project settings
 *   SUPABASE_SERVICE_KEY    service_role key
 */

import type { VercelRequest, VercelResponse } from "@vercel/node";
import Stripe from "stripe";
import { getSupabase } from "../lib/supabase.js";

export const config = { api: { bodyParser: false } };

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: "2025-02-24.acacia",
});

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const sig = req.headers["stripe-signature"] as string;
  if (!sig) return res.status(400).json({ error: "Missing stripe-signature" });

  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body as Buffer,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET!
    );
  } catch (err) {
    console.error("Webhook signature failed:", (err as Error).message);
    return res.status(400).json({ error: "Invalid signature" });
  }

  const supabase = getSupabase();

  switch (event.type) {
    case "checkout.session.completed": {
      const session = event.data.object as Stripe.Checkout.Session;
      const userId = session.metadata?.userId;
      const tier = session.metadata?.tier ?? "pro";
      const subscriptionId =
        typeof session.subscription === "string"
          ? session.subscription
          : session.subscription?.id;

      if (!userId || !subscriptionId) break;

      const sub = await stripe.subscriptions.retrieve(subscriptionId);
      const periodEnd = new Date(sub.current_period_end * 1000).toISOString();

      await supabase.from("subscriptions").upsert({
        user_id: userId,
        tier,
        stripe_subscription_id: subscriptionId,
        status: "active",
        current_period_end: periodEnd,
      });

      console.log(`Subscription activated: userId=${userId} tier=${tier}`);
      break;
    }

    case "customer.subscription.updated": {
      const sub = event.data.object as Stripe.Subscription;
      const customerId = typeof sub.customer === "string" ? sub.customer : sub.customer.id;
      const periodEnd = new Date(sub.current_period_end * 1000).toISOString();

      const { data: row } = await supabase
        .from("subscriptions")
        .select("user_id")
        .eq("stripe_customer_id", customerId)
        .single();

      if (row) {
        await supabase
          .from("subscriptions")
          .update({ status: sub.status, current_period_end: periodEnd })
          .eq("user_id", row.user_id);
      }
      break;
    }

    case "customer.subscription.deleted": {
      const sub = event.data.object as Stripe.Subscription;
      const customerId = typeof sub.customer === "string" ? sub.customer : sub.customer.id;

      const { data: row } = await supabase
        .from("subscriptions")
        .select("user_id")
        .eq("stripe_customer_id", customerId)
        .single();

      if (row) {
        await supabase
          .from("subscriptions")
          .update({ tier: "free", status: "canceled", stripe_subscription_id: null })
          .eq("user_id", row.user_id);
        console.log(`Subscription canceled: userId=${row.user_id} → free tier`);
      }
      break;
    }

    default:
      break;
  }

  return res.status(200).json({ received: true });
}
