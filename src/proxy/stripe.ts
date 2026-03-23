/**
 * proxy/stripe.ts
 *
 * Stripe API proxy.
 * Axis retrieves the stored API key and injects it — the agent never sees it.
 *
 * Supported actions:
 *   service: "stripe"
 *   action:  "paymentIntents.create" | "customers.list"
 *
 * Security invariants:
 *   - The API key is retrieved from the keystore and used only in the
 *     Authorization header; it is never returned to the caller.
 *   - Error messages never include the API key.
 *   - Request body is built from validated + sanitized params only.
 */

import { Keystore } from "../vault/keystore.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PaymentIntentsCreateParams {
  amount: number;
  currency: string;
  [key: string]: unknown;
}

export interface CustomersListParams {
  [key: string]: unknown;
}

interface ProxyResult {
  ok: true;
  data: unknown;
}

interface ProxyError {
  ok: false;
  error: string;
  status?: number;
}

type ProxyResponse = ProxyResult | ProxyError;

// ---------------------------------------------------------------------------
// Sanitization
// ---------------------------------------------------------------------------

export function sanitizeParams(
  params: Record<string, unknown>
): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(params).filter(([k]) => {
      const lower = k.toLowerCase();
      return (
        !lower.includes("key") &&
        !lower.includes("secret") &&
        !lower.includes("token") &&
        !lower.includes("password") &&
        !lower.includes("auth")
      );
    })
  );
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

function requireString(params: Record<string, unknown>, key: string): string {
  const val = params[key];
  if (!val || typeof val !== "string" || val.trim().length === 0) {
    throw new Error(`Required param "${key}" must be a non-empty string.`);
  }
  return val;
}

function requireNumber(params: Record<string, unknown>, key: string): number {
  const val = params[key];
  if (val === undefined || val === null || typeof val !== "number") {
    throw new Error(`Required param "${key}" must be a number.`);
  }
  return val;
}

function requireBaseObject(params: unknown): Record<string, unknown> {
  if (!params || typeof params !== "object" || Array.isArray(params)) {
    throw new Error("Params must be a non-null object.");
  }
  return params as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Per-action validation
// ---------------------------------------------------------------------------

export function validatePaymentIntentsCreateParams(
  params: unknown
): PaymentIntentsCreateParams {
  const p = requireBaseObject(params);
  requireNumber(p, "amount");
  requireString(p, "currency");
  return p as PaymentIntentsCreateParams;
}

export function validateCustomersListParams(
  params: unknown
): CustomersListParams {
  const p = requireBaseObject(params);
  // Optional: limit (1–100), email
  if (p["limit"] !== undefined) {
    if (typeof p["limit"] !== "number" || p["limit"] < 1 || p["limit"] > 100) {
      throw new Error(`Optional param "limit" must be a number between 1 and 100.`);
    }
  }
  return p as CustomersListParams;
}

// ---------------------------------------------------------------------------
// Shared fetch helper
// ---------------------------------------------------------------------------

const STRIPE_API_BASE = "https://api.stripe.com";

async function stripeFetch(
  url: string,
  method: string,
  apiKey: string,
  body?: Record<string, unknown>
): Promise<ProxyResponse> {
  let response: Response;
  try {
    // Stripe uses form-encoded bodies for POST
    const headers: Record<string, string> = {
      Authorization: `Bearer ${apiKey}`,
      "User-Agent": "axis/0.1.0",
    };

    let bodyContent: string | undefined;
    if (body && method !== "GET") {
      headers["Content-Type"] = "application/x-www-form-urlencoded";
      bodyContent = new URLSearchParams(
        Object.entries(body).reduce<Record<string, string>>((acc, [k, v]) => {
          acc[k] = String(v);
          return acc;
        }, {})
      ).toString();
    }

    response = await fetch(url, {
      method,
      headers,
      body: bodyContent,
    });
  } catch (err) {
    const msg = (err as Error).message.replace(apiKey, "[REDACTED]");
    return { ok: false, error: `Network error calling Stripe API: ${msg}` };
  }

  let responseData: unknown;
  try {
    responseData = await response.json();
  } catch {
    return {
      ok: false,
      error: `Stripe API returned non-JSON response (HTTP ${response.status}).`,
      status: response.status,
    };
  }

  if (!response.ok) {
    const errMsg =
      (responseData as { error?: { message?: string } })?.error?.message ??
      `HTTP ${response.status}`;
    return { ok: false, error: `Stripe API error: ${errMsg}`, status: response.status };
  }

  return { ok: true, data: responseData };
}

// ---------------------------------------------------------------------------
// Action proxy functions
// ---------------------------------------------------------------------------

async function proxyPaymentIntentsCreate(
  params: unknown,
  keystore: Keystore
): Promise<ProxyResponse> {
  let validated: PaymentIntentsCreateParams;
  try {
    validated = validatePaymentIntentsCreateParams(params);
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }

  let apiKey: string;
  try {
    apiKey = keystore.getSecret("stripe");
  } catch (err) {
    return {
      ok: false,
      error: `Could not retrieve Stripe secret from keystore: ${(err as Error).message}`,
    };
  }

  const { amount, currency, ...rest } = validated;
  const body = { amount: String(amount), currency, ...sanitizeParams(rest as Record<string, unknown>) };
  const url = `${STRIPE_API_BASE}/v1/payment_intents`;
  const result = await stripeFetch(url, "POST", apiKey, body as Record<string, unknown>);
  apiKey = "";
  return result;
}

async function proxyCustomersList(
  params: unknown,
  keystore: Keystore
): Promise<ProxyResponse> {
  let validated: CustomersListParams;
  try {
    validated = validateCustomersListParams(params);
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }

  let apiKey: string;
  try {
    apiKey = keystore.getSecret("stripe");
  } catch (err) {
    return {
      ok: false,
      error: `Could not retrieve Stripe secret from keystore: ${(err as Error).message}`,
    };
  }

  const sanitized = sanitizeParams(validated as Record<string, unknown>);
  const queryParams = new URLSearchParams(
    Object.entries(sanitized).reduce<Record<string, string>>((acc, [k, v]) => {
      acc[k] = String(v);
      return acc;
    }, {})
  ).toString();
  const url = `${STRIPE_API_BASE}/v1/customers${queryParams ? `?${queryParams}` : ""}`;
  const result = await stripeFetch(url, "GET", apiKey);
  apiKey = "";
  return result;
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

export async function proxyStripeAction(
  action: string,
  params: unknown,
  keystore: Keystore
): Promise<ProxyResponse> {
  switch (action) {
    case "paymentIntents.create":
      return proxyPaymentIntentsCreate(params, keystore);
    case "customers.list":
      return proxyCustomersList(params, keystore);
    default:
      return { ok: false, error: `Unsupported Stripe action: "${action}".` };
  }
}
