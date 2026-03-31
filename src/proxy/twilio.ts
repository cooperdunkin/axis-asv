/**
 * proxy/twilio.ts
 *
 * Twilio API proxy.
 * Axis retrieves the stored credential and injects it — the agent never sees it.
 *
 * Supported actions:
 *   service: "twilio"
 *   action:  "messages.create"
 *
 * Security invariants:
 *   - The credential is retrieved from the keystore and used only for auth;
 *     it is never returned to the caller.
 *   - Error messages never include the credential.
 *   - Request body is built from validated + sanitized params only.
 *
 * Credential format: Store as "accountSid:authToken" (combined secret).
 * The proxy splits on first ":" at call time.
 * Use "axis add twilio" and enter your credential in "accountSid:authToken" format.
 */

import { SecretStore } from "../vault/keystore.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface MessagesCreateParams {
  accountSid: string;
  to: string;
  from: string;
  body: string;
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

function requireBaseObject(params: unknown): Record<string, unknown> {
  if (!params || typeof params !== "object" || Array.isArray(params)) {
    throw new Error("Params must be a non-null object.");
  }
  return params as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Per-action validation
// ---------------------------------------------------------------------------

export function validateMessagesCreateParams(
  params: unknown
): MessagesCreateParams {
  const p = requireBaseObject(params);
  requireString(p, "accountSid");
  requireString(p, "to");
  requireString(p, "from");
  requireString(p, "body");
  return p as MessagesCreateParams;
}

// ---------------------------------------------------------------------------
// Shared fetch helper
// ---------------------------------------------------------------------------

const TWILIO_API_BASE = "https://api.twilio.com/2010-04-01";

async function twilioFetch(
  url: string,
  accountSid: string,
  authToken: string,
  body: Record<string, string>
): Promise<ProxyResponse> {
  const credential = `${accountSid}:${authToken}`;
  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${Buffer.from(credential).toString("base64")}`,
        "User-Agent": "axis/0.1.0",
      },
      body: new URLSearchParams(body).toString(),
    });
  } catch (err) {
    const msg = (err as Error).message
      .replace(accountSid, "[REDACTED]")
      .replace(authToken, "[REDACTED]");
    return { ok: false, error: `Network error calling Twilio API: ${msg}` };
  }

  let responseData: unknown;
  try {
    responseData = await response.json();
  } catch {
    return {
      ok: false,
      error: `Twilio API returned non-JSON response (HTTP ${response.status}).`,
      status: response.status,
    };
  }

  if (!response.ok) {
    const errMsg =
      (responseData as { message?: string })?.message ?? `HTTP ${response.status}`;
    return { ok: false, error: `Twilio API error: ${errMsg}`, status: response.status };
  }

  return { ok: true, data: responseData };
}

// ---------------------------------------------------------------------------
// Action proxy functions
// ---------------------------------------------------------------------------

async function proxyMessagesCreate(
  params: unknown,
  keystore: SecretStore
): Promise<ProxyResponse> {
  let validated: MessagesCreateParams;
  try {
    validated = validateMessagesCreateParams(params);
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }

  let credential: string;
  try {
    credential = keystore.getSecret("twilio");
  } catch (err) {
    return {
      ok: false,
      error: `Could not retrieve Twilio secret from keystore: ${(err as Error).message}`,
    };
  }

  // Split on first ":" to get accountSid and authToken
  const colonIndex = credential.indexOf(":");
  if (colonIndex === -1) {
    credential = "";
    return {
      ok: false,
      error: `Twilio credential must be in "accountSid:authToken" format.`,
    };
  }
  const accountSid = credential.substring(0, colonIndex);
  let authToken = credential.substring(colonIndex + 1);
  credential = "";

  const { accountSid: _sid, to, from, body, ...rest } = validated;
  const formBody: Record<string, string> = {
    To: to,
    From: from,
    Body: body,
  };

  // Add any extra sanitized params
  const sanitized = sanitizeParams(rest as Record<string, unknown>);
  for (const [k, v] of Object.entries(sanitized)) {
    formBody[k] = String(v);
  }

  const url = `${TWILIO_API_BASE}/Accounts/${encodeURIComponent(accountSid)}/Messages.json`;
  const result = await twilioFetch(url, accountSid, authToken, formBody);
  authToken = "";
  return result;
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

export async function proxyTwilioAction(
  action: string,
  params: unknown,
  keystore: SecretStore
): Promise<ProxyResponse> {
  switch (action) {
    case "messages.create":
      return proxyMessagesCreate(params, keystore);
    default:
      return { ok: false, error: `Unsupported Twilio action: "${action}".` };
  }
}
