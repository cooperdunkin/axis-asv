/**
 * proxy/sendgrid.ts
 *
 * SendGrid API proxy.
 * Axis retrieves the stored API key and injects it — the agent never sees it.
 *
 * Supported actions:
 *   service: "sendgrid"
 *   action:  "mail.send"
 *
 * Security invariants:
 *   - The API key is retrieved from the keystore and used only in the
 *     Authorization header; it is never returned to the caller.
 *   - Error messages never include the API key.
 *   - Request body is built from validated + sanitized params only.
 */

import { SecretStore } from "../vault/keystore.js";
import { fetchWithTimeout } from "./fetchWithTimeout.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface MailSendParams {
  to: string | string[];
  from: string;
  subject: string;
  text?: string;
  html?: string;
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

export function validateMailSendParams(params: unknown): MailSendParams {
  const p = requireBaseObject(params);

  // Validate "to"
  if (p["to"] === undefined || p["to"] === null) {
    throw new Error(`Required param "to" is missing.`);
  }
  if (
    typeof p["to"] !== "string" &&
    !(Array.isArray(p["to"]) && p["to"].length > 0)
  ) {
    throw new Error(`Required param "to" must be a non-empty string or array.`);
  }

  requireString(p, "from");
  requireString(p, "subject");

  if (!p["text"] && !p["html"]) {
    throw new Error(`Either "text" or "html" body is required.`);
  }

  return p as MailSendParams;
}

// ---------------------------------------------------------------------------
// Shared fetch helper
// ---------------------------------------------------------------------------

const SENDGRID_API_BASE = "https://api.sendgrid.com";

async function sendgridFetch(
  url: string,
  method: string,
  apiKey: string,
  body?: unknown
): Promise<ProxyResponse> {
  let response: Response;
  try {
    response = await fetchWithTimeout(url, {
      method,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
        "User-Agent": "axis/0.1.0",
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch (err: any) {
    if (err?.name === "AbortError") {
      return { ok: false, error: "Request timed out after 30 seconds" };
    }
    const msg = (err as Error).message.replace(apiKey, "[REDACTED]");
    return { ok: false, error: `Network error calling SendGrid API: ${msg}` };
  }

  // SendGrid mail.send returns 202 Accepted with empty body on success
  if (response.status === 202) {
    return { ok: true, data: { accepted: true } };
  }

  let responseData: unknown;
  try {
    responseData = await response.json();
  } catch {
    return {
      ok: false,
      error: `SendGrid API returned non-JSON response (HTTP ${response.status}).`,
      status: response.status,
    };
  }

  if (!response.ok) {
    const errors = (responseData as { errors?: Array<{ message?: string }> })?.errors;
    const errMsg = errors?.[0]?.message ?? `HTTP ${response.status}`;
    return { ok: false, error: `SendGrid API error: ${errMsg}`, status: response.status };
  }

  return { ok: true, data: responseData };
}

// ---------------------------------------------------------------------------
// Action proxy functions
// ---------------------------------------------------------------------------

async function proxyMailSend(
  params: unknown,
  keystore: SecretStore
): Promise<ProxyResponse> {
  let validated: MailSendParams;
  try {
    validated = validateMailSendParams(params);
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }

  let apiKey: string;
  try {
    apiKey = keystore.getSecret("sendgrid");
  } catch (err) {
    return {
      ok: false,
      error: `Could not retrieve SendGrid secret from keystore: ${(err as Error).message}`,
    };
  }

  // Build SendGrid v3 mail/send body format
  const toAddresses = Array.isArray(validated.to) ? validated.to : [validated.to];
  const body = {
    personalizations: [
      {
        to: toAddresses.map((addr) => ({ email: addr })),
      },
    ],
    from: { email: validated.from },
    subject: validated.subject,
    content: (() => {
      const c: Array<{ type: string; value: string }> = [];
      if (validated.text) c.push({ type: "text/plain", value: validated.text });
      if (validated.html) c.push({ type: "text/html", value: validated.html });
      return c;
    })(),
  };

  const url = `${SENDGRID_API_BASE}/v3/mail/send`;
  try {
    return await sendgridFetch(url, "POST", apiKey, body);
  } finally {
    apiKey = "";
  }
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

export async function proxySendGridAction(
  action: string,
  params: unknown,
  keystore: SecretStore
): Promise<ProxyResponse> {
  switch (action) {
    case "mail.send":
      return proxyMailSend(params, keystore);
    default:
      return { ok: false, error: `Unsupported SendGrid action: "${action}".` };
  }
}
