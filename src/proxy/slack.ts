/**
 * proxy/slack.ts
 *
 * Slack API proxy.
 * Axis retrieves the stored bot token and injects it — the agent never sees it.
 *
 * Supported actions:
 *   service: "slack"
 *   action:  "chat.postMessage" | "conversations.list"
 *
 * Security invariants:
 *   - The token is retrieved from the keystore and used only in the
 *     Authorization header; it is never returned to the caller.
 *   - Error messages never include the token.
 *   - Request body is built from validated + sanitized params only.
 */

import { Keystore } from "../vault/keystore.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ChatPostMessageParams {
  channel: string;
  text: string;
  [key: string]: unknown;
}

export interface ConversationsListParams {
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

export function validateChatPostMessageParams(
  params: unknown
): ChatPostMessageParams {
  const p = requireBaseObject(params);
  requireString(p, "channel");
  requireString(p, "text");
  return p as ChatPostMessageParams;
}

export function validateConversationsListParams(
  params: unknown
): ConversationsListParams {
  const p = requireBaseObject(params);
  return p as ConversationsListParams;
}

// ---------------------------------------------------------------------------
// Shared fetch helper
// ---------------------------------------------------------------------------

const SLACK_API_BASE = "https://slack.com/api";

async function slackFetch(
  url: string,
  method: string,
  token: string,
  body?: unknown
): Promise<ProxyResponse> {
  let response: Response;
  try {
    response = await fetch(url, {
      method,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
        "User-Agent": "axis/0.1.0",
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch (err) {
    const msg = (err as Error).message.replace(token, "[REDACTED]");
    return { ok: false, error: `Network error calling Slack API: ${msg}` };
  }

  let responseData: unknown;
  try {
    responseData = await response.json();
  } catch {
    return {
      ok: false,
      error: `Slack API returned non-JSON response (HTTP ${response.status}).`,
      status: response.status,
    };
  }

  // Slack returns HTTP 200 even for errors; check the "ok" field
  if (!response.ok || !(responseData as { ok?: boolean })?.ok) {
    const errMsg =
      (responseData as { error?: string })?.error ?? `HTTP ${response.status}`;
    return { ok: false, error: `Slack API error: ${errMsg}`, status: response.status };
  }

  return { ok: true, data: responseData };
}

// ---------------------------------------------------------------------------
// Action proxy functions
// ---------------------------------------------------------------------------

async function proxyChatPostMessage(
  params: unknown,
  keystore: Keystore
): Promise<ProxyResponse> {
  let validated: ChatPostMessageParams;
  try {
    validated = validateChatPostMessageParams(params);
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }

  let token: string;
  try {
    token = keystore.getSecret("slack");
  } catch (err) {
    return {
      ok: false,
      error: `Could not retrieve Slack secret from keystore: ${(err as Error).message}`,
    };
  }

  const { channel, text, ...rest } = validated;
  const body = { channel, text, ...sanitizeParams(rest as Record<string, unknown>) };
  const url = `${SLACK_API_BASE}/chat.postMessage`;
  const result = await slackFetch(url, "POST", token, body);
  token = "";
  return result;
}

async function proxyConversationsList(
  params: unknown,
  keystore: Keystore
): Promise<ProxyResponse> {
  let validated: ConversationsListParams;
  try {
    validated = validateConversationsListParams(params);
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }

  let token: string;
  try {
    token = keystore.getSecret("slack");
  } catch (err) {
    return {
      ok: false,
      error: `Could not retrieve Slack secret from keystore: ${(err as Error).message}`,
    };
  }

  const sanitized = sanitizeParams(validated as Record<string, unknown>);
  const queryParams = new URLSearchParams(
    Object.entries(sanitized).reduce<Record<string, string>>((acc, [k, v]) => {
      acc[k] = String(v);
      return acc;
    }, {})
  ).toString();
  const url = `${SLACK_API_BASE}/conversations.list${queryParams ? `?${queryParams}` : ""}`;
  const result = await slackFetch(url, "GET", token);
  token = "";
  return result;
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

export async function proxySlackAction(
  action: string,
  params: unknown,
  keystore: Keystore
): Promise<ProxyResponse> {
  switch (action) {
    case "chat.postMessage":
      return proxyChatPostMessage(params, keystore);
    case "conversations.list":
      return proxyConversationsList(params, keystore);
    default:
      return { ok: false, error: `Unsupported Slack action: "${action}".` };
  }
}
