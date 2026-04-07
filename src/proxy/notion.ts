/**
 * proxy/notion.ts
 *
 * Notion API proxy.
 * Axis retrieves the stored integration token and injects it — the agent never sees it.
 *
 * Supported actions:
 *   service: "notion"
 *   action:  "pages.create" | "databases.query"
 *
 * Security invariants:
 *   - The token is retrieved from the keystore and used only in the
 *     Authorization header; it is never returned to the caller.
 *   - Error messages never include the token.
 *   - Request body is built from validated + sanitized params only.
 */

import { SecretStore } from "../vault/keystore.js";
import { fetchWithTimeout } from "./fetchWithTimeout.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PagesCreateParams {
  parent: { database_id?: string; page_id?: string };
  properties: Record<string, unknown>;
  [key: string]: unknown;
}

export interface DatabasesQueryParams {
  database_id: string;
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

export function validatePagesCreateParams(params: unknown): PagesCreateParams {
  const p = requireBaseObject(params);

  if (!p["parent"] || typeof p["parent"] !== "object" || Array.isArray(p["parent"])) {
    throw new Error(`Required param "parent" must be an object with "database_id" or "page_id".`);
  }
  const parent = p["parent"] as Record<string, unknown>;
  if (!parent["database_id"] && !parent["page_id"]) {
    throw new Error(`Required param "parent" must have "database_id" or "page_id".`);
  }

  if (!p["properties"] || typeof p["properties"] !== "object" || Array.isArray(p["properties"])) {
    throw new Error(`Required param "properties" must be an object.`);
  }
  if (Object.keys(p["properties"] as Record<string, unknown>).length === 0) {
    throw new Error("properties must contain at least one property");
  }

  return p as PagesCreateParams;
}

export function validateDatabasesQueryParams(
  params: unknown
): DatabasesQueryParams {
  const p = requireBaseObject(params);
  requireString(p, "database_id");
  return p as DatabasesQueryParams;
}

// ---------------------------------------------------------------------------
// Shared fetch helper
// ---------------------------------------------------------------------------

const NOTION_API_BASE = "https://api.notion.com";
const NOTION_VERSION = "2022-06-28";

async function notionFetch(
  url: string,
  method: string,
  token: string,
  body?: unknown
): Promise<ProxyResponse> {
  let response: Response;
  try {
    response = await fetchWithTimeout(url, {
      method,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
        "Notion-Version": NOTION_VERSION,
        "User-Agent": "axis/0.1.0",
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch (err: any) {
    if (err?.name === "AbortError") {
      return { ok: false, error: "Request timed out after 30 seconds" };
    }
    const msg = (err as Error).message.replace(token, "[REDACTED]");
    return { ok: false, error: `Network error calling Notion API: ${msg}` };
  }

  let responseData: unknown;
  try {
    responseData = await response.json();
  } catch {
    return {
      ok: false,
      error: `Notion API returned non-JSON response (HTTP ${response.status}).`,
      status: response.status,
    };
  }

  if (!response.ok) {
    const errMsg =
      (responseData as { message?: string })?.message ?? `HTTP ${response.status}`;
    return { ok: false, error: `Notion API error: ${errMsg}`, status: response.status };
  }

  return { ok: true, data: responseData };
}

// ---------------------------------------------------------------------------
// Action proxy functions
// ---------------------------------------------------------------------------

async function proxyPagesCreate(
  params: unknown,
  keystore: SecretStore
): Promise<ProxyResponse> {
  let validated: PagesCreateParams;
  try {
    validated = validatePagesCreateParams(params);
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }

  let token: string;
  try {
    token = keystore.getSecret("notion");
  } catch (err) {
    return {
      ok: false,
      error: `Could not retrieve Notion secret from keystore: ${(err as Error).message}`,
    };
  }

  const { parent, properties, children, ...rest } = validated;
  const body: Record<string, unknown> = {
    parent,
    properties,
    ...(children ? { children } : {}),
    ...sanitizeParams(rest as Record<string, unknown>),
  };

  const url = `${NOTION_API_BASE}/v1/pages`;
  try {
    return await notionFetch(url, "POST", token, body);
  } finally {
    token = "";
  }
}

async function proxyDatabasesQuery(
  params: unknown,
  keystore: SecretStore
): Promise<ProxyResponse> {
  let validated: DatabasesQueryParams;
  try {
    validated = validateDatabasesQueryParams(params);
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }

  let token: string;
  try {
    token = keystore.getSecret("notion");
  } catch (err) {
    return {
      ok: false,
      error: `Could not retrieve Notion secret from keystore: ${(err as Error).message}`,
    };
  }

  const { database_id, ...rest } = validated;
  const body = sanitizeParams(rest as Record<string, unknown>);
  const url = `${NOTION_API_BASE}/v1/databases/${encodeURIComponent(database_id)}/query`;
  try {
    return await notionFetch(url, "POST", token, Object.keys(body).length ? body : undefined);
  } finally {
    token = "";
  }
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

export async function proxyNotionAction(
  action: string,
  params: unknown,
  keystore: SecretStore
): Promise<ProxyResponse> {
  switch (action) {
    case "pages.create":
      return proxyPagesCreate(params, keystore);
    case "databases.query":
      return proxyDatabasesQuery(params, keystore);
    default:
      return { ok: false, error: `Unsupported Notion action: "${action}".` };
  }
}
