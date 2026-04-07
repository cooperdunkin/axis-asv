/**
 * proxy/gcp.ts
 *
 * Google Cloud Storage proxy.
 * Axis retrieves the stored access token and injects it — the agent never sees it.
 *
 * Supported actions:
 *   service: "gcp"
 *   action:  "storage.getObject" | "storage.listObjects"
 *
 * Security invariants:
 *   - The access token is retrieved from the keystore and used only in the
 *     Authorization header; it is never returned to the caller.
 *   - Error messages never include the token.
 *
 * Auth: Store a pre-generated OAuth2 access token.
 * Use "axis add gcp" and enter your access token.
 * Note: Access tokens expire (~1 hour). Re-run "axis add gcp" to refresh.
 */

import { SecretStore } from "../vault/keystore.js";
import { fetchWithTimeout } from "./fetchWithTimeout.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface StorageGetObjectParams {
  bucket: string;
  object: string;
  [key: string]: unknown;
}

export interface StorageListObjectsParams {
  bucket: string;
  prefix?: string;
  maxResults?: number;
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

export function validateStorageGetObjectParams(
  params: unknown
): StorageGetObjectParams {
  const p = requireBaseObject(params);
  requireString(p, "bucket");
  requireString(p, "object");
  return p as StorageGetObjectParams;
}

export function validateStorageListObjectsParams(
  params: unknown
): StorageListObjectsParams {
  const p = requireBaseObject(params);
  requireString(p, "bucket");
  if (p["maxResults"] !== undefined) {
    if (typeof p["maxResults"] !== "number" || p["maxResults"] <= 0) {
      throw new Error(`Optional param "maxResults" must be a positive number.`);
    }
  }
  return p as StorageListObjectsParams;
}

// ---------------------------------------------------------------------------
// Shared fetch helper
// ---------------------------------------------------------------------------

const GCS_API_BASE = "https://storage.googleapis.com";

async function gcsFetch(
  url: string,
  accessToken: string
): Promise<ProxyResponse> {
  let response: Response;
  try {
    response = await fetchWithTimeout(url, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "User-Agent": "axis/0.1.0",
      },
    });
  } catch (err: any) {
    if (err?.name === "AbortError") {
      return { ok: false, error: "Request timed out after 30 seconds" };
    }
    const msg = (err as Error).message.replace(accessToken, "[REDACTED]");
    return { ok: false, error: `Network error calling GCS API: ${msg}` };
  }

  if (!response.ok) {
    let errorDetail = `HTTP ${response.status}`;
    try {
      const errData = (await response.json()) as { error?: { message?: string } };
      errorDetail = errData?.error?.message ?? errorDetail;
    } catch {
      // ignore JSON parse failures
    }
    return { ok: false, error: `GCS API error: ${errorDetail}`, status: response.status };
  }

  // For media downloads, return raw text; for JSON responses, parse
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    try {
      const data = await response.json();
      return { ok: true, data };
    } catch {
      return {
        ok: false,
        error: `GCS API returned invalid JSON (HTTP ${response.status}).`,
        status: response.status,
      };
    }
  }

  const text = await response.text();
  return { ok: true, data: text };
}

// ---------------------------------------------------------------------------
// Action proxy functions
// ---------------------------------------------------------------------------

async function proxyStorageGetObject(
  params: unknown,
  keystore: SecretStore
): Promise<ProxyResponse> {
  let validated: StorageGetObjectParams;
  try {
    validated = validateStorageGetObjectParams(params);
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }

  let accessToken: string;
  try {
    accessToken = keystore.getSecret("gcp");
  } catch (err) {
    return {
      ok: false,
      error: `Could not retrieve GCP secret from keystore: ${(err as Error).message}`,
    };
  }

  const url = `${GCS_API_BASE}/storage/v1/b/${encodeURIComponent(validated.bucket)}/o/${encodeURIComponent(validated.object)}?alt=media`;
  try {
    return await gcsFetch(url, accessToken);
  } finally {
    accessToken = "";
  }
}

async function proxyStorageListObjects(
  params: unknown,
  keystore: SecretStore
): Promise<ProxyResponse> {
  let validated: StorageListObjectsParams;
  try {
    validated = validateStorageListObjectsParams(params);
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }

  let accessToken: string;
  try {
    accessToken = keystore.getSecret("gcp");
  } catch (err) {
    return {
      ok: false,
      error: `Could not retrieve GCP secret from keystore: ${(err as Error).message}`,
    };
  }

  const queryParts: string[] = [];
  if (validated.prefix) {
    queryParts.push(`prefix=${encodeURIComponent(validated.prefix)}`);
  }
  if (validated.maxResults !== undefined) {
    queryParts.push(`maxResults=${validated.maxResults}`);
  }
  const queryString = queryParts.length ? `?${queryParts.join("&")}` : "";
  const url = `${GCS_API_BASE}/storage/v1/b/${encodeURIComponent(validated.bucket)}/o${queryString}`;
  try {
    return await gcsFetch(url, accessToken);
  } finally {
    accessToken = "";
  }
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

export async function proxyGCPAction(
  action: string,
  params: unknown,
  keystore: SecretStore
): Promise<ProxyResponse> {
  switch (action) {
    case "storage.getObject":
      return proxyStorageGetObject(params, keystore);
    case "storage.listObjects":
      return proxyStorageListObjects(params, keystore);
    default:
      return { ok: false, error: `Unsupported GCP action: "${action}".` };
  }
}
