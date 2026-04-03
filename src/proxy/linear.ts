/**
 * proxy/linear.ts
 *
 * Linear API proxy.
 * Axis retrieves the stored API key and injects it — the agent never sees it.
 *
 * Supported actions:
 *   service: "linear"
 *   action:  "issues.create"
 *
 * Security invariants:
 *   - The API key is retrieved from the keystore and used only in the
 *     Authorization header; it is never returned to the caller.
 *   - Error messages never include the API key.
 *   - Request body is built from validated + sanitized params only.
 *
 * Note: Linear uses GraphQL. Auth header is "Authorization: <key>" (no "Bearer" prefix).
 */

import { SecretStore } from "../vault/keystore.js";
import { fetchWithTimeout } from "./fetchWithTimeout.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface IssuesCreateParams {
  teamId: string;
  title: string;
  description?: string;
  priority?: number;
  assigneeId?: string;
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

export function validateIssuesCreateParams(params: unknown): IssuesCreateParams {
  const p = requireBaseObject(params);
  requireString(p, "teamId");
  requireString(p, "title");

  if (p["priority"] !== undefined) {
    if (
      typeof p["priority"] !== "number" ||
      !Number.isInteger(p["priority"]) ||
      p["priority"] < 0 ||
      p["priority"] > 4
    ) {
      throw new Error(`Optional param "priority" must be an integer between 0 and 4.`);
    }
  }

  return p as IssuesCreateParams;
}

// ---------------------------------------------------------------------------
// Shared fetch helper
// ---------------------------------------------------------------------------

const LINEAR_API_URL = "https://api.linear.app/graphql";

async function linearFetch(
  apiKey: string,
  query: string,
  variables: Record<string, unknown>
): Promise<ProxyResponse> {
  let response: Response;
  try {
    response = await fetchWithTimeout(LINEAR_API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        // Linear uses "Authorization: <key>" (no "Bearer" prefix)
        Authorization: apiKey,
        "User-Agent": "axis/0.1.0",
      },
      body: JSON.stringify({ query, variables }),
    });
  } catch (err: any) {
    if (err?.name === "AbortError") {
      return { ok: false, error: "Request timed out after 30 seconds" };
    }
    const msg = (err as Error).message.replace(apiKey, "[REDACTED]");
    return { ok: false, error: `Network error calling Linear API: ${msg}` };
  }

  let responseData: unknown;
  try {
    responseData = await response.json();
  } catch {
    return {
      ok: false,
      error: `Linear API returned non-JSON response (HTTP ${response.status}).`,
      status: response.status,
    };
  }

  if (!response.ok) {
    return {
      ok: false,
      error: `Linear API error: HTTP ${response.status}`,
      status: response.status,
    };
  }

  // Check for GraphQL errors
  const gqlErrors = (responseData as { errors?: Array<{ message?: string }> })?.errors;
  if (gqlErrors && gqlErrors.length > 0) {
    const errMsg = gqlErrors[0]?.message ?? "Unknown GraphQL error";
    return { ok: false, error: `Linear GraphQL error: ${errMsg}` };
  }

  return { ok: true, data: (responseData as { data?: unknown })?.data ?? responseData };
}

// ---------------------------------------------------------------------------
// Action proxy functions
// ---------------------------------------------------------------------------

async function proxyIssuesCreate(
  params: unknown,
  keystore: SecretStore
): Promise<ProxyResponse> {
  let validated: IssuesCreateParams;
  try {
    validated = validateIssuesCreateParams(params);
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }

  let apiKey: string;
  try {
    apiKey = keystore.getSecret("linear");
  } catch (err) {
    return {
      ok: false,
      error: `Could not retrieve Linear secret from keystore: ${(err as Error).message}`,
    };
  }

  const input: Record<string, unknown> = {
    teamId: validated.teamId,
    title: validated.title,
  };
  if (validated.description !== undefined) input["description"] = validated.description;
  if (validated.priority !== undefined) input["priority"] = validated.priority;
  if (validated.assigneeId !== undefined) input["assigneeId"] = validated.assigneeId;

  const query = `
    mutation IssueCreate($input: IssueCreateInput!) {
      issueCreate(input: $input) {
        success
        issue {
          id
          title
          url
        }
      }
    }
  `;

  const result = await linearFetch(apiKey, query, { input });
  apiKey = "";
  return result;
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

export async function proxyLinearAction(
  action: string,
  params: unknown,
  keystore: SecretStore
): Promise<ProxyResponse> {
  switch (action) {
    case "issues.create":
      return proxyIssuesCreate(params, keystore);
    default:
      return { ok: false, error: `Unsupported Linear action: "${action}".` };
  }
}
