#!/usr/bin/env node
/**
 * mcp/server.ts
 *
 * Axis MCP Server — exposes one tool: execute_action
 *
 * Startup requirements (non-interactive, no TTY):
 *   AXIS_MASTER_PASSWORD  — optional; takes priority over OS keychain if set
 *                          If absent, master password is read from OS keychain.
 *                          Run "axis keychain set" to store it there.
 *   AXIS_IDENTITY         — optional; defaults to "unknown"
 *   AXIS_POLICY_PATH      — optional; defaults to config/policy.yaml relative to cwd
 *
 * The agent calls execute_action with:
 *   { service, action, justification, params }
 *
 * Axis:
 *   1. Checks policy (deny-by-default).
 *   2. If denied: audit-logs + returns { denied: true, reason, request_id }.
 *   3. If allowed: calls proxy → audit-logs → returns { ok: true, result, request_id }.
 */

import * as fs from "fs";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { Keystore, SecretStore } from "../vault/keystore.js";
import { PolicyEngine } from "../policy/policy.js";
import { AuditLogger } from "../audit/audit.js";
import { proxyRequest } from "../proxy/openai.js";
import { keychainGet } from "../keychain/keychain.js";
import { RateLimiter } from "../policy/ratelimit.js";
import { TtlStore } from "../policy/ttlstore.js";
// ---------------------------------------------------------------------------
// Master password resolution
// ---------------------------------------------------------------------------

/**
 * Resolve the master password from (in priority order):
 *   1. AXIS_MASTER_PASSWORD env var (explicit override)
 *   2. OS keychain via keytar (set with: axis keychain set)
 *
 * Exits with a clear error if neither source has the password.
 * Returns [password, source] where source is "env" or "keychain".
 */
async function resolveMasterPassword(): Promise<[string, string]> {
  const envPassword = process.env["AXIS_MASTER_PASSWORD"];
  if (envPassword && envPassword.trim().length > 0) {
    return [envPassword, "env"];
  }

  // Try OS keychain
  let keychainPassword: string | null = null;
  try {
    keychainPassword = await keychainGet();
  } catch {
    // keytar unavailable (e.g. libsecret missing on Linux) — fall through to error
  }

  if (keychainPassword) {
    return [keychainPassword, "keychain"];
  }

  process.stderr.write(
    "Error: No master password found.\n" +
      "Set AXIS_MASTER_PASSWORD env var, or run: axis keychain set\n"
  );
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Tool schema
// ---------------------------------------------------------------------------

const EXECUTE_ACTION_TOOL = {
  name: "execute_action",
  description:
    "Ask Axis to execute an action on an external service on your behalf. " +
    "You provide the service name, action, justification, and request parameters. " +
    "Axis checks policy, executes the action server-side, and returns the result. " +
    "You never receive or handle credentials directly.",
  inputSchema: {
    type: "object" as const,
    properties: {
      service: {
        type: "string",
        description: 'The service to call (e.g. "openai")',
      },
      action: {
        type: "string",
        description: 'The action to perform (e.g. "responses.create")',
      },
      justification: {
        type: "string",
        description: "Why this call is being made (logged for audit purposes)",
      },
      params: {
        type: "object",
        description: "Service-specific request parameters",
        additionalProperties: true,
      },
    },
    required: ["service", "action", "justification", "params"],
  },
};

const LIST_SERVICES_TOOL = {
  name: "list_services",
  description:
    "List services the current identity is allowed to access and whether credentials are stored.",
  inputSchema: {
    type: "object" as const,
    properties: {},
  },
};

const LIST_ACTIONS_TOOL = {
  name: "list_actions",
  description:
    "List available actions for a service and whether the current identity is allowed to use each one.",
  inputSchema: {
    type: "object" as const,
    properties: {
      service: {
        type: "string",
        description: 'The service to query (e.g. "openai")',
      },
    },
    required: ["service"],
  },
};

/** Hardcoded action map per service (mirrors proxy dispatch table). */
const SERVICE_ACTIONS: Record<string, string[]> = {
  openai: ["responses.create"],
  anthropic: ["messages.create"],
  github: ["repos.get", "issues.create", "pulls.create", "contents.read"],
  stripe: ["paymentIntents.create", "customers.list"],
  slack: ["chat.postMessage", "conversations.list"],
  sendgrid: ["mail.send"],
  notion: ["pages.create", "databases.query"],
  linear: ["issues.create"],
  twilio: ["messages.create"],
  aws: ["s3.getObject", "s3.putObject"],
  gcp: ["storage.getObject", "storage.listObjects"],
};

// ---------------------------------------------------------------------------
// Exported handler for testing
// ---------------------------------------------------------------------------

export interface HandlerDeps {
  identity: string;
  policy: PolicyEngine;
  audit: AuditLogger;
  keystore: SecretStore;
  rateLimiter: RateLimiter;
  ttlStore: TtlStore;
}

export interface McpToolResponse {
  [key: string]: unknown;
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
}

export async function handleExecuteAction(
  args: Record<string, unknown>,
  deps: HandlerDeps,
): Promise<McpToolResponse> {
  const { identity, policy, audit, keystore, rateLimiter, ttlStore } = deps;
  const service = args["service"] as string | undefined;
  const action = args["action"] as string | undefined;
  const justification = args["justification"] as string | undefined;
  const params = args["params"] as Record<string, unknown> | undefined;

  if (!service || !action || !justification || params === undefined) {
    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({ error: "Missing required fields: service, action, justification, params" }),
      }],
      isError: true,
    };
  }

  const requestId = audit.newRequestId();
  const startMs = Date.now();

  // Policy check
  const { allowed, ttl } = policy.isAllowed(identity, service, action);
  if (!allowed) {
    const reason = `Policy denied: identity="${identity}" service="${service}" action="${action}"`;
    audit.logDeny({ request_id: requestId, identity, service, action, justification, reason });
    return {
      content: [{ type: "text" as const, text: JSON.stringify({ denied: true, reason, request_id: requestId }) }],
    };
  }

  // TTL check
  if (ttl !== undefined) {
    const ttlState = ttlStore.check(identity, service, action);
    if (ttlState.active) {
      const remainingSecs = Math.ceil(ttlState.remainingMs / 1000);
      const reason = `TTL active: try again in ${remainingSecs}s (grant TTL=${ttl}s)`;
      audit.logDeny({ request_id: requestId, identity, service, action, justification, reason });
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ denied: true, reason, request_id: requestId }) }],
      };
    }
  }

  // Rate limit check
  const rateLimit = policy.getRateLimit(identity);
  if (rateLimit !== null && !rateLimiter.check(identity, rateLimit)) {
    const reason = `Rate limit exceeded for identity "${identity}"`;
    audit.logDeny({ request_id: requestId, identity, service, action, justification, reason });
    return {
      content: [{ type: "text" as const, text: JSON.stringify({ denied: true, reason, request_id: requestId }) }],
    };
  }

  // Payload size check (1MB limit)
  const MAX_PAYLOAD_BYTES = 1_048_576;
  const serialized = JSON.stringify(params);
  if (serialized.length > MAX_PAYLOAD_BYTES) {
    audit.logDeny({
      request_id: requestId, identity, service, action, justification,
      reason: `Payload size ${serialized.length} bytes exceeds limit of ${MAX_PAYLOAD_BYTES} bytes`,
    });
    return {
      content: [{ type: "text" as const, text: JSON.stringify({
        error: `Request payload too large (${serialized.length} bytes). Maximum is ${MAX_PAYLOAD_BYTES} bytes (1MB).`,
        request_id: requestId,
      }) }],
      isError: true,
    };
  }

  // Proxy call
  let proxyResult;
  try {
    proxyResult = await proxyRequest(service, action, params, keystore);
  } catch (err) {
    const error = `Unexpected proxy error: ${(err as Error).message}`;
    audit.logError({ request_id: requestId, identity, service, action, justification, latency_ms: Date.now() - startMs, error });
    return {
      content: [{ type: "text" as const, text: JSON.stringify({ ok: false, error, request_id: requestId }) }],
      isError: true,
    };
  }

  const latency = Date.now() - startMs;

  if (!proxyResult.ok) {
    audit.logError({ request_id: requestId, identity, service, action, justification, latency_ms: latency, error: proxyResult.error });
    return {
      content: [{ type: "text" as const, text: JSON.stringify({ ok: false, error: proxyResult.error, request_id: requestId }) }],
      isError: true,
    };
  }

  // Record TTL grant after successful call
  if (ttl !== undefined) {
    ttlStore.grant(identity, service, action, ttl);
  }

  // Success
  audit.logAllow({ request_id: requestId, identity, service, action, justification, latency_ms: latency });
  return {
    content: [{ type: "text" as const, text: JSON.stringify({ ok: true, result: proxyResult.data, request_id: requestId }) }],
  };
}

// ---------------------------------------------------------------------------
// Server bootstrap
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  // Resolve master password: env var takes priority, then OS keychain
  const [masterPassword, passwordSource] = await resolveMasterPassword();
  const identity = process.env["AXIS_IDENTITY"] ?? "unknown";
  const policyPath = process.env["AXIS_POLICY_PATH"] ?? undefined;

  // Initialize local keystore
  const localKs = new Keystore(masterPassword);
  if (!localKs.verifyPassword()) {
    process.stderr.write(
      "Error: AXIS_MASTER_PASSWORD is incorrect — could not decrypt keystore.\n"
    );
    process.exit(1);
  }
  const keystore: SecretStore = localKs;

  // Initialise shared services
  const policy = new PolicyEngine(policyPath);
  const audit = new AuditLogger();
  const rateLimiter = new RateLimiter();

  const ttlStore = new TtlStore();

  // Watch policy file for changes and hot-reload on edit
  fs.watch(policy.getPath(), { persistent: false }, (eventType) => {
    if (eventType === "change") {
      try {
        policy.reload();
        process.stderr.write(`[Axis] Policy reloaded from ${policy.getPath()}\n`);
      } catch (err) {
        process.stderr.write(
          `[Axis] Policy reload failed: ${(err as Error).message}\n`
        );
      }
    }
  });

  // Create MCP server
  const server = new Server(
    { name: "axis", version: "0.5.0" },
    { capabilities: { tools: {} } }
  );

  // ---------------------------------------------------------------------------
  // List tools handler
  // ---------------------------------------------------------------------------
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [EXECUTE_ACTION_TOOL, LIST_SERVICES_TOOL, LIST_ACTIONS_TOOL],
  }));

  // ---------------------------------------------------------------------------
  // Call tool handler
  // ---------------------------------------------------------------------------
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    // ----- list_services -----
    if (name === "list_services") {
      const policies = policy.getPolicies();
      const serviceMap = new Map<string, string[]>();
      for (const entry of policies) {
        if (entry.identity !== identity && entry.identity !== "*") continue;
        for (const allow of entry.allow) {
          const svc = allow.service;
          const existing = serviceMap.get(svc) ?? [];
          for (const a of allow.actions) {
            if (!existing.includes(a)) existing.push(a);
          }
          serviceMap.set(svc, existing);
        }
      }
      const services = Array.from(serviceMap.entries()).map(([svc, actions]) => {
        let hasCred = false;
        try { keystore.getSecret(svc); hasCred = true; } catch { /* no credential */ }
        return { service: svc, allowed_actions: actions, has_credential: hasCred };
      });
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ services }) }],
      };
    }

    // ----- list_actions -----
    if (name === "list_actions") {
      const toolArgs = args as Record<string, unknown>;
      const svc = toolArgs["service"] as string | undefined;
      if (!svc) {
        return {
          content: [{ type: "text" as const, text: JSON.stringify({ error: "Missing required field: service" }) }],
          isError: true,
        };
      }
      const available = SERVICE_ACTIONS[svc];
      if (!available) {
        return {
          content: [{ type: "text" as const, text: JSON.stringify({ error: `Unknown service: ${svc}` }) }],
          isError: true,
        };
      }
      const result = available.map((action) => ({
        action,
        allowed: policy.isAllowed(identity, svc, action).allowed,
      }));
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ service: svc, available_actions: result }) }],
      };
    }

    // ----- execute_action -----
    if (name !== "execute_action") {
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ error: `Unknown tool: ${name}` }),
          },
        ],
        isError: true,
      };
    }

    return handleExecuteAction(args as Record<string, unknown>, {
      identity, policy, audit, keystore, rateLimiter, ttlStore,
    });
  });

  // ---------------------------------------------------------------------------
  // Connect transport
  // ---------------------------------------------------------------------------
  const transport = new StdioServerTransport();
  await server.connect(transport);

  // Log startup to stderr (not stdout, which is the MCP JSON-RPC channel)
  process.stderr.write(
    `[Axis] MCP server started — identity="${identity}" policy="${policy.getPath()}" password_source=${passwordSource}\n`
  );
}

// Only start the server when run directly (not when imported for testing).
// Check both require.main (CommonJS) and process.argv[1] (covers tsx/esm loaders).
const entryScript = process.argv[1] ?? "";
const isMain =
  require.main === module ||
  entryScript.endsWith("/mcp/server.js") ||
  entryScript.endsWith("/mcp/server.ts");
if (isMain) {
  main().catch((err) => {
    process.stderr.write(`[Axis] Fatal error: ${(err as Error).message}\n`);
    process.exit(1);
  });
}
