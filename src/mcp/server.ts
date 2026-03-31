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
import { CloudClient, CloudKeystore } from "../cloud/client.js";
import type { AuditEntry } from "../audit/audit.js";

// ---------------------------------------------------------------------------
// Cloud audit log sync (fire-and-forget)
// ---------------------------------------------------------------------------

/**
 * Post an audit entry to the cloud API if a session exists.
 * Never throws — cloud audit failure must not interrupt the request flow.
 */
function postCloudAuditLog(entry: AuditEntry): void {
  const session = CloudClient.getSession();
  if (!session) return;

  const url = "https://axis-webhook.vercel.app/api/audit-logs";
  fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${session.accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(entry),
  }).catch(() => {
    // Silently ignore — local log is the source of truth
  });
}

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

// ---------------------------------------------------------------------------
// Server bootstrap
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  // Resolve master password: env var takes priority, then OS keychain
  const [masterPassword, passwordSource] = await resolveMasterPassword();
  const identity = process.env["AXIS_IDENTITY"] ?? "unknown";
  const policyPath = process.env["AXIS_POLICY_PATH"] ?? undefined;

  // Determine credential source: cloud (if logged in) or local keystore
  let keystore: SecretStore;
  const cloudSession = CloudClient.getSession();

  if (cloudSession) {
    process.stderr.write("[Axis] Cloud session found — loading credentials from Axis Cloud...\n");
    try {
      keystore = await CloudKeystore.build(masterPassword);
      process.stderr.write("[Axis] Cloud credentials loaded and decrypted.\n");
    } catch (err) {
      process.stderr.write(
        `[Axis] Failed to load cloud credentials: ${(err as Error).message}\n` +
        "[Axis] Falling back to local keystore.\n"
      );
      const localKs = new Keystore(masterPassword);
      if (!localKs.verifyPassword()) {
        process.stderr.write("Error: AXIS_MASTER_PASSWORD is incorrect.\n");
        process.exit(1);
      }
      keystore = localKs;
    }
  } else {
    const localKs = new Keystore(masterPassword);
    if (!localKs.verifyPassword()) {
      process.stderr.write(
        "Error: AXIS_MASTER_PASSWORD is incorrect — could not decrypt keystore.\n"
      );
      process.exit(1);
    }
    keystore = localKs;
  }

  // Initialise shared services
  const policy = new PolicyEngine(policyPath);
  const audit = new AuditLogger();
  const rateLimiter = new RateLimiter();

  // Patch audit logger to also post entries to cloud (fire-and-forget)
  const _localLog = audit.log.bind(audit);
  audit.log = (entry: AuditEntry) => {
    _localLog(entry);
    postCloudAuditLog(entry);
  };
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
    { name: "axis", version: "0.1.0" },
    { capabilities: { tools: {} } }
  );

  // ---------------------------------------------------------------------------
  // List tools handler
  // ---------------------------------------------------------------------------
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [EXECUTE_ACTION_TOOL],
  }));

  // ---------------------------------------------------------------------------
  // Call tool handler
  // ---------------------------------------------------------------------------
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

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

    // Parse and validate inputs
    const toolArgs = args as Record<string, unknown>;
    const service = toolArgs["service"] as string | undefined;
    const action = toolArgs["action"] as string | undefined;
    const justification = toolArgs["justification"] as string | undefined;
    const params = toolArgs["params"] as Record<string, unknown> | undefined;

    if (!service || !action || !justification || params === undefined) {
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              error: "Missing required fields: service, action, justification, params",
            }),
          },
        ],
        isError: true,
      };
    }

    const requestId = audit.newRequestId();
    const startMs = Date.now();

    // ---------------------------------------------------------------------------
    // Policy check
    // ---------------------------------------------------------------------------
    const { allowed, ttl } = policy.isAllowed(identity, service, action);

    if (!allowed) {
      const reason = `Policy denied: identity="${identity}" service="${service}" action="${action}"`;
      audit.logDeny({
        request_id: requestId,
        identity,
        service,
        action,
        justification,
        reason,
      });

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              denied: true,
              reason,
              request_id: requestId,
            }),
          },
        ],
      };
    }

    // ---------------------------------------------------------------------------
    // TTL check (short-lived grant enforcement)
    // ---------------------------------------------------------------------------
    if (ttl !== undefined) {
      const ttlState = ttlStore.check(identity, service, action);
      if (ttlState.active) {
        const remainingSecs = Math.ceil(ttlState.remainingMs / 1000);
        const reason = `TTL active: try again in ${remainingSecs}s (grant TTL=${ttl}s)`;
        audit.logDeny({
          request_id: requestId,
          identity,
          service,
          action,
          justification,
          reason,
        });
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({ denied: true, reason, request_id: requestId }),
            },
          ],
        };
      }
    }

    // ---------------------------------------------------------------------------
    // Rate limit check
    // ---------------------------------------------------------------------------
    const rateLimit = policy.getRateLimit(identity);
    if (rateLimit !== null && !rateLimiter.check(identity, rateLimit)) {
      const reason = `Rate limit exceeded for identity "${identity}"`;
      audit.logDeny({
        request_id: requestId,
        identity,
        service,
        action,
        justification,
        reason,
      });
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ denied: true, reason, request_id: requestId }),
          },
        ],
      };
    }

    // ---------------------------------------------------------------------------
    // Proxy call
    // ---------------------------------------------------------------------------
    let proxyResult;
    try {
      proxyResult = await proxyRequest(service, action, params, keystore);
    } catch (err) {
      const error = `Unexpected proxy error: ${(err as Error).message}`;
      audit.logAllow({
        request_id: requestId,
        identity,
        service,
        action,
        justification,
        latency_ms: Date.now() - startMs,
        error,
      });
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ ok: false, error, request_id: requestId }),
          },
        ],
        isError: true,
      };
    }

    const latency = Date.now() - startMs;

    if (!proxyResult.ok) {
      audit.logAllow({
        request_id: requestId,
        identity,
        service,
        action,
        justification,
        latency_ms: latency,
        error: proxyResult.error,
      });
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              ok: false,
              error: proxyResult.error,
              request_id: requestId,
            }),
          },
        ],
        isError: true,
      };
    }

    // Record TTL grant after successful call
    if (ttl !== undefined) {
      ttlStore.grant(identity, service, action, ttl);
    }

    // Success
    audit.logAllow({
      request_id: requestId,
      identity,
      service,
      action,
      justification,
      latency_ms: latency,
    });

    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify({
            ok: true,
            result: proxyResult.data,
            request_id: requestId,
          }),
        },
      ],
    };
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

main().catch((err) => {
  process.stderr.write(`[Axis] Fatal error: ${(err as Error).message}\n`);
  process.exit(1);
});
