#!/usr/bin/env node
/**
 * mcp/server.ts
 *
 * ASV MCP Server — exposes one tool: request_credential
 *
 * Startup requirements (non-interactive, no TTY):
 *   ASV_MASTER_PASSWORD  — required; used to unlock the keystore
 *   ASV_IDENTITY         — optional; defaults to "unknown"
 *   ASV_POLICY_PATH      — optional; defaults to config/policy.yaml relative to cwd
 *
 * The agent calls request_credential with:
 *   { service, action, justification, params }
 *
 * ASV:
 *   1. Checks policy (deny-by-default).
 *   2. If denied: audit-logs + returns { denied: true, reason, request_id }.
 *   3. If allowed: calls proxy → audit-logs → returns { ok: true, result, request_id }.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { Keystore } from "../vault/keystore.js";
import { PolicyEngine } from "../policy/policy.js";
import { AuditLogger } from "../audit/audit.js";
import { proxyRequest } from "../proxy/openai.js";

// ---------------------------------------------------------------------------
// Environment validation
// ---------------------------------------------------------------------------

function getRequiredEnv(name: string): string {
  const val = process.env[name];
  if (!val || val.trim().length === 0) {
    process.stderr.write(
      `Error: ${name} env var required for non-interactive MCP server start.\n` +
        `Set it in your MCP host configuration (e.g. Cursor or Claude Code mcpServers env).\n`
    );
    process.exit(1);
  }
  return val;
}

// ---------------------------------------------------------------------------
// Tool schema
// ---------------------------------------------------------------------------

const REQUEST_CREDENTIAL_TOOL = {
  name: "request_credential",
  description:
    "Ask ASV to call an external service on your behalf using a stored credential. " +
    "You provide the service name, action, justification, and request parameters. " +
    "ASV checks policy, proxies the call, and returns the API response. " +
    "You never receive the raw credential.",
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
  // Fail fast if env vars are missing
  const masterPassword = getRequiredEnv("ASV_MASTER_PASSWORD");
  const identity = process.env["ASV_IDENTITY"] ?? "unknown";
  const policyPath = process.env["ASV_POLICY_PATH"] ?? undefined;

  // Initialise shared services
  const keystore = new Keystore(masterPassword);
  const policy = new PolicyEngine(policyPath);
  const audit = new AuditLogger();

  // Verify master password early (fail fast on wrong password)
  if (!keystore.verifyPassword()) {
    process.stderr.write(
      "Error: ASV_MASTER_PASSWORD is incorrect — could not decrypt keystore.\n"
    );
    process.exit(1);
  }

  // Create MCP server
  const server = new Server(
    { name: "agent-secrets-vault", version: "0.1.0" },
    { capabilities: { tools: {} } }
  );

  // ---------------------------------------------------------------------------
  // List tools handler
  // ---------------------------------------------------------------------------
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [REQUEST_CREDENTIAL_TOOL],
  }));

  // ---------------------------------------------------------------------------
  // Call tool handler
  // ---------------------------------------------------------------------------
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    if (name !== "request_credential") {
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
    const allowed = policy.isAllowed(identity, service, action);

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
    `[ASV] MCP server started — identity="${identity}" policy="${policy.getPath()}"\n`
  );
}

main().catch((err) => {
  process.stderr.write(`[ASV] Fatal error: ${(err as Error).message}\n`);
  process.exit(1);
});
