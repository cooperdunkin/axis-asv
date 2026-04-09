/**
 * index.ts
 *
 * Public API entry point for axis-asv.
 *
 * Usage:
 *   import { AxisVault } from 'axis-asv';
 *
 *   const vault = new AxisVault({ masterPassword: '...' });
 *   await vault.addCredential('openai', 'sk-...');
 *   const result = await vault.executeAction({ ... });
 *
 * The AxisVault class wraps the internal keystore, policy engine, rate limiter,
 * TTL store, and audit logger into a single safe API. Raw secrets are never
 * exposed to the caller.
 */

import * as fs from "fs";
import * as path from "path";
import { Keystore } from "./vault/keystore.js";
import { PolicyEngine } from "./policy/policy.js";
import { RateLimiter } from "./policy/ratelimit.js";
import { TtlStore } from "./policy/ttlstore.js";
import { AuditLogger } from "./audit/audit.js";
import { proxyRequest } from "./proxy/openai.js";
import { SERVICE_ACTIONS } from "./services.js";

// Re-export proxy response types for consumers
export type { ProxyResponse, ProxyResult, ProxyError } from "./proxy/openai.js";

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface AxisVaultOptions {
  /** Master password for keystore encryption. Required. */
  masterPassword: string;
  /** Path to YAML policy file. Defaults to config/policy.yaml */
  policyPath?: string;
  /** Path to keystore file. Defaults to ~/.axis/keystore.json */
  keystorePath?: string;
  /** Path to audit log. Defaults to ~/.axis/audit.jsonl */
  auditLogPath?: string;
  /** Agent identity string. Defaults to "sdk" */
  identity?: string;
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

export interface ExecuteActionSuccess {
  ok: true;
  result: unknown;
  requestId: string;
}

export interface ExecuteActionError {
  ok: false;
  error: string;
  requestId: string;
}

export type ExecuteActionResponse = ExecuteActionSuccess | ExecuteActionError;

// ---------------------------------------------------------------------------
// AxisVault
// ---------------------------------------------------------------------------

const MAX_PAYLOAD_BYTES = 1_048_576;

export class AxisVault {
  private readonly keystore: Keystore;
  private readonly policy: PolicyEngine;
  private readonly rateLimiter: RateLimiter;
  private readonly ttlStore: TtlStore;
  private readonly audit: AuditLogger;
  private readonly identity: string;

  constructor(options: AxisVaultOptions) {
    if (!options.masterPassword || options.masterPassword.length === 0) {
      throw new Error("masterPassword is required.");
    }

    // Set keystore path env var before constructing Keystore so it picks it up
    if (options.keystorePath) {
      process.env["AXIS_KEYSTORE_PATH"] = options.keystorePath;
    }

    this.keystore = new Keystore(options.masterPassword);
    this.policy = new PolicyEngine(options.policyPath);
    this.rateLimiter = new RateLimiter();
    this.ttlStore = new TtlStore();
    this.audit = new AuditLogger(options.auditLogPath);
    this.identity = options.identity ?? "sdk";
  }

  /** Store an encrypted credential for a service. */
  async addCredential(service: string, secret: string): Promise<void> {
    this.keystore.setSecret(service, secret);
  }

  /** Remove a stored credential. */
  async revokeCredential(service: string): Promise<void> {
    this.keystore.deleteSecret(service);
  }

  /** List stored services (metadata only — never exposes secrets). */
  listServices(): string[] {
    return this.keystore.listServices().map((s) => s.service);
  }

  /** Check if identity is allowed to perform action (dry run, no proxy call). */
  checkPolicy(
    service: string,
    action: string
  ): { allowed: boolean; ttl?: number } {
    return this.policy.isAllowed(this.identity, service, action);
  }

  /**
   * Execute a proxied action — the core operation.
   * Checks policy, rate limits, proxies the API call, logs everything.
   * Returns the API response. The credential is never exposed to the caller.
   */
  async executeAction(params: {
    service: string;
    action: string;
    justification: string;
    params: Record<string, unknown>;
  }): Promise<ExecuteActionResponse> {
    const { service, action, justification, params: actionParams } = params;
    const requestId = this.audit.newRequestId();
    const startMs = Date.now();

    // Policy check
    const { allowed, ttl } = this.policy.isAllowed(
      this.identity,
      service,
      action
    );
    if (!allowed) {
      const reason = `Policy denied: identity="${this.identity}" service="${service}" action="${action}"`;
      this.audit.logDeny({
        request_id: requestId,
        identity: this.identity,
        service,
        action,
        justification,
        reason,
      });
      return { ok: false, error: reason, requestId };
    }

    // TTL check
    if (ttl !== undefined) {
      const ttlState = this.ttlStore.check(this.identity, service, action);
      if (ttlState.active) {
        const remainingSecs = Math.ceil(ttlState.remainingMs / 1000);
        const reason = `TTL active: try again in ${remainingSecs}s (grant TTL=${ttl}s)`;
        this.audit.logDeny({
          request_id: requestId,
          identity: this.identity,
          service,
          action,
          justification,
          reason,
        });
        return { ok: false, error: reason, requestId };
      }
    }

    // Rate limit check
    const rateLimit = this.policy.getRateLimit(this.identity);
    if (rateLimit !== null && !this.rateLimiter.check(this.identity, rateLimit)) {
      const reason = `Rate limit exceeded for identity "${this.identity}"`;
      this.audit.logDeny({
        request_id: requestId,
        identity: this.identity,
        service,
        action,
        justification,
        reason,
      });
      return { ok: false, error: reason, requestId };
    }

    // Payload size check
    const serialized = JSON.stringify(actionParams);
    if (serialized.length > MAX_PAYLOAD_BYTES) {
      const reason = `Request payload too large (${serialized.length} bytes). Maximum is ${MAX_PAYLOAD_BYTES} bytes (1MB).`;
      this.audit.logDeny({
        request_id: requestId,
        identity: this.identity,
        service,
        action,
        justification,
        reason,
      });
      return { ok: false, error: reason, requestId };
    }

    // Proxy call
    let proxyResult;
    try {
      proxyResult = await proxyRequest(service, action, actionParams, this.keystore);
    } catch (err) {
      const error = `Unexpected proxy error: ${(err as Error).message}`;
      this.audit.logError({
        request_id: requestId,
        identity: this.identity,
        service,
        action,
        justification,
        latency_ms: Date.now() - startMs,
        error,
      });
      return { ok: false, error, requestId };
    }

    const latency = Date.now() - startMs;

    if (!proxyResult.ok) {
      this.audit.logError({
        request_id: requestId,
        identity: this.identity,
        service,
        action,
        justification,
        latency_ms: latency,
        error: proxyResult.error,
      });
      return { ok: false, error: proxyResult.error, requestId };
    }

    // Record TTL grant after successful call
    if (ttl !== undefined) {
      this.ttlStore.grant(this.identity, service, action, ttl);
    }

    // Success
    this.audit.logAllow({
      request_id: requestId,
      identity: this.identity,
      service,
      action,
      justification,
      latency_ms: latency,
    });
    return { ok: true, result: proxyResult.data, requestId };
  }

  /** Read audit log entries with optional filters. */
  getAuditLog(
    filters?: {
      service?: string;
      decision?: "allow" | "deny" | "error";
      limit?: number;
    }
  ): Array<Record<string, unknown>> {
    const logPath = this.audit.getPath();
    if (!fs.existsSync(logPath)) {
      return [];
    }

    const raw = fs.readFileSync(logPath, "utf-8");
    const lines = raw.trim().split("\n").filter((l) => l.length > 0);
    let entries: Array<Record<string, unknown>> = lines.map((line) =>
      JSON.parse(line) as Record<string, unknown>
    );

    if (filters?.service) {
      entries = entries.filter((e) => e.service === filters.service);
    }
    if (filters?.decision) {
      entries = entries.filter((e) => e.decision === filters.decision);
    }
    if (filters?.limit !== undefined && filters.limit > 0) {
      entries = entries.slice(-filters.limit);
    }

    return entries;
  }

  /** List available actions for a service. Returns null if service is unknown. */
  listActions(service: string): string[] | null {
    return SERVICE_ACTIONS[service.toLowerCase()] ?? null;
  }
}

export default AxisVault;
