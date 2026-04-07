/**
 * audit/audit.ts
 *
 * Append-only JSONL audit logger.
 * Writes to ~/.axis/audit.jsonl — one JSON object per line.
 *
 * Security invariants:
 *   - NEVER log secrets, API keys, or full request bodies.
 *   - Each entry has a UUID v4 request_id for correlation.
 *   - Timestamps are ISO-8601 UTC.
 */

import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { v4 as uuidv4 } from "uuid";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type Decision = "allow" | "deny" | "error";

export interface AuditEntry {
  timestamp: string;
  request_id: string;
  identity: string;
  service: string;
  action: string;
  decision: Decision;
  justification?: string;
  latency_ms: number | null;
  error?: string;
}

// ---------------------------------------------------------------------------
// Path
// ---------------------------------------------------------------------------

export function auditLogPath(): string {
  return path.join(os.homedir(), ".axis", "audit.jsonl");
}

// ---------------------------------------------------------------------------
// Audit Logger
// ---------------------------------------------------------------------------

export class AuditLogger {
  private logPath: string;

  constructor(logPath?: string) {
    this.logPath = logPath ?? auditLogPath();
  }

  /**
   * Generate a new request ID (UUID v4).
   * Call this at the start of each request to get a consistent ID
   * for both the log entry and the response.
   */
  newRequestId(): string {
    return uuidv4();
  }

  /**
   * Log a completed request. Never throws — audit failure should not
   * interrupt the request flow, but we do stderr-warn on failure.
   */
  log(entry: AuditEntry): boolean {
    try {
      fs.mkdirSync(path.dirname(this.logPath), { recursive: true, mode: 0o700 });
      const line = JSON.stringify(entry) + "\n";
      fs.appendFileSync(this.logPath, line, { mode: 0o600 });
      return true;
    } catch (err) {
      // Warn but do not crash the caller
      process.stderr.write(
        `[Axis audit] WARNING: failed to write audit log: ${(err as Error).message}\n`
      );
      return false;
    }
  }

  /**
   * Convenience: log a denied request.
   */
  logDeny(opts: {
    request_id: string;
    identity: string;
    service: string;
    action: string;
    justification?: string;
    reason: string;
  }): void {
    this.log({
      timestamp: new Date().toISOString(),
      request_id: opts.request_id,
      identity: opts.identity,
      service: opts.service,
      action: opts.action,
      decision: "deny",
      justification: opts.justification,
      latency_ms: null,
      error: opts.reason,
    });
  }

  /**
   * Convenience: log an allowed request with timing.
   */
  logAllow(opts: {
    request_id: string;
    identity: string;
    service: string;
    action: string;
    justification?: string;
    latency_ms: number;
    error?: string;
  }): void {
    this.log({
      timestamp: new Date().toISOString(),
      request_id: opts.request_id,
      identity: opts.identity,
      service: opts.service,
      action: opts.action,
      decision: "allow",
      justification: opts.justification,
      latency_ms: opts.latency_ms,
      error: opts.error,
    });
  }

  /**
   * Convenience: log a proxy error (policy allowed, but the API call failed).
   */
  logError(opts: {
    request_id: string;
    identity: string;
    service: string;
    action: string;
    justification?: string;
    latency_ms: number;
    error: string;
  }): void {
    this.log({
      timestamp: new Date().toISOString(),
      request_id: opts.request_id,
      identity: opts.identity,
      service: opts.service,
      action: opts.action,
      decision: "error",
      justification: opts.justification,
      latency_ms: opts.latency_ms,
      error: opts.error,
    });
  }

  getPath(): string {
    return this.logPath;
  }
}
