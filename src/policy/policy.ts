/**
 * policy/policy.ts
 *
 * YAML-based policy engine with deny-by-default semantics.
 *
 * Policy file format (config/policy.yaml):
 *
 *   policies:
 *     - identity: local-dev
 *       allow:
 *         - service: openai
 *           actions:
 *             - responses.create
 *
 * Resolution order:
 *   1. Exact identity match.
 *   2. Wildcard identity "*".
 *   3. Default: DENY.
 */

import * as fs from "fs";
import * as path from "path";
import * as yaml from "js-yaml";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface PolicyAllow {
  service: string;
  actions: string[];
  ttl?: number;
}

interface RateLimit {
  requestsPerMinute: number;
}

interface PolicyEntry {
  identity: string;
  rateLimit?: RateLimit;
  allow: PolicyAllow[];
}

interface PolicyFile {
  policies: PolicyEntry[];
}

// ---------------------------------------------------------------------------
// Default config path
// ---------------------------------------------------------------------------

export function defaultPolicyPath(): string {
  return path.resolve(process.cwd(), "config", "policy.yaml");
}

// ---------------------------------------------------------------------------
// Policy Engine
// ---------------------------------------------------------------------------

export class PolicyEngine {
  private policies: PolicyEntry[];
  private policyPath: string;

  constructor(policyPath?: string) {
    this.policyPath = policyPath ?? defaultPolicyPath();
    this.policies = this.load();
  }

  private load(): PolicyEntry[] {
    if (!fs.existsSync(this.policyPath)) {
      throw new Error(
        `Policy file not found: ${this.policyPath}\n` +
          `Run "axis init" to create a default policy file.`
      );
    }

    const raw = fs.readFileSync(this.policyPath, "utf-8");
    let parsed: unknown;
    try {
      parsed = yaml.load(raw);
    } catch (err) {
      throw new Error(`Failed to parse policy file: ${(err as Error).message}`);
    }

    if (
      !parsed ||
      typeof parsed !== "object" ||
      !Array.isArray((parsed as PolicyFile).policies)
    ) {
      throw new Error(
        `Policy file is malformed — expected top-level "policies" array.`
      );
    }

    const file = parsed as PolicyFile;

    // Validate structure
    for (const entry of file.policies) {
      if (typeof entry.identity !== "string") {
        throw new Error(`Policy entry missing "identity" field.`);
      }
      // Validate optional rateLimit field
      if (entry.rateLimit !== undefined && entry.rateLimit !== null) {
        const rl = entry.rateLimit as { requestsPerMinute?: unknown };
        if (
          typeof rl.requestsPerMinute !== "number" ||
          rl.requestsPerMinute <= 0
        ) {
          throw new Error(
            `Policy entry "${entry.identity}" has invalid rateLimit.requestsPerMinute — must be a positive number.`
          );
        }
      }
      if (!Array.isArray(entry.allow)) {
        throw new Error(
          `Policy entry for "${entry.identity}" missing "allow" array.`
        );
      }
      for (const allow of entry.allow) {
        if (typeof allow.service !== "string") {
          throw new Error(
            `Allow entry in policy "${entry.identity}" missing "service" field.`
          );
        }
        if (!Array.isArray(allow.actions)) {
          throw new Error(
            `Allow entry for service "${allow.service}" in policy "${entry.identity}" missing "actions" array.`
          );
        }
        if (allow.ttl !== undefined) {
          if (typeof allow.ttl !== "number" || allow.ttl <= 0) {
            throw new Error(
              `Allow entry for service "${allow.service}" in policy "${entry.identity}" has invalid "ttl" — must be a positive number (seconds).`
            );
          }
        }
      }
    }

    return file.policies;
  }

  /**
   * Check whether an identity is allowed to perform an action on a service.
   * Deny-by-default: returns { allowed: false } unless an explicit allow rule matches.
   *
   * Wildcard identity "*" matches any identity.
   * Wildcard action "*" matches any action.
   * Wildcard service "*" matches any service.
   *
   * If allowed and a TTL is configured on the matching rule, it is returned.
   */
  isAllowed(
    identity: string,
    service: string,
    action: string
  ): { allowed: boolean; ttl?: number } {
    const lIdentity = identity.toLowerCase();
    const lService = service.toLowerCase();
    const lAction = action.toLowerCase();

    for (const entry of this.policies) {
      const identityMatches =
        entry.identity === "*" || entry.identity.toLowerCase() === lIdentity;
      if (!identityMatches) continue;

      for (const allow of entry.allow) {
        const serviceMatches = allow.service === "*" || allow.service.toLowerCase() === lService;
        if (!serviceMatches) continue;

        for (const allowedAction of allow.actions) {
          if (allowedAction === "*" || allowedAction.toLowerCase() === lAction) {
            return { allowed: true, ttl: allow.ttl };
          }
        }
      }
    }
    return { allowed: false };
  }

  /** Reload policy from disk (useful for long-running servers). */
  reload(): void {
    this.policies = this.load();
  }

  /** Return path being used. */
  getPath(): string {
    return this.policyPath;
  }

  /** Return a copy of loaded policies (for introspection/doctor). */
  getPolicies(): ReadonlyArray<PolicyEntry> {
    return this.policies;
  }

  /**
   * Add an allow rule for an identity + service.
   * If the identity entry doesn't exist, creates one.
   * If a rule for the service already exists, merges actions.
   * Writes the updated YAML back to disk.
   */
  addAllowRule(identity: string, service: string, actions: string[]): void {
    identity = identity.toLowerCase();
    service = service.toLowerCase();
    const raw = fs.readFileSync(this.policyPath, "utf-8");
    const parsed = yaml.load(raw) as PolicyFile;

    let entry = parsed.policies.find((p) => p.identity === identity);
    if (!entry) {
      entry = { identity, allow: [] };
      parsed.policies.push(entry);
    }

    let rule = entry.allow.find((a) => a.service === service);
    if (rule) {
      // Merge actions — if adding "*", replace all; otherwise add unique
      if (actions.includes("*")) {
        rule.actions = ["*"];
      } else {
        for (const a of actions) {
          if (!rule.actions.includes(a)) rule.actions.push(a);
        }
      }
    } else {
      entry.allow.push({ service, actions });
    }

    const yamlStr = yaml.dump(parsed, { lineWidth: -1 });
    const tmp = this.policyPath + ".tmp";
    fs.writeFileSync(tmp, yamlStr, "utf-8");
    fs.renameSync(tmp, this.policyPath);
    this.policies = this.load();
  }

  /**
   * Remove all allow rules for a service under an identity.
   * Writes the updated YAML back to disk.
   * Returns true if a rule was removed, false if none found.
   */
  removeAllowRule(identity: string, service: string): boolean {
    identity = identity.toLowerCase();
    service = service.toLowerCase();
    const raw = fs.readFileSync(this.policyPath, "utf-8");
    const parsed = yaml.load(raw) as PolicyFile;

    const entry = parsed.policies.find((p) => p.identity === identity);
    if (!entry) return false;

    const before = entry.allow.length;
    entry.allow = entry.allow.filter((a) => a.service !== service);
    if (entry.allow.length === before) return false;

    const yamlStr = yaml.dump(parsed, { lineWidth: -1 });
    const tmp = this.policyPath + ".tmp";
    fs.writeFileSync(tmp, yamlStr, "utf-8");
    fs.renameSync(tmp, this.policyPath);
    this.policies = this.load();
    return true;
  }

  /**
   * Return the rate limit (requests per minute) configured for an identity.
   * Checks exact identity match first, then wildcard "*".
   * Returns null if no rate limit is configured.
   */
  getRateLimit(identity: string): number | null {
    const lIdentity = identity.toLowerCase();
    for (const entry of this.policies) {
      if (entry.identity.toLowerCase() === lIdentity) {
        return entry.rateLimit?.requestsPerMinute ?? null;
      }
    }
    for (const entry of this.policies) {
      if (entry.identity === "*") {
        return entry.rateLimit?.requestsPerMinute ?? null;
      }
    }
    return null;
  }
}
