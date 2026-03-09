/**
 * policy/ttlstore.ts
 *
 * In-memory TTL store for per-grant access control.
 *
 * After a credential is granted, subsequent calls for the same
 * (identity, service, action) tuple are denied until the TTL expires.
 *
 * This enforces "one use per TTL window" semantics — preventing an agent
 * from making rapid-fire calls to the same service/action.
 *
 * The store is in-memory and resets on server restart (consistent with
 * the RateLimiter approach).
 */

export class TtlStore {
  /** Map from "identity:service:action" → expiry timestamp (ms) */
  private grants: Map<string, number> = new Map();

  private key(identity: string, service: string, action: string): string {
    return `${identity}:${service}:${action}`;
  }

  /**
   * Check if a grant is currently active (i.e., TTL has not yet expired).
   * Returns { active: false } if no grant or expired.
   * Returns { active: true, remainingMs: number } if still within TTL window.
   */
  check(
    identity: string,
    service: string,
    action: string
  ): { active: false } | { active: true; remainingMs: number } {
    const k = this.key(identity, service, action);
    const expiresAt = this.grants.get(k);
    if (expiresAt === undefined) {
      return { active: false };
    }
    const now = Date.now();
    if (now >= expiresAt) {
      this.grants.delete(k);
      return { active: false };
    }
    return { active: true, remainingMs: expiresAt - now };
  }

  /**
   * Record a new grant for (identity, service, action) with the given TTL in seconds.
   * Overwrites any existing grant.
   */
  grant(identity: string, service: string, action: string, ttlSeconds: number): void {
    const k = this.key(identity, service, action);
    this.grants.set(k, Date.now() + ttlSeconds * 1000);
  }

  /**
   * Manually expire a grant (for testing or administrative use).
   */
  expire(identity: string, service: string, action: string): void {
    const k = this.key(identity, service, action);
    this.grants.delete(k);
  }

  /**
   * Override the expiry time for a grant (for testing with mock clocks).
   */
  setExpiry(identity: string, service: string, action: string, expiresAt: number): void {
    const k = this.key(identity, service, action);
    this.grants.set(k, expiresAt);
  }
}
