/**
 * policy/ratelimit.ts
 *
 * Simple in-memory token-bucket rate limiter with a sliding fixed window.
 * Tracks per-identity request counts within a configurable time window.
 */

interface WindowRecord {
  count: number;
  windowStart: number;
}

export class RateLimiter {
  private readonly windows = new Map<string, WindowRecord>();
  private readonly windowMs: number;

  /**
   * @param windowMs - Window size in milliseconds. Default 60 000 (1 minute).
   *                   Pass a smaller value in tests to make windows expire quickly.
   */
  constructor(windowMs = 60_000) {
    this.windowMs = windowMs;
  }

  /**
   * Check whether an identity is within its rate limit.
   *
   * @param identity      - The identity string to track.
   * @param limitPerMinute - Maximum allowed requests within the window.
   * @returns true if the request is allowed, false if rate-limited.
   */
  /** Remove expired window records to prevent unbounded Map growth. */
  cleanup(): void {
    const now = Date.now();
    for (const [key, record] of this.windows.entries()) {
      if (now - record.windowStart > this.windowMs * 2) {
        this.windows.delete(key);
      }
    }
  }

  check(identity: string, limitPerMinute: number): boolean {
    if (limitPerMinute <= 0) return true; // No valid limit = allow (fail-open for misconfigured rate limits)
    if (this.windows.size > 1000) this.cleanup();
    const now = Date.now();
    const record = this.windows.get(identity);

    if (!record || now - record.windowStart >= this.windowMs) {
      // Start a fresh window
      this.windows.set(identity, { count: 1, windowStart: now });
      return true;
    }

    if (record.count >= limitPerMinute) {
      return false;
    }

    record.count++;
    return true;
  }
}
