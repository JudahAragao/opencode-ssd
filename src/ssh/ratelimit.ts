/**
 * Per-host rate limiting for command execution.
 * Guards against runaway loops hammering the same remote server.
 */

interface HostWindow {
  count: number
  windowStart: number
  lastRun: number
}

export interface RateLimiterOptions {
  /** Maximum commands allowed per host per minute. */
  maxPerMinute: number
  /** Minimum number of seconds between two commands on the same host. */
  cooldownSeconds: number
  /** Clock for deterministic tests (defaults to Date.now). */
  now?: () => number
}

export interface RateLimitResult {
  allowed: boolean
  reason?: string
  retryAfterSeconds?: number
}

export class RateLimiter {
  private windows = new Map<string, HostWindow>()
  private readonly maxPerMinute: number
  private readonly cooldownSeconds: number
  private readonly nowFn: () => number

  constructor(options: RateLimiterOptions) {
    this.maxPerMinute = options.maxPerMinute
    this.cooldownSeconds = options.cooldownSeconds
    this.nowFn = options.now ?? Date.now
  }

  private now(): number {
    return this.nowFn()
  }

  /** Check whether a command for `host` may run right now, without consuming the token. */
  check(host: string): RateLimitResult {
    const now = this.now()
    const window = this.windows.get(host)

    if (this.cooldownSeconds > 0 && window) {
      const elapsed = (now - window.lastRun) / 1000
      if (elapsed < this.cooldownSeconds) {
        const wait = Math.ceil(this.cooldownSeconds - elapsed)
        return { allowed: false, reason: `Cooldown active for host "${host}"`, retryAfterSeconds: wait }
      }
    }

    if (!window) return { allowed: true }

    const windowMs = 60_000
    const elapsed = (now - window.windowStart) / 1000

    if (elapsed >= 60) {
      return { allowed: true }
    }

    if (window.count >= this.maxPerMinute) {
      const wait = Math.max(1, Math.ceil(60 - elapsed))
      return { allowed: false, reason: `Rate limit exceeded for host "${host}"`, retryAfterSeconds: wait }
    }

    return { allowed: true }
  }

  /** Record that a command for `host` was executed (consumes capacity). */
  record(host: string, executed: boolean): void {
    const now = this.now()
    let window = this.windows.get(host)

    if (!window) {
      window = { count: 0, windowStart: now, lastRun: now }
      this.windows.set(host, window)
    }

    if (now - window.windowStart >= 60_000) {
      window.count = 0
      window.windowStart = now
    }

    if (executed) window.count++
    window.lastRun = now
  }

  /** Reset all windows (useful for tests / session cleanup). */
  reset(): void {
    this.windows.clear()
  }
}