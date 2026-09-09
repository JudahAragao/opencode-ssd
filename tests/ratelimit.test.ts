import { describe, expect, test } from "bun:test"
import { RateLimiter } from "../src/ssh/ratelimit.js"

describe("RateLimiter", () => {
  test("allows the first command on a fresh host", () => {
    const rl = new RateLimiter({ maxPerMinute: 2, cooldownSeconds: 0, now: () => 0 })
    expect(rl.check("host1")).toEqual({ allowed: true })
  })

  test("enforces max commands per minute", () => {
    let t = 0
    const rl = new RateLimiter({ maxPerMinute: 2, cooldownSeconds: 0, now: () => t })

    rl.record("host1", true)
    rl.record("host1", true)
    const third = rl.check("host1")
    expect(third.allowed).toBe(false)
    expect(third.reason).toContain("Rate limit")
    expect(third.retryAfterSeconds).toBeGreaterThan(0)
  })

  test("does not consume capacity when check fails", () => {
    let t = 0
    const rl = new RateLimiter({ maxPerMinute: 1, cooldownSeconds: 0, now: () => t })
    rl.record("h", true)
    expect(rl.check("h").allowed).toBe(false)
    // After the window expires the capacity resets.
    t += 61_000
    expect(rl.check("h").allowed).toBe(true)
  })

  test("resets the window after 60 seconds", () => {
    let t = 0
    const rl = new RateLimiter({ maxPerMinute: 1, cooldownSeconds: 0, now: () => t })
    rl.record("h", true)
    expect(rl.check("h").allowed).toBe(false)
    t += 60_001
    expect(rl.check("h").allowed).toBe(true)
  })

  test("cooldown blocks subsequent commands regardless of rate", () => {
    let t = 0
    const rl = new RateLimiter({ maxPerMinute: 100, cooldownSeconds: 30, now: () => t })
    rl.record("h", true)
    const res = rl.check("h")
    expect(res.allowed).toBe(false)
    expect(res.retryAfterSeconds).toBe(30)
    t += 31_000
    expect(rl.check("h").allowed).toBe(true)
  })

  test("hosts are tracked independently", () => {
    let t = 0
    const rl = new RateLimiter({ maxPerMinute: 1, cooldownSeconds: 0, now: () => t })
    rl.record("a", true)
    expect(rl.check("a").allowed).toBe(false)
    expect(rl.check("b").allowed).toBe(true)
  })

  test("reset clears all windows", () => {
    let t = 0
    const rl = new RateLimiter({ maxPerMinute: 1, cooldownSeconds: 0, now: () => t })
    rl.record("h", true)
    rl.reset()
    expect(rl.check("h").allowed).toBe(true)
  })
})