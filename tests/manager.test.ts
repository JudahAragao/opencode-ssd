import { describe, test, expect } from "bun:test"
import { SshSessionManager } from "../src/ssh/manager.js"

describe("SshSessionManager", () => {
  test("creates manager with default options", () => {
    const manager = new SshSessionManager()
    expect(manager.sessionCount).toBe(0)
  })

  test("creates manager with custom max sessions", () => {
    const manager = new SshSessionManager({ maxSessions: 10 })
    expect(manager.sessionCount).toBe(0)
  })

  test("listSessions returns empty array when no sessions", () => {
    const manager = new SshSessionManager()
    const sessions = manager.listSessions()
    expect(sessions.length).toBe(0)
  })

  test("hasSession returns false for non-existent session", () => {
    const manager = new SshSessionManager()
    expect(manager.hasSession("nonexistent")).toBe(false)
  })

  test("getSession returns undefined for non-existent session", () => {
    const manager = new SshSessionManager()
    expect(manager.getSession("nonexistent")).toBeUndefined()
  })

  test("closeSession returns false for non-existent session", async () => {
    const manager = new SshSessionManager()
    const result = await manager.closeSession("nonexistent")
    expect(result).toBe(false)
  })

  // Note: Tests that actually connect to SSH servers are integration tests
  // and require a real SSH server. These unit tests verify the manager logic
  // without network calls.
})
