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

  // `closeSession` is documented to accept "Session ID or alias", and the
  // `ssh.disconnect` tool forwards whatever the caller passes. It used to look
  // up `sessions` by ID only, so closing by alias always reported failure and
  // left the session open.
  describe("closing by alias", () => {
    const seed = (manager: SshSessionManager, id: string, alias?: string) => {
      const connection = { config: { alias }, disconnect: () => {} }
      manager.sessions.set(id, connection as never)
      if (alias) manager.aliases.set(alias.toLowerCase(), id)
    }

    test("removes the session when given its alias", async () => {
      const manager = new SshSessionManager()
      seed(manager, "ssh-abc123", "prod-web")

      expect(manager.sessionCount).toBe(1)
      expect(await manager.closeSession("prod-web")).toBe(true)
      expect(manager.sessionCount).toBe(0)
      expect(manager.getSession("prod-web")).toBeUndefined()
      expect(manager.getSession("ssh-abc123")).toBeUndefined()
    })

    test("matches the alias case-insensitively", async () => {
      const manager = new SshSessionManager()
      seed(manager, "ssh-abc123", "prod-web")

      expect(await manager.closeSession("PROD-WEB")).toBe(true)
      expect(manager.sessionCount).toBe(0)
    })

    test("still resolves a plain session ID", async () => {
      const manager = new SshSessionManager()
      seed(manager, "ssh-abc123", "prod-web")

      expect(await manager.closeSession("ssh-abc123")).toBe(true)
      expect(manager.sessionCount).toBe(0)
      expect(manager.getSession("prod-web")).toBeUndefined()
    })

    test("closes sessions that have no alias", async () => {
      const manager = new SshSessionManager()
      seed(manager, "ssh-nolias")

      expect(await manager.closeSession("ssh-nolias")).toBe(true)
      expect(manager.sessionCount).toBe(0)
    })
  })

  // Note: Tests that actually connect to SSH servers are integration tests
  // and require a real SSH server. These unit tests verify the manager logic
  // without network calls.
})
