import { describe, test, expect, beforeEach, afterEach } from "bun:test"
import { mkdirSync, rmSync, existsSync } from "fs"
import { join } from "path"
import { logCommand, readAuditLog, formatAuditLog, getAuditStats } from "../src/ssh/audit.js"

const TEST_DIR = join(import.meta.dir, "../.test-audit")

beforeEach(() => {
  if (!existsSync(TEST_DIR)) {
    mkdirSync(TEST_DIR, { recursive: true })
  }
})

afterEach(() => {
  if (existsSync(TEST_DIR)) {
    rmSync(TEST_DIR, { recursive: true, force: true })
  }
})

describe("Audit Logging", () => {
  test("logCommand creates audit entry", () => {
    logCommand(TEST_DIR, {
      sessionId: "ssh-001",
      command: "ls -la",
      result: "success",
      exitCode: 0,
      duration: 150,
    })

    const entries = readAuditLog(TEST_DIR)
    expect(entries.length).toBe(1)
    expect(entries[0].sessionId).toBe("ssh-001")
    expect(entries[0].command).toBe("ls -la")
    expect(entries[0].result).toBe("success")
    expect(entries[0].exitCode).toBe(0)
    expect(entries[0].duration).toBe(150)
  })

  test("logCommand appends multiple entries", () => {
    logCommand(TEST_DIR, {
      sessionId: "ssh-001",
      command: "ls",
      result: "success",
      exitCode: 0,
      duration: 100,
    })

    logCommand(TEST_DIR, {
      sessionId: "ssh-002",
      command: "rm -rf /",
      result: "blocked",
      exitCode: 1,
      duration: 50,
      reason: "Destructive command",
    })

    const entries = readAuditLog(TEST_DIR)
    expect(entries.length).toBe(2)
  })

  test("readAuditLog returns empty for missing directory", () => {
    const entries = readAuditLog("/nonexistent/path")
    expect(entries.length).toBe(0)
  })

  test("readAuditLog supports limit", () => {
    for (let i = 0; i < 10; i++) {
      logCommand(TEST_DIR, {
        sessionId: "ssh-001",
        command: `cmd-${i}`,
        result: "success",
        exitCode: 0,
        duration: 100,
      })
    }

    const entries = readAuditLog(TEST_DIR, { limit: 5 })
    expect(entries.length).toBe(5)
  })

  test("readAuditLog supports session filter", () => {
    logCommand(TEST_DIR, {
      sessionId: "ssh-001",
      command: "cmd-1",
      result: "success",
      exitCode: 0,
      duration: 100,
    })

    logCommand(TEST_DIR, {
      sessionId: "ssh-002",
      command: "cmd-2",
      result: "success",
      exitCode: 0,
      duration: 100,
    })

    const entries = readAuditLog(TEST_DIR, { sessionId: "ssh-001" })
    expect(entries.length).toBe(1)
    expect(entries[0].sessionId).toBe("ssh-001")
  })

  test("readAuditLog supports command filter", () => {
    logCommand(TEST_DIR, {
      sessionId: "ssh-001",
      command: "docker ps",
      result: "success",
      exitCode: 0,
      duration: 100,
    })

    logCommand(TEST_DIR, {
      sessionId: "ssh-001",
      command: "ls -la",
      result: "success",
      exitCode: 0,
      duration: 100,
    })

    const entries = readAuditLog(TEST_DIR, { commandFilter: "docker" })
    expect(entries.length).toBe(1)
    expect(entries[0].command).toBe("docker ps")
  })

  test("formatAuditLog formats entries correctly", () => {
    logCommand(TEST_DIR, {
      sessionId: "ssh-001",
      command: "ls -la",
      result: "success",
      exitCode: 0,
      duration: 150,
    })

    const entries = readAuditLog(TEST_DIR)
    const formatted = formatAuditLog(entries)
    expect(formatted).toContain("ls -la")
    expect(formatted).toContain("ssh-001")
  })

  test("formatAuditLog returns empty message for no entries", () => {
    const formatted = formatAuditLog([])
    expect(formatted).toContain("No audit entries")
  })

  test("getAuditStats counts correctly", () => {
    logCommand(TEST_DIR, {
      sessionId: "ssh-001",
      command: "ls",
      result: "success",
      exitCode: 0,
      duration: 100,
    })

    logCommand(TEST_DIR, {
      sessionId: "ssh-001",
      command: "rm -rf /",
      result: "blocked",
      exitCode: 1,
      duration: 50,
    })

    logCommand(TEST_DIR, {
      sessionId: "ssh-001",
      command: "sudo su",
      result: "approved",
      exitCode: 0,
      duration: 200,
    })

    const stats = getAuditStats(TEST_DIR)
    expect(stats.total).toBe(3)
    expect(stats.success).toBe(1)
    expect(stats.blocked).toBe(1)
    expect(stats.approved).toBe(1)
    expect(stats.blockedCommands).toContain("rm -rf /")
  })
})
