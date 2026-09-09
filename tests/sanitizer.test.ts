import { describe, test, expect } from "bun:test"
import {
  sanitizeCommand,
  sanitizeHost,
  sanitizeUsername,
  sanitizePath,
  escapeShellArg,
} from "../src/ssh/sanitizer.js"

describe("Command Sanitizer", () => {
  test("accepts normal commands", () => {
    expect(sanitizeCommand("ls -la").clean).toBe(true)
    expect(sanitizeCommand("cat /etc/hostname").clean).toBe(true)
    expect(sanitizeCommand("docker ps").clean).toBe(true)
  })

  test("rejects null bytes", () => {
    expect(sanitizeCommand("ls\x00 malicious").clean).toBe(false)
  })

  test("rejects ANSI escape sequences", () => {
    expect(sanitizeCommand("ls\x1b[31m").clean).toBe(false)
  })

  test("rejects Unicode direction overrides", () => {
    expect(sanitizeCommand("ls\u202amalicious").clean).toBe(false)
    expect(sanitizeCommand("ls\u202bmalicious").clean).toBe(false)
    expect(sanitizeCommand("ls\u202c").clean).toBe(false)
    expect(sanitizeCommand("ls\u202d").clean).toBe(false)
    expect(sanitizeCommand("ls\u202e").clean).toBe(false)
  })

  test("rejects commands exceeding max length", () => {
    const longCommand = "a".repeat(10001)
    expect(sanitizeCommand(longCommand).clean).toBe(false)
  })

  test("accepts commands near max length", () => {
    const normalCommand = "a".repeat(9999)
    expect(sanitizeCommand(normalCommand).clean).toBe(true)
  })
})

describe("Host Sanitizer", () => {
  test("accepts valid hostnames", () => {
    expect(sanitizeHost("192.168.1.1").clean).toBe(true)
    expect(sanitizeHost("example.com").clean).toBe(true)
    expect(sanitizeHost("my-server.local").clean).toBe(true)
    expect(sanitizeHost("2001:db8::1").clean).toBe(true)
    expect(sanitizeHost("[::1]").clean).toBe(true)
  })

  test("rejects empty hostnames", () => {
    expect(sanitizeHost("").clean).toBe(false)
  })

  test("rejects hostnames with special characters", () => {
    expect(sanitizeHost("host;rm -rf /").clean).toBe(false)
    expect(sanitizeHost("host| malicious").clean).toBe(false)
    expect(sanitizeHost("host& background").clean).toBe(false)
  })

  test("rejects overly long hostnames", () => {
    const longHost = "a".repeat(254)
    expect(sanitizeHost(longHost).clean).toBe(false)
  })
})

describe("Username Sanitizer", () => {
  test("accepts valid usernames", () => {
    expect(sanitizeUsername("root").clean).toBe(true)
    expect(sanitizeUsername("admin").clean).toBe(true)
    expect(sanitizeUsername("user-name").clean).toBe(true)
    expect(sanitizeUsername("user_name").clean).toBe(true)
    expect(sanitizeUsername("user.name").clean).toBe(true)
  })

  test("rejects empty usernames", () => {
    expect(sanitizeUsername("").clean).toBe(false)
  })

  test("rejects usernames with special characters", () => {
    expect(sanitizeUsername("user;rm").clean).toBe(false)
    expect(sanitizeUsername("user|cmd").clean).toBe(false)
    expect(sanitizeUsername("user&bg").clean).toBe(false)
  })

  test("rejects overly long usernames", () => {
    const longUser = "a".repeat(33)
    expect(sanitizeUsername(longUser).clean).toBe(false)
  })
})

describe("Path Sanitizer", () => {
  test("accepts valid paths", () => {
    expect(sanitizePath("/home/user/file.txt").clean).toBe(true)
    expect(sanitizePath("./relative/path").clean).toBe(true)
    expect(sanitizePath("../parent/file").clean).toBe(true)
  })

  test("rejects empty paths", () => {
    expect(sanitizePath("").clean).toBe(false)
  })

  test("rejects paths with null bytes", () => {
    expect(sanitizePath("/home\x00/user").clean).toBe(false)
  })

  test("rejects paths with shell metacharacters", () => {
    expect(sanitizePath("/home/`cmd`/file").clean).toBe(false)
    expect(sanitizePath("/home/$(cmd)/file").clean).toBe(false)
    expect(sanitizePath("/home/user$(cmd)/file").clean).toBe(false)
  })
})

describe("escapeShellArg", () => {
  test("escapes simple strings", () => {
    expect(escapeShellArg("hello")).toBe("'hello'")
  })

  test("escapes strings with single quotes", () => {
    expect(escapeShellArg("it's")).toBe("'it'\\''s'")
  })

  test("escapes strings with spaces", () => {
    expect(escapeShellArg("hello world")).toBe("'hello world'")
  })

  test("escapes strings with special characters", () => {
    expect(escapeShellArg("file; rm -rf /")).toBe("'file; rm -rf /'")
  })
})
