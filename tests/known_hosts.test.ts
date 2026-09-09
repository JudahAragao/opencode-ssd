import { describe, expect, test } from "bun:test"
import { createHash } from "crypto"
import { mkdtempSync, writeFileSync } from "fs"
import { join } from "path"
import { tmpdir } from "os"
import { verifyHostKey, loadKnownHosts, normalizeHostName } from "../src/ssh/known_hosts.js"

// Synthetic key blobs (arbitrary bytes; only equality matters here).
const keyA = Buffer.from("ssh-rsa-test-key-a")
const keyB = Buffer.from("ssh-rsa-test-key-b")

function hostKeyB64(raw: Buffer): string {
  return raw.toString("base64")
}

function tmpKnownHosts(content: string): string {
  const dir = mkdtempSync(join(tmpdir(), "kh-"))
  const file = join(dir, "known_hosts")
  writeFileSync(file, content)
  return file
}

function loadKnownHostsFrom(content: string) {
  return loadKnownHosts(tmpKnownHosts(content))
}

describe("known_hosts", () => {
  test("parseKnownHosts skips comments and blank lines", () => {
    const entries = loadKnownHostsFrom(
      ["# comment line", "", "", `example.com ssh-rsa ${hostKeyB64(keyA)} comment here`].join("\n"),
    )
    expect(entries).toHaveLength(1)
    expect(entries[0].original).toBe("example.com")
    expect(entries[0].hashed).toBe(false)
  })

  test("verify 'ok' when key matches", () => {
    const file = tmpKnownHosts(`example.com ssh-rsa ${hostKeyB64(keyA)}`)
    expect(verifyHostKey("example.com", keyA, file)).toBe("ok")
  })

  test("verify 'changed' when a different key is stored", () => {
    const file = tmpKnownHosts(`example.com ssh-rsa ${hostKeyB64(keyA)}`)
    expect(verifyHostKey("example.com", keyB, file)).toBe("changed")
  })

  test("verify 'unknown' when host not present", () => {
    const file = tmpKnownHosts(`example.com ssh-rsa ${hostKeyB64(keyA)}`)
    expect(verifyHostKey("other.com", keyA, file)).toBe("unknown")
  })

  test("verify 'unknown' when no known_hosts file exists", () => {
    expect(verifyHostKey("example.com", keyA, "/nonexistent/known_hosts")).toBe("unknown")
  })

  test("verify 'unknown' on null/empty key", () => {
    expect(verifyHostKey("example.com", Buffer.alloc(0), undefined)).toBe("unknown")
  })

  test("matches [host]:port bracket form only for the matching port", () => {
    const file = tmpKnownHosts(`[example.com]:2200 ssh-rsa ${hostKeyB64(keyA)}`)
    expect(verifyHostKey("example.com", keyA, file, 2200)).toBe("ok")
    // Plain hostname lookup defaults to port 22, which must NOT match port 2200.
    expect(verifyHostKey("example.com", keyA, file)).toBe("unknown")
  })

  test("matches wildcard patterns", () => {
    const file = tmpKnownHosts(`*.example.com ssh-rsa ${hostKeyB64(keyA)}`)
    expect(verifyHostKey("api.example.com", keyA, file)).toBe("ok")
    expect(verifyHostKey("other.org", keyA, file)).toBe("unknown")
  })

  test("matches comma-separated host lists", () => {
    const file = tmpKnownHosts(`server1,server2 ssh-rsa ${hostKeyB64(keyA)}`)
    expect(verifyHostKey("server2", keyA, file)).toBe("ok")
  })

  test("hashed host entry matches (SHA1(salt || host), case-insensitive)", () => {
    const salt = Buffer.from("0123456789abcdef")
    const digest = createHash("sha1").update(salt).update("example.com", "utf8").digest()
    const file = tmpKnownHosts(
      `|1|${salt.toString("base64")}|${digest.toString("base64")} ssh-rsa ${hostKeyB64(keyA)}`,
    )
    expect(verifyHostKey("example.com", keyA, file)).toBe("ok")
    expect(verifyHostKey("EXAMPLE.COM", keyA, file)).toBe("ok")
    expect(verifyHostKey("evilsite.net", keyA, file)).toBe("unknown")
  })

  test("ignores @-marked marker lines (revoked/cert-authority)", () => {
    const file = tmpKnownHosts(
      [`@revoked example.com ssh-rsa ${hostKeyB64(keyB)}`, `example.com ssh-rsa ${hostKeyB64(keyA)}`].join("\n"),
    )
    expect(verifyHostKey("example.com", keyA, file)).toBe("ok")
  })

  test("normalizeHostName strips [brackets] and default ports", () => {
    expect(normalizeHostName("[example.com]", 22)).toBe("example.com")
    expect(normalizeHostName("example.com:2222", 2222)).toBe("example.com")
    expect(normalizeHostName("example.com", 22)).toBe("example.com")
  })
})