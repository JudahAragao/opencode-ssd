/**
 * known_hosts support — verifies the remote server's host key against
 * ~/.ssh/known_hosts so connections cannot be silently redirected (MITM).
 */
import { readFileSync, existsSync } from "fs"
import { createHash } from "crypto"
import { resolve as pathResolve } from "path"

export type HostKeyVerdict = "ok" | "changed" | "unknown"

const DEFAULT_KNOWN_HOSTS = () => pathResolve(process.env.HOME || "", ".ssh", "known_hosts")

interface KnownHostEntry {
  /** Unix shell-style pattern for the host (may contain * / ? and be comma separated). */
  original: string
  /** Base64-encoded SSH public key blob (matches what ssh2 passes to hostVerifier). */
  key: Buffer
  /** True if the hostname portion is stored hashed (`|1|...|`). */
  hashed: boolean
}

function parseKnownHosts(content: string): KnownHostEntry[] {
  const entries: KnownHostEntry[] = []

  for (const rawLine of content.split("\n")) {
    const line = rawLine.trim()
    if (!line || line.startsWith("#")) continue

    // Fields: marker? hostpart(s) keytype base64key [comment...]
    const parts = line.split(/\s+/)
    if (parts.length < 3) continue

    // Skip optional "marker" (@cert-authority, @revoked)
    let idx = 0
    if (parts[0].startsWith("@")) idx = 1

    const hostPart = parts[idx]
    const keyPart = parts[idx + 2] // parts[idx+1] is the key type
    if (!keyPart) continue

    let key: Buffer
    try {
      key = Buffer.from(keyPart, "base64")
    } catch {
      continue
    }
    if (!key || key.length === 0) continue

    const hashed = hostPart.startsWith("|")
    entries.push({ original: hostPart, key, hashed })
  }

  return entries
}

/** Strip `[host]:port` brackets and the default-22 port suffix for comparisons. */
export function normalizeHostName(host: string, port?: number): string {
  let h = host
  const bracket = h.match(/^\[(.+)\]/)
  if (bracket) {
    h = bracket[1]
    return h
  }
  // `hostname,hostname2` handled at compare time; here just strip port if present
  const withPort = h.match(/^(.+):(\d+)$/)
  if (withPort) {
    const p = Number(withPort[2])
    if (port === undefined || p === port) h = withPort[1]
  }
  return h
}

/**
 * Normalize a known_hosts pattern into a bare host string, extracting the
 * host portion out of `[host]:port` / `host:port` forms when the stored port
 * matches the requested one.
 */
function normalizePatternHost(pattern: string, port?: number): string {
  let p = pattern
  const bracket = p.match(/^\[(.+)\](?::(\d+))?$/)
  if (bracket) {
    const pPort = bracket[2] ? Number(bracket[2]) : undefined
    if (port !== undefined && pPort !== undefined && pPort !== port) return ""
    return bracket[1]
  }
  const withPort = p.match(/^(.+):(\d+)$/)
  if (withPort) {
    const pPort = Number(withPort[2])
    if (port !== undefined && pPort !== port) return ""
    return withPort[1]
  }
  return p
}

function hostPatternMatches(pattern: string, host: string, port?: number): boolean {
  // known_hosts supports `|1|base64salt|base64hash`
  if (pattern.startsWith("|")) {
    const parts = pattern.split("|")
    if (parts.length !== 4) return false
    const [, magic, saltB64, hashB64] = parts
    if (magic !== "1") return false
    try {
      const salt = Buffer.from(saltB64, "base64")
      const expected = Buffer.from(hashB64, "base64")
      // OpenSSH stores SHA1(salt || lowercased-host)
      const digest = createHash("sha1").update(salt).update(host.toLowerCase(), "utf8").digest()
      return digest.equals(expected)
    } catch {
      return false
    }
  }

  // `[host]:port`, `host:port` and comma-separated lists of patterns.
  const target = host.toLowerCase()
  for (const raw of pattern.split(",")) {
    const part = normalizePatternHost(raw.trim(), port)
    if (!part) continue
    const p = part.toLowerCase()
    if (p === target) return true
    if (!p.includes("*") && !p.includes("?")) continue
    let re = ""
    for (const ch of p) {
      if (ch === "*") re += ".*"
      else if (ch === "?") re += "."
      else re += ch.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
    }
    try {
      if (new RegExp(`^${re}$`).test(target)) return true
    } catch {
      /* ignore invalid patterns */
    }
  }

  return false
}

function entriesForHost(entries: KnownHostEntry[], host: string, port?: number): KnownHostEntry[] {
  const normalized = normalizeHostName(host, port)
  return entries.filter((e) => hostPatternMatches(e.original, normalized, port))
}

/** Load and parse a known_hosts file (defaults to ~/.ssh/known_hosts). */
export function loadKnownHosts(configuredPath?: string): KnownHostEntry[] {
  const path = configuredPath || DEFAULT_KNOWN_HOSTS()
  if (!existsSync(path)) return []
  return parseKnownHosts(readFileSync(path, "utf-8"))
}

/**
 * Verify a server host key against known_hosts.
 *
 * @param host              hostname/IP the user asked to connect to
 * @param serverKey         raw server public key blob (as delivered to ssh2 hostVerifier)
 * @param configuredPath    optional path to a custom known_hosts file
 * @returns "ok" when a matching, identical key exists; "changed" when a matching
 *          entry holds a different key; "unknown" when no entry matches the host.
 */
export function verifyHostKey(
  host: string,
  serverKey: Buffer,
  configuredPath?: string,
  port?: number,
): HostKeyVerdict {
  if (!serverKey || serverKey.length === 0) return "unknown"

  const entries = entriesForHost(loadKnownHosts(configuredPath), host, port ?? 22)

  if (entries.length === 0) return "unknown"

  const match = entries.some((e) => e.key.equals(serverKey))
  return match ? "ok" : "changed"
}