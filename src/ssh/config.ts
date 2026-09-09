/**
 * SSH config (~/.ssh/config) parser.
 * Reads alias, HostName, User, Port and IdentityFile so ssh.connect
 * can reuse your normal SSH configuration and auto_connect knows what to hook.
 */
import { readFileSync, existsSync } from "fs"
import { resolve as pathResolve } from "path"

export interface SshConfigEntry {
  /** Host patterns from the "Host" line (aliases / globs). */
  patterns: string[]
  /** Real hostname to connect to (HostName). */
  hostName?: string
  /** User (User). */
  user?: string
  /** Port (Port). */
  port?: number
  /** Identity file (IdentityFile). */
  identityFile?: string
}

export interface LoadedSshConfig {
  entries: SshConfigEntry[]
  path: string
}

/** Expand a leading `~` to the current user's home directory. */
export function expandHomePath(p: string): string {
  if (p.startsWith("~/")) {
    return pathResolve(process.env.HOME || "", p.slice(2))
  }
  return p
}

/** Resolve the ssh config file path, using the override or ~/.ssh/config. */
export function resolveSshConfigPath(configuredPath?: string): string {
  if (configuredPath && configuredPath.trim()) {
    const p = configuredPath.trim()
    return p.startsWith("~/") ? expandHomePath(p) : pathResolve(p)
  }
  return pathResolve(process.env.HOME || "", ".ssh", "config")
}

/**
 * Parse the content of an OpenSSH config file.
 * Handles `Host` blocks and `Match` blocks, and captures
 * HostName / User / Port / IdentityFile directives.
 */
export function parseSshConfig(content: string): SshConfigEntry[] {
  const entries: SshConfigEntry[] = []
  let current: SshConfigEntry | null = null

  for (const rawLine of content.split("\n")) {
    const line = rawLine.trim()
    if (!line || line.startsWith("#")) continue

    const match = line.match(/^(\S+)\s+(.+)$/)
    if (!match) continue

    const key = match[1].toLowerCase()
    const value = match[2].trim()

    if (key === "host") {
      const tokens = value.match(/"[^"]*"|\S+/g) || []
      current = {
        patterns: tokens.map((t) =>
          t.startsWith('"') && t.endsWith('"') ? t.slice(1, -1) : t,
        ),
      }
      entries.push(current)
      continue
    }

    if (key === "match") {
      current = { patterns: [] }
      entries.push(current)
      continue
    }

    if (!current) continue

    switch (key) {
      case "hostname":
        current.hostName = value
        break
      case "user":
        current.user = value
        break
      case "port": {
        const num = Number.parseInt(value, 10)
        if (!Number.isNaN(num)) current.port = num
        break
      }
      case "identityfile":
        current.identityFile = value
        break
    }
  }

  return entries
}

/** Turn an OpenSSH Host pattern (may contain `*` / `?`) into a RegExp. */
function hostPatternToRegex(pattern: string): RegExp {
  let out = ""
  for (const ch of pattern) {
    if (ch === "*") out += ".*"
    else if (ch === "?") out += "."
    else out += ch.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
  }
  return new RegExp(`^${out}$`, "i")
}

/**
 * Find the first ssh config entry matching a host name.
 * Prefers exact aliases, then falls back to `*`/`?` glob patterns.
 */
export function findHostConfig(entries: SshConfigEntry[], host: string): SshConfigEntry | undefined {
  const normalized = host.toLowerCase()
  for (const entry of entries) {
    for (const pattern of entry.patterns) {
      if (pattern.toLowerCase() === normalized) return entry
    }
  }
  for (const entry of entries) {
    for (const pattern of entry.patterns) {
      if (pattern.includes("*") || pattern.includes("?")) {
        if (hostPatternToRegex(pattern).test(host)) return entry
      }
    }
  }
  return undefined
}

/** Load and parse the ssh config file. Empty entry list if it does not exist. */
export function loadSshConfig(configuredPath?: string): LoadedSshConfig {
  const path = resolveSshConfigPath(configuredPath)
  if (!existsSync(path)) return { entries: [], path }
  return { entries: parseSshConfig(readFileSync(path, "utf-8")), path }
}

/**
 * Concrete machines suitable for auto-connecting: `Host` entries that
 * resolve to a real `HostName`.
 */
export function getAutoConnectHosts(
  configuredPath?: string,
): Array<{ alias: string; hostName: string; user?: string; port?: number; identityFile?: string }> {
  const { entries } = loadSshConfig(configuredPath)
  const hosts: Array<{ alias: string; hostName: string; user?: string; port?: number; identityFile?: string }> = []

  for (const entry of entries) {
    if (entry.patterns.length > 0 && entry.hostName) {
      hosts.push({
        alias: entry.patterns[0],
        hostName: entry.hostName,
        user: entry.user,
        port: entry.port,
        identityFile: entry.identityFile,
      })
    }
  }

  return hosts
}