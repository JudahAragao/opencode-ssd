import { readFileSync, writeFileSync, existsSync, mkdirSync } from "fs"
import { join } from "path"
import { getSshDataDir } from "../config/defaults.js"
import { createCustomEntries, type BlocklistEntry, type CommandLevel } from "./blocklist.js"
import type { SecurityMode } from "../config/schema.js"

export interface SecurityPolicy {
  mode: SecurityMode
  extraBlocklist: string[]
  customAllowlist: string[]
  updatedAt: string
}

const POLICY_FILE = "policy.json"

/**
 * Load the security policy from disk.
 */
export function loadPolicy(projectDir: string): SecurityPolicy | null {
  const dataDir = getSshDataDir(projectDir)
  const filePath = join(dataDir, POLICY_FILE)

  if (!existsSync(filePath)) return null

  try {
    const content = readFileSync(filePath, "utf-8")
    return JSON.parse(content) as SecurityPolicy
  } catch {
    return null
  }
}

/**
 * Save the security policy to disk.
 */
export function savePolicy(projectDir: string, policy: SecurityPolicy): void {
  const dataDir = getSshDataDir(projectDir)
  if (!existsSync(dataDir)) {
    mkdirSync(dataDir, { recursive: true })
  }

  const filePath = join(dataDir, POLICY_FILE)
  writeFileSync(filePath, JSON.stringify(policy, null, 2), "utf-8")
}

/**
 * Get or create a default policy.
 */
export function getPolicy(projectDir: string, mode: SecurityMode = "full"): SecurityPolicy {
  const existing = loadPolicy(projectDir)
  if (existing) return existing

  const defaultPolicy: SecurityPolicy = {
    mode,
    extraBlocklist: [],
    customAllowlist: [],
    updatedAt: new Date().toISOString(),
  }

  savePolicy(projectDir, defaultPolicy)
  return defaultPolicy
}

/**
 * Add a pattern to the blocklist.
 */
export function addBlocklistPattern(projectDir: string, pattern: string): SecurityPolicy {
  const policy = getPolicy(projectDir)
  if (policy.extraBlocklist.includes(pattern)) {
    return policy
  }

  policy.extraBlocklist.push(pattern)
  policy.updatedAt = new Date().toISOString()
  savePolicy(projectDir, policy)
  return policy
}

/**
 * Remove a pattern from the blocklist.
 */
export function removeBlocklistPattern(projectDir: string, pattern: string): SecurityPolicy {
  const policy = getPolicy(projectDir)
  policy.extraBlocklist = policy.extraBlocklist.filter((p) => p !== pattern)
  policy.updatedAt = new Date().toISOString()
  savePolicy(projectDir, policy)
  return policy
}

/**
 * Add a pattern to the allowlist.
 */
export function addAllowlistPattern(projectDir: string, pattern: string): SecurityPolicy {
  const policy = getPolicy(projectDir)
  if (policy.customAllowlist.includes(pattern)) {
    return policy
  }

  policy.customAllowlist.push(pattern)
  policy.updatedAt = new Date().toISOString()
  savePolicy(projectDir, policy)
  return policy
}

/**
 * Remove a pattern from the allowlist.
 */
export function removeAllowlistPattern(projectDir: string, pattern: string): SecurityPolicy {
  const policy = getPolicy(projectDir)
  policy.customAllowlist = policy.customAllowlist.filter((p) => p !== pattern)
  policy.updatedAt = new Date().toISOString()
  savePolicy(projectDir, policy)
  return policy
}

/**
 * Merge the plugin config `allowlist` with the per-project custom allowlist
 * (managed via ssh.security_policy add_allowlist). Returns a deduped list.
 */
export function getEffectiveCustomAllowlist(
  projectDir: string,
  configAllowlist: string[] = [],
): string[] {
  const policy = loadPolicy(projectDir)
  const policyAllowlist: string[] = policy?.customAllowlist ?? []
  return [...new Set([...configAllowlist, ...policyAllowlist])]
}

/**
 * Format the current policy for display.
 */
export function formatPolicy(policy: SecurityPolicy): string {
  const lines = [
    "## SSH Security Policy",
    "",
    `**Mode:** ${policy.mode}`,
    `**Last updated:** ${policy.updatedAt}`,
    "",
  ]

  if (policy.extraBlocklist.length > 0) {
    lines.push("### Extra Blocklist Patterns")
    for (const p of policy.extraBlocklist) {
      lines.push(`- \`${p}\``)
    }
    lines.push("")
  }

  if (policy.customAllowlist.length > 0) {
    lines.push("### Custom Allowlist Patterns")
    for (const p of policy.customAllowlist) {
      lines.push(`- \`${p}\``)
    }
    lines.push("")
  }

  lines.push("### Mode Description")
  switch (policy.mode) {
    case "full":
      lines.push("All commands allowed except those in the blocklist.")
      break
    case "restricted":
      lines.push("Only commands in the allowlist + read-only commands are allowed.")
      break
    case "read_only":
      lines.push("Only read-only commands are allowed (ls, cat, grep, etc.).")
      break
  }

  return lines.join("\n")
}
