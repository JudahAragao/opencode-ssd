import { getBuiltinBlocklist, createCustomEntries, type CommandLevel, type BlocklistEntry } from "./blocklist.js"
import { getAllowedCommands, type AllowlistEntry } from "./allowlist.js"
import type { SecurityMode } from "../config/schema.js"

export type ValidationResult = {
  /** Whether the command is safe to execute */
  safe: boolean
  /** Danger level of the command */
  level: CommandLevel | "not_in_allowlist"
  /** Human-readable reason */
  reason?: string
  /** The matched rule ID from blocklist */
  matched_rule?: string
  /** Suggestions for safer alternatives */
  suggestions?: string[]
}

/**
 * Validate a command against the security policy.
 *
 * Validation order:
 * 1. Check against destructive blocklist → ALWAYS BLOCKED (no exceptions)
 * 2. Check against risky blocklist → requires permission prompt
 * 3. In restricted/read_only mode, check against allowlist
 */
export function validateCommand(
  command: string,
  mode: SecurityMode,
  extraBlocklist: string[] = [],
): ValidationResult {
  const trimmed = command.trim()
  if (!trimmed) {
    return { safe: true, level: "safe" }
  }

  // ── Step 1: Check against ALL blocklist entries ──
  const allBlocklistEntries = [
    ...getBuiltinBlocklist(),
    ...createCustomEntries(extraBlocklist),
  ]

  for (const entry of allBlocklistEntries) {
    if (entry.pattern.test(trimmed)) {
      // Destructive: always blocked, no override
      if (entry.level === "destructive") {
        return {
          safe: false,
          level: "destructive",
          reason: `🚫 BLOCKED [${entry.id}]: ${entry.reason}`,
          matched_rule: entry.id,
          suggestions: getSuggestions(entry),
        }
      }

      // Risky: requires permission prompt
      if (entry.level === "risky") {
        return {
          safe: false,
          level: "risky",
          reason: `⚠️ REQUIRES APPROVAL [${entry.id}]: ${entry.reason}`,
          matched_rule: entry.id,
          suggestions: getSuggestions(entry),
        }
      }
    }
  }

  // ── Step 2: In restricted/read_only mode, check allowlist ──
  if (mode === "restricted" || mode === "read_only") {
    const allowedCommands = getAllowedCommands(mode)
    const isAllowed = allowedCommands.some((entry) => entry.pattern.test(trimmed))

    if (!isAllowed) {
      return {
        safe: false,
        level: "not_in_allowlist",
        reason: `🔒 NOT ALLOWED in "${mode}" mode. Command not in the allowlist.`,
        suggestions: [
          `Switch to "full" mode to allow all non-blocked commands`,
          `Add this command pattern to the allowlist via ssh.security_policy`,
        ],
      }
    }
  }

  // ── Command is safe ──
  return { safe: true, level: "safe" }
}

/**
 * Check if a command is purely read-only (no side effects).
 */
export function isReadOnlyCommand(command: string): boolean {
  const readOnlyPatterns = [
    /^ls\b/,
    /^ll\b/,
    /^la\b/,
    /^cat\b/,
    /^head\b/,
    /^tail\b/,
    /^less\b/,
    /^more\b/,
    /^grep\b/,
    /^rg\b/,
    /^find\b/,
    /^which\b/,
    /^whereis\b/,
    /^whoami\b/,
    /^id\b/,
    /^pwd\b/,
    /^echo\b/,
    /^date\b/,
    /^uptime\b/,
    /^uname\b/,
    /^hostname\b/,
    /^df\b/,
    /^du\b/,
    /^free\b/,
    /^ps\b/,
    /^wc\b/,
    /^file\b/,
    /^stat\b/,
    /^tree\b/,
    /^diff\b/,
    /^md5sum\b/,
    /^sha256sum\b/,
    /^env\b/,
    /^printenv\b/,
    /^man\b/,
    /^ping\b/,
    /^dig\b/,
    /^nslookup\b/,
    /^docker\s+ps\b/,
    /^docker\s+images\b/,
    /^docker\s+logs\b/,
    /^docker\s+inspect\b/,
    /^kubectl\s+get\b/,
    /^kubectl\s+describe\b/,
    /^kubectl\s+logs\b/,
    /^kubectl\s+top\b/,
    /^systemctl\s+status\b/,
    /^systemctl\s+list\b/,
    /^journalctl\b/,
    /^git\s+(status|log|diff|show|branch|remote)\b/,
  ]

  return readOnlyPatterns.some((p) => p.test(command.trim()))
}

/**
 * Get safer alternatives for a blocked/risky command.
 */
function getSuggestions(entry: BlocklistEntry): string[] {
  const suggestions: Record<string, string[]> = {
    DESTR: ["This command is permanently blocked and cannot be overridden."],
    RISK: ["Consider running this command manually via a direct SSH session."],
  }

  const prefix = entry.id.split("-")[0]
  return suggestions[prefix] || ["Consider a safer alternative or run manually."]
}

/**
 * Format validation result for display.
 */
export function formatValidationResult(result: ValidationResult): string {
  if (result.safe) {
    return "✅ Command is safe to execute."
  }

  const lines: string[] = [result.reason || "Command validation failed."]

  if (result.matched_rule) {
    lines.push(`Rule: ${result.matched_rule}`)
  }

  if (result.suggestions && result.suggestions.length > 0) {
    lines.push("\nSuggestions:")
    for (const s of result.suggestions) {
      lines.push(`  • ${s}`)
    }
  }

  return lines.join("\n")
}
