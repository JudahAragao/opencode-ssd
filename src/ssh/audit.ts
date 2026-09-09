import { appendFileSync, readFileSync, existsSync, mkdirSync } from "fs"
import { join } from "path"
import { getSshDataDir } from "../config/defaults.js"

export interface AuditEntry {
  /** ISO timestamp */
  timestamp: string
  /** Session identifier (host@user) */
  sessionId: string
  /** Command executed */
  command: string
  /** Result of the command */
  result: "success" | "blocked" | "approved" | "error"
  /** Exit code */
  exitCode: number
  /** Duration in milliseconds */
  duration: number
  /** Reason for blocking/error */
  reason?: string
  /** Matched blocklist rule ID */
  matchedRule?: string
}

const AUDIT_FILE = "audit.jsonl"

/**
 * Get the audit log file path.
 */
function getAuditPath(projectDir: string): string {
  const dataDir = getSshDataDir(projectDir)
  try {
    if (!existsSync(dataDir)) {
      mkdirSync(dataDir, { recursive: true })
    }
  } catch {
    // If we can't create the directory, use a fallback
  }
  return join(dataDir, AUDIT_FILE)
}

/**
 * Log a command execution to the audit trail.
 * Uses JSONL format (append-only).
 */
export function logCommand(projectDir: string, entry: Omit<AuditEntry, "timestamp">): void {
  const auditEntry: AuditEntry = {
    timestamp: new Date().toISOString(),
    ...entry,
  }

  try {
    const auditPath = getAuditPath(projectDir)
    appendFileSync(auditPath, JSON.stringify(auditEntry) + "\n", "utf-8")
  } catch {
    // Audit logging should never crash the main flow
  }
}

/**
 * Read the audit log entries.
 */
export function readAuditLog(
  projectDir: string,
  options: {
    limit?: number
    sessionId?: string
    commandFilter?: string
  } = {},
): AuditEntry[] {
  const auditPath = getAuditPath(projectDir)
  if (!existsSync(auditPath)) return []

  try {
    const content = readFileSync(auditPath, "utf-8")
    const lines = content.trim().split("\n").filter(Boolean)

    let entries: AuditEntry[] = lines.map((line) => {
      try {
        return JSON.parse(line) as AuditEntry
      } catch {
        return null
      }
    }).filter((e): e is AuditEntry => e !== null)

    // Apply filters
    if (options.sessionId) {
      entries = entries.filter((e) => e.sessionId === options.sessionId)
    }

    if (options.commandFilter) {
      const filter = options.commandFilter.toLowerCase()
      entries = entries.filter((e) => e.command.toLowerCase().includes(filter))
    }

    // Apply limit (return most recent entries)
    if (options.limit && options.limit > 0) {
      entries = entries.slice(-options.limit)
    }

    return entries
  } catch {
    return []
  }
}

/**
 * Format audit log entries for display.
 */
export function formatAuditLog(entries: AuditEntry[]): string {
  if (entries.length === 0) {
    return "📋 No audit entries found."
  }

  const lines = [`## SSH Audit Log (${entries.length} entries)\n`]

  for (const entry of entries) {
    const icon =
      entry.result === "success"
        ? "✅"
        : entry.result === "approved"
          ? "⚠️"
          : entry.result === "blocked"
            ? "🚫"
            : "❌"

    const duration = entry.duration < 1000
      ? `${entry.duration}ms`
      : `${(entry.duration / 1000).toFixed(1)}s`

    lines.push(
      `${icon} **${entry.timestamp}** | ${entry.sessionId} | \`${entry.command}\``,
    )

    const details: string[] = []
    if (entry.exitCode !== 0) details.push(`exit: ${entry.exitCode}`)
    details.push(`duration: ${duration}`)
    if (entry.matchedRule) details.push(`rule: ${entry.matchedRule}`)
    if (entry.reason) details.push(`reason: ${entry.reason}`)

    if (details.length > 0) {
      lines.push(`   ${details.join(" | ")}`)
    }

    lines.push("")
  }

  return lines.join("\n")
}

/**
 * Get audit statistics.
 */
export function getAuditStats(projectDir: string): {
  total: number
  success: number
  blocked: number
  approved: number
  error: number
  blockedCommands: string[]
} {
  const entries = readAuditLog(projectDir)

  return {
    total: entries.length,
    success: entries.filter((e) => e.result === "success").length,
    blocked: entries.filter((e) => e.result === "blocked").length,
    approved: entries.filter((e) => e.result === "approved").length,
    error: entries.filter((e) => e.result === "error").length,
    blockedCommands: [
      ...new Set(
        entries
          .filter((e) => e.result === "blocked")
          .map((e) => e.command),
      ),
    ],
  }
}
