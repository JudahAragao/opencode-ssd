import type { ExecResult } from "../ssh/executor.js"
import type { SshConnectionInfo } from "../ssh/connection.js"

/**
 * Format an SSH execution result for display in the terminal.
 */
export function formatExecResult(result: ExecResult): string {
  const lines: string[] = []

  // ── Header with session and command info ──
  const durationStr =
    result.duration < 1000
      ? `${result.duration}ms`
      : `${(result.duration / 1000).toFixed(1)}s`

  const exitIcon = result.exitCode === 0 ? "✅" : "❌"

  lines.push(`### SSH Execution [${result.sessionId}]`)
  lines.push("")

  // Command
  lines.push(`**$ ${result.command}**`)
  if (result.validation.level === "risky") {
    lines.push(`⚠️ *Risky command — executed with user approval*`)
  }
  lines.push("")

  // stdout
  if (result.stdout) {
    const trimmed = result.stdout.trim()
    if (trimmed.length > 0) {
      lines.push("**Output:**")
      lines.push("```")
      lines.push(trimmed)
      lines.push("```")
    }
  }

  // stderr
  if (result.stderr) {
    const trimmed = result.stderr.trim()
    if (trimmed.length > 0) {
      lines.push("**Errors:**")
      lines.push("```")
      lines.push(trimmed)
      lines.push("```")
    }
  }

  // Footer with exit code and duration
  lines.push(`${exitIcon} Exit: ${result.exitCode ?? "?"} | Duration: ${durationStr}`)

  return lines.join("\n")
}

/**
 * Format a session list for display.
 */
export function formatSessionList(sessions: SshConnectionInfo[]): string {
  if (sessions.length === 0) {
    return "📋 No active SSH sessions."
  }

  const lines = [`## Active SSH Sessions (${sessions.length})\n`]

  for (const session of sessions) {
    const status = session.connected ? "🟢 Connected" : "🔴 Disconnected"
    const alias = session.config.alias ? ` (${session.config.alias})` : ""
    const uptime = session.connectedAt
      ? formatUptime(new Date(session.connectedAt))
      : "N/A"

    lines.push(
      `- **${session.id}**${alias}: ${session.config.username}@${session.config.host}:${session.config.port} — ${status}`,
    )
    lines.push(`  Uptime: ${uptime} | Auth: ${session.config.authMethod}`)
    lines.push("")
  }

  return lines.join("\n")
}

/**
 * Format a connection success message.
 */
export function formatConnectResult(
  sessionId: string,
  host: string,
  port: number,
  username: string,
  alias?: string,
): string {
  const aliasStr = alias ? ` ("${alias}")` : ""
  return [
    `## SSH Connected${aliasStr}`,
    "",
    `- **Session:** \`${sessionId}\``,
    `- **Host:** ${username}@${host}:${port}`,
    `- **Status:** 🟢 Connected`,
    "",
    `Use \`ssh.exec\` with session_id=\`${sessionId}\` to run commands.`,
  ].join("\n")
}

/**
 * Format a disconnection message.
 */
export function formatDisconnectResult(sessionId: string): string {
  return `## SSH Disconnected\n\nSession \`${sessionId}\` has been closed.`
}

/**
 * Format a blocked command message.
 */
export function formatBlockedCommand(
  command: string,
  reason: string,
  level: "destructive" | "risky",
): string {
  if (level === "destructive") {
    return [
      "## 🚫 Command Blocked (Destructive)",
      "",
      `**Command:** \`${command}\``,
      `**Reason:** ${reason}`,
      "",
      "This command is **permanently blocked** and cannot be overridden.",
      "Destructive commands are blocked for your safety.",
    ].join("\n")
  }

  return [
    "## ⚠️ Command Requires Approval",
    "",
    `**Command:** \`${command}\``,
    `**Reason:** ${reason}`,
    "",
    "This command has been classified as risky and requires your approval.",
  ].join("\n")
}

/**
 * Format a command check result (dry-run validation).
 */
export function formatCheckResult(
  command: string,
  validation: { safe: boolean; level: string; reason?: string; matched_rule?: string },
): string {
  const icon = validation.safe ? "✅" : validation.level === "destructive" ? "🚫" : "⚠️"

  const lines = [
    `## Command Safety Check`,
    "",
    `**Command:** \`${command}\``,
    `**Status:** ${icon} ${validation.safe ? "Safe" : validation.level === "destructive" ? "BLOCKED" : "Requires Approval"}`,
  ]

  if (validation.reason) {
    lines.push(`**Reason:** ${validation.reason}`)
  }

  if (validation.matched_rule) {
    lines.push(`**Rule:** ${validation.matched_rule}`)
  }

  return lines.join("\n")
}

/**
 * Format a security policy for display.
 */
export function formatSecurityPolicy(policy: {
  mode: string
  extraBlocklist: string[]
  customAllowlist: string[]
  updatedAt: string
}): string {
  const lines = [
    "## SSH Security Policy",
    "",
    `**Mode:** \`${policy.mode}\``,
    `**Last Updated:** ${policy.updatedAt}`,
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

// ── Helpers ──

function formatUptime(connectedAt: Date): string {
  const now = Date.now()
  const diff = now - connectedAt.getTime()
  const seconds = Math.floor(diff / 1000)
  const minutes = Math.floor(seconds / 60)
  const hours = Math.floor(minutes / 60)

  if (hours > 0) return `${hours}h ${minutes % 60}m`
  if (minutes > 0) return `${minutes}m ${seconds % 60}s`
  return `${seconds}s`
}
