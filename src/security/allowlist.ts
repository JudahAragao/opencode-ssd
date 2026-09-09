/**
 * Allowlist for SSH command execution.
 * Used in "restricted" and "read_only" security modes.
 */

export interface AllowlistEntry {
  /** Regex pattern to match */
  pattern: RegExp
  /** Description of the allowed command */
  description: string
}

// ─── READ-ONLY COMMANDS (always allowed) ───────────────────────────
const READ_ONLY_COMMANDS: AllowlistEntry[] = [
  { pattern: /^ls\b/, description: "List directory contents" },
  { pattern: /^ll\b/, description: "List directory contents (long)" },
  { pattern: /^la\b/, description: "List all files including hidden" },
  { pattern: /^cat\b/, description: "Display file contents" },
  { pattern: /^head\b/, description: "Display first lines of a file" },
  { pattern: /^tail\b/, description: "Display last lines of a file" },
  { pattern: /^less\b/, description: "View file contents pager" },
  { pattern: /^more\b/, description: "View file contents" },
  { pattern: /^grep\b/, description: "Search text patterns" },
  { pattern: /^rg\b/, description: "Ripgrep search" },
  { pattern: /^find\b/, description: "Find files" },
  { pattern: /^which\b/, description: "Locate a command" },
  { pattern: /^whereis\b/, description: "Locate binary, source, man" },
  { pattern: /^whoami\b/, description: "Print current user" },
  { pattern: /^id\b/, description: "Print user/group IDs" },
  { pattern: /^pwd\b/, description: "Print working directory" },
  { pattern: /^echo\b/, description: "Print text" },
  { pattern: /^date\b/, description: "Print date and time" },
  { pattern: /^uptime\b/, description: "System uptime" },
  { pattern: /^uname\b/, description: "System information" },
  { pattern: /^hostname\b/, description: "Print hostname" },
  { pattern: /^df\b/, description: "Disk space usage" },
  { pattern: /^du\b/, description: "Directory space usage" },
  { pattern: /^free\b/, description: "Memory usage" },
  { pattern: /^ps\b/, description: "Process status" },
  { pattern: /^top\b/, description: "Process monitor (read-only)" },
  { pattern: /^htop\b/, description: "Process monitor (enhanced)" },
  { pattern: /^wc\b/, description: "Word/line/byte count" },
  { pattern: /^file\b/, description: "Determine file type" },
  { pattern: /^stat\b/, description: "Display file status" },
  { pattern: /^tree\b/, description: "Directory tree display" },
  { pattern: /^du\b/, description: "Disk usage" },
  { pattern: /^diff\b/, description: "Compare files" },
  { pattern: /^md5sum\b/, description: "MD5 checksum" },
  { pattern: /^sha256sum\b/, description: "SHA256 checksum" },
  { pattern: /^env\b/, description: "Print environment variables" },
  { pattern: /^printenv\b/, description: "Print environment variable" },
  { pattern: /^history\b/, description: "Command history" },
  { pattern: /^man\b/, description: "Manual pages" },
  { pattern: /^tldr\b/, description: "Simplified man pages" },
  { pattern: /^ping\b/, description: "Network connectivity test" },
  { pattern: /^dig\b/, description: "DNS lookup" },
  { pattern: /^nslookup\b/, description: "DNS lookup" },
  { pattern: /^host\b/, description: "DNS lookup" },
  { pattern: /^curl\s+.*\s+-I\b/, description: "HTTP HEAD request via curl" },
  { pattern: /^git\s+(status|log|diff|show|branch|remote)\b/, description: "Git read-only commands" },
  { pattern: /^docker\s+ps\b/, description: "List Docker containers" },
  { pattern: /^docker\s+images\b/, description: "List Docker images" },
  { pattern: /^docker\s+logs\b/, description: "View Docker container logs" },
  { pattern: /^docker\s+inspect\b/, description: "Inspect Docker object" },
  { pattern: /^kubectl\s+get\b/, description: "Kubernetes get resources" },
  { pattern: /^kubectl\s+describe\b/, description: "Kubernetes describe resource" },
  { pattern: /^kubectl\s+logs\b/, description: "Kubernetes pod logs" },
  { pattern: /^kubectl\s+top\b/, description: "Kubernetes resource usage" },
  { pattern: /^systemctl\s+status\b/, description: "Service status" },
  { pattern: /^systemctl\s+list\b/, description: "List services" },
  { pattern: /^journalctl\b/, description: "View systemd journal" },
]

// ─── SAFE WRITE COMMANDS (allowed in "restricted" mode) ────────────
const SAFE_WRITE_COMMANDS: AllowlistEntry[] = [
  { pattern: /^mkdir\b/, description: "Create directory" },
  { pattern: /^touch\b/, description: "Create empty file" },
  { pattern: /^cp\b/, description: "Copy files" },
  { pattern: /^mv\b/, description: "Move/rename files" },
  { pattern: /^nano\b/, description: "Text editor" },
  { pattern: /^vim\b/, description: "Text editor" },
  { pattern: /^vi\b/, description: "Text editor" },
  { pattern: /^git\s+(add|commit|push|pull|checkout|merge|stash)\b/, description: "Git write commands" },
  { pattern: /^npm\s+(install|run|test|build)\b/, description: "NPM commands" },
  { pattern: /^yarn\s+(add|run|test|build)\b/, description: "Yarn commands" },
  { pattern: /^pnpm\s+(add|run|test|build)\b/, description: "PNPM commands" },
  { pattern: /^bun\s+(install|run|test|build)\b/, description: "Bun commands" },
]

/**
 * Get read-only allowed commands.
 */
export function getReadOnlyCommands(): AllowlistEntry[] {
  return [...READ_ONLY_COMMANDS]
}

/**
 * Get safe write commands (used in "restricted" mode).
 */
export function getSafeWriteCommands(): AllowlistEntry[] {
  return [...SAFE_WRITE_COMMANDS]
}

/**
 * Get all allowed commands for a given mode.
 */
export function getAllowedCommands(mode: "full" | "restricted" | "read_only"): AllowlistEntry[] {
  switch (mode) {
    case "read_only":
      return getReadOnlyCommands()
    case "restricted":
      return [...getReadOnlyCommands(), ...getSafeWriteCommands()]
    case "full":
      return [] // Only blocklist applies in full mode
  }
}
