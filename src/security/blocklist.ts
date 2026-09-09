/**
 * Command Blocklist for SSH plugin.
 *
 * Commands are categorized into two levels:
 * - DESTRUCTIVE: 100% blocked, no exceptions, no override possible
 * - RISKY: Blocked by default, requires user approval via permission prompt every time
 */

export type CommandLevel = "destructive" | "risky" | "safe"

export interface BlocklistEntry {
  /** Regex pattern to match against the command */
  pattern: RegExp
  /** Human-readable description of why this is blocked */
  reason: string
  /** Level of danger */
  level: CommandLevel
  /** Unique rule ID for audit logging */
  id: string
}

// ─── DESTRUCTIVE COMMANDS ───────────────────────────────────────────
// These are ALWAYS blocked. No permission prompt, no override.

const DESTRUCTIVE_COMMANDS: BlocklistEntry[] = [
  {
    id: "DESTR-001",
    pattern: /\brm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)?\/\s*$/i,
    reason: "Recursive deletion of root filesystem",
    level: "destructive",
  },
  {
    id: "DESTR-002",
    pattern: /\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\s+\/\s*\*?\s*$/i,
    reason: "Recursive force deletion from root",
    level: "destructive",
  },
  {
    id: "DESTR-003",
    pattern: /\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\s+~\s*$/i,
    reason: "Recursive force deletion of home directory",
    level: "destructive",
  },
  {
    id: "DESTR-004",
    pattern: /\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\s+\.\*?\s*$/i,
    reason: "Recursive force deletion of current directory contents",
    level: "destructive",
  },
  {
    id: "DESTR-005",
    pattern: /\bmkfs\b/,
    reason: "Filesystem formatting command",
    level: "destructive",
  },
  {
    id: "DESTR-006",
    pattern: /\bdd\s+if=\/dev\/(zero|random|urandom)/i,
    reason: "Direct disk write operation (zeroing/randomizing)",
    level: "destructive",
  },
  {
    id: "DESTR-007",
    pattern: /\bdd\s+.*of=\/dev\/[a-z]/i,
    reason: "Direct write to block device",
    level: "destructive",
  },
  {
    id: "DESTR-008",
    pattern: /:\(\)\{.*\|.*\&\}\s*;?:/,
    reason: "Fork bomb detected",
    level: "destructive",
  },
  {
    id: "DESTR-009",
    pattern: /\bchmod\s+(-[a-zA-Z]*R[a-zA-Z]*)?\s+777\s+\//i,
    reason: "Recursive chmod 777 on root",
    level: "destructive",
  },
  {
    id: "DESTR-010",
    pattern: /\bchmod\s+(-[a-zA-Z]*R[a-zA-Z]*)?\s+000\s+\//i,
    reason: "Recursive chmod 000 on root (removes all permissions)",
    level: "destructive",
  },
  {
    id: "DESTR-011",
    pattern: /\bchown\s+(-[a-zA-Z]*R[a-zA-Z]*)?\s+.*\s+\//i,
    reason: "Recursive chown on root filesystem",
    level: "destructive",
  },
  {
    id: "DESTR-012",
    pattern: /\b(wget|curl)\s+.*\|\s*(sh|bash|zsh|dash|ksh)/i,
    reason: "Piping remote content directly to shell (remote code execution)",
    level: "destructive",
  },
  {
    id: "DESTR-013",
    pattern: /\b>\s*\/dev\/sda/i,
    reason: "Direct write to system disk device",
    level: "destructive",
  },
  {
    id: "DESTR-014",
    pattern: /\bmv\s+.*\s+\/\s*$/i,
    reason: "Moving content to root filesystem",
    level: "destructive",
  },
  {
    id: "DESTR-015",
    pattern: /\bshutdown\b/i,
    reason: "System shutdown command",
    level: "destructive",
  },
  {
    id: "DESTR-016",
    pattern: /\breboot\b/i,
    reason: "System reboot command",
    level: "destructive",
  },
  {
    id: "DESTR-017",
    pattern: /\binit\s+[06]\b/i,
    reason: "System halt/init 0 or init 6",
    level: "destructive",
  },
  {
    id: "DESTR-018",
    pattern: /\bkill\s+-9\s+1\b/i,
    reason: "Killing PID 1 (init/systemd) - will crash the system",
    level: "destructive",
  },
  {
    id: "DESTR-019",
    pattern: /\bkillall\b/i,
    reason: "Kill all processes command",
    level: "destructive",
  },
  {
    id: "DESTR-020",
    pattern: /\biptables\s+-F\b/i,
    reason: "Flushing all firewall rules",
    level: "destructive",
  },
  {
    id: "DESTR-021",
    pattern: /\bufw\s+disable\b/i,
    reason: "Disabling the firewall",
    level: "destructive",
  },
  {
    id: "DESTR-022",
    pattern: /\b(>|>>)\s*\/dev\/(sda|sdb|hda|vda|nvme)/i,
    reason: "Writing directly to block device",
    level: "destructive",
  },
  {
    id: "DESTR-023",
    pattern: /\bformat\s+[a-zA-Z]:\\/i,
    reason: "Windows format command",
    level: "destructive",
  },
  {
    id: "DESTR-024",
    pattern: /\bdel\s+\/[sfq]\s+[\\\/]/i,
    reason: "Windows recursive delete command",
    level: "destructive",
  },
]

// ─── RISKY COMMANDS ────────────────────────────────────────────────
// These require user approval EVERY TIME via permission prompt.

const RISKY_COMMANDS: BlocklistEntry[] = [
  {
    id: "RISK-001",
    pattern: /\bDROP\s+TABLE\b/i,
    reason: "Destructive SQL: dropping a table",
    level: "risky",
  },
  {
    id: "RISK-002",
    pattern: /\bDROP\s+DATABASE\b/i,
    reason: "Destructive SQL: dropping an entire database",
    level: "risky",
  },
  {
    id: "RISK-003",
    pattern: /\bDELETE\s+FROM\b/i,
    reason: "Destructive SQL: deleting rows from a table",
    level: "risky",
  },
  {
    id: "RISK-004",
    pattern: /\bTRUNCATE\b/i,
    reason: "Destructive SQL: truncating a table",
    level: "risky",
  },
  {
    id: "RISK-005",
    pattern: /\bALTER\s+TABLE\s+\S+\s+DROP\b/i,
    reason: "Schema change: dropping a column",
    level: "risky",
  },
  {
    id: "RISK-006",
    pattern: /\bsudo\s+su\b/i,
    reason: "Switching to root user",
    level: "risky",
  },
  {
    id: "RISK-007",
    pattern: /\bsudo\s+-i\b/i,
    reason: "Interactive root shell",
    level: "risky",
  },
  {
    id: "RISK-008",
    pattern: /\bsystemctl\s+stop\b/i,
    reason: "Stopping a system service",
    level: "risky",
  },
  {
    id: "RISK-009",
    pattern: /\bsystemctl\s+disable\b/i,
    reason: "Disabling a system service",
    level: "risky",
  },
  {
    id: "RISK-010",
    pattern: /\bkill\s+-9\b/i,
    reason: "Force killing a process (SIGKILL)",
    level: "risky",
  },
  {
    id: "RISK-011",
    pattern: /\bkill\s+-15\b/i,
    reason: "Sending SIGTERM to a process",
    level: "risky",
  },
  {
    id: "RISK-012",
    pattern: /\bservice\s+\S+\s+stop\b/i,
    reason: "Stopping a service via service command",
    level: "risky",
  },
  {
    id: "RISK-013",
    pattern: /\bnpm\s+uninstall\s+-g\b/i,
    reason: "Global npm package uninstallation",
    level: "risky",
  },
  {
    id: "RISK-014",
    pattern: /\byarn\s+global\s+remove\b/i,
    reason: "Global yarn package removal",
    level: "risky",
  },
  {
    id: "RISK-015",
    pattern: /\bapt\s+(remove|purge)\b/i,
    reason: "Package removal via apt",
    level: "risky",
  },
  {
    id: "RISK-016",
    pattern: /\byum\s+remove\b/i,
    reason: "Package removal via yum",
    level: "risky",
  },
  {
    id: "RISK-017",
    pattern: /\bdnf\s+remove\b/i,
    reason: "Package removal via dnf",
    level: "risky",
  },
  {
    id: "RISK-018",
    pattern: /\bsnap\s+remove\b/i,
    reason: "Snap package removal",
    level: "risky",
  },
  {
    id: "RISK-019",
    pattern: /\bcron(tab)?\s+(-r|-l)\b/i,
    reason: "Cron job manipulation (remove or list for editing)",
    level: "risky",
  },
  {
    id: "RISK-020",
    pattern: /\buserdel\b/i,
    reason: "User account deletion",
    level: "risky",
  },
  {
    id: "RISK-021",
    pattern: /\bgroupdel\b/i,
    reason: "Group deletion",
    level: "risky",
  },
  {
    id: "RISK-022",
    pattern: /\bpasswd\s+\w+/i,
    reason: "Changing another user's password",
    level: "risky",
  },
  {
    id: "RISK-023",
    pattern: /\biptables\s+-[AD]\b/i,
    reason: "Modifying firewall rules",
    level: "risky",
  },
  {
    id: "RISK-024",
    pattern: /\bnc\s+.*-l\b/i,
    reason: "Listening on a network port (netcat)",
    level: "risky",
  },
  {
    id: "RISK-025",
    pattern: /\bss\s+-lntp\b/i,
    reason: "Listing all listening network ports",
    level: "risky",
  },
  {
    id: "RISK-026",
    pattern: /\bchmod\s+(-[a-zA-Z]*R[a-zA-Z]*)?\s+777\b/i,
    reason: "Granting full permissions (777) recursively",
    level: "risky",
  },
  {
    id: "RISK-027",
    pattern: /\bchmod\s+(-[a-zA-Z]*R[a-zA-Z]*)?\s+000\b/i,
    reason: "Removing all permissions recursively",
    level: "risky",
  },
]

/**
 * Get all built-in blocklist entries.
 */
export function getBuiltinBlocklist(): BlocklistEntry[] {
  return [...DESTRUCTIVE_COMMANDS, ...RISKY_COMMANDS]
}

/**
 * Get only destructive commands.
 */
export function getDestructiveCommands(): BlocklistEntry[] {
  return [...DESTRUCTIVE_COMMANDS]
}

/**
 * Get only risky commands.
 */
export function getRiskyCommands(): BlocklistEntry[] {
  return [...RISKY_COMMANDS]
}

/**
 * Create custom blocklist entries from user-provided regex patterns.
 */
export function createCustomEntries(
  patterns: string[],
  level: CommandLevel = "risky",
): BlocklistEntry[] {
  return patterns.map((p, i) => ({
    id: `CUSTOM-${level.toUpperCase()}-${String(i + 1).padStart(3, "0")}`,
    pattern: new RegExp(p, "i"),
    reason: `Custom ${level} pattern`,
    level,
  }))
}
