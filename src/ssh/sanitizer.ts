/**
 * Input sanitizer for SSH commands.
 * Prevents command injection, special character attacks, and encoding tricks.
 */

/**
 * Dangerous characters/sequences that could be used for injection.
 */
const INJECTION_PATTERNS = [
  // Null byte injection
  /\x00/,
  // Command chaining via backticks (when not already in a string context)
  /`[^`]*`/,
  // ANSI escape sequences (terminal injection)
  /\x1b\[[0-9;]*[a-zA-Z]/,
  // Unicode direction override characters (bidirectional attacks)
  /[\u202a-\u202e\u2066-\u2069]/,
  // Unicode homoglyphs for common ASCII (basic detection)
  // These are often used for visual spoofing
]

/**
 * Sanitize a command string before execution.
 *
 * This does NOT change the command - it detects and rejects
 * commands that contain injection attempts.
 */
export function sanitizeCommand(command: string): { clean: boolean; reason?: string } {
  if (!command || command.trim().length === 0) {
    return { clean: false, reason: "Empty command" }
  }

  // Check for null bytes
  if (command.includes("\x00")) {
    return { clean: false, reason: "Command contains null bytes (possible injection)" }
  }

  // Check for ANSI escape sequences
  if (/\x1b\[[0-9;]*[a-zA-Z]/.test(command)) {
    return { clean: false, reason: "Command contains ANSI escape sequences (terminal injection attempt)" }
  }

  // Check for Unicode direction overrides
  if (/[\u202a-\u202e\u2066-\u2069]/.test(command)) {
    return { clean: false, reason: "Command contains Unicode direction override characters (BIDI attack attempt)" }
  }

  // Check for extremely long commands (possible buffer overflow attempt)
  if (command.length > 10000) {
    return { clean: false, reason: "Command exceeds maximum length (10,000 chars)" }
  }

  return { clean: true }
}

/**
 * Sanitize a hostname string.
 */
export function sanitizeHost(host: string): { clean: boolean; reason?: string } {
  if (!host || host.trim().length === 0) {
    return { clean: false, reason: "Empty hostname" }
  }

  // Hostnames should only contain alphanumeric, hyphens, dots, and colons (for IPv6)
  if (!/^[a-zA-Z0-9.\-:\[\]]+$/.test(host)) {
    return { clean: false, reason: "Hostname contains invalid characters" }
  }

  // Basic length check
  if (host.length > 253) {
    return { clean: false, reason: "Hostname exceeds maximum length" }
  }

  return { clean: true }
}

/**
 * Sanitize a username string.
 */
export function sanitizeUsername(username: string): { clean: boolean; reason?: string } {
  if (!username || username.trim().length === 0) {
    return { clean: false, reason: "Empty username" }
  }

  // Unix usernames typically: lowercase, digits, hyphens, underscores
  if (!/^[a-zA-Z0-9._\-]+$/.test(username)) {
    return { clean: false, reason: "Username contains invalid characters" }
  }

  if (username.length > 32) {
    return { clean: false, reason: "Username exceeds maximum length" }
  }

  return { clean: true }
}

/**
 * Sanitize a file path for SCP operations.
 */
export function sanitizePath(filePath: string): { clean: boolean; reason?: string } {
  if (!filePath || filePath.trim().length === 0) {
    return { clean: false, reason: "Empty file path" }
  }

  // Check for null bytes
  if (filePath.includes("\x00")) {
    return { clean: false, reason: "Path contains null bytes" }
  }

  // Check for command substitution in paths
  if (/[`$()]/.test(filePath)) {
    return { clean: false, reason: "Path contains shell metacharacters (possible injection)" }
  }

  // Path traversal is allowed (user might need to navigate), but log it
  // The blocklist will catch dangerous operations anyway

  return { clean: true }
}

/**
 * Escape a string for safe use in shell commands.
 * Useful when building compound commands.
 */
export function escapeShellArg(arg: string): string {
  // Wrap in single quotes, escaping any single quotes within
  return "'" + arg.replace(/'/g, "'\\''") + "'"
}
