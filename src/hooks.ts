import type { Hooks } from "@opencode-ai/plugin"
import { validateCommand } from "./security/validator.js"
import { getEffectiveCustomAllowlist } from "./security/policy.js"
import type { SecurityMode } from "./config/schema.js"

/**
 * Create the SSH plugin hooks.
 *
 * Hooks behavior:
 * - system.transform: Injects SSH availability info into the system prompt
 * - permission.ask: Handles permission responses for SSH commands
 * - tool.execute.before: Pre-execution validation (additional safety net)
 * - tool.execute.after: Post-execution audit metadata
 */
export function createSshHooks(
  mode: SecurityMode = "full",
  extraBlocklist: string[] = [],
  extraAllowlist: string[] = [],
  projectDir: string = "",
): Hooks {
  let systemInjected = false

  return {
    // ═══════════════════════════════════════════════════════════════
    // System prompt injection
    // ═══════════════════════════════════════════════════════════════
    "experimental.chat.system.transform": async (_input, output) => {
      if (systemInjected) return

      output.system.push(
        [
          "## SSH Access Plugin (opencode-ssh)",
          "",
          "You have SSH access to remote servers via the opencode-ssh plugin.",
          "",
          "### Available Tools",
          "- `ssh.connect` — Establish SSH connection to a remote server",
          "- `ssh.disconnect` — Close an SSH session",
          "- `ssh.list_sessions` — List active SSH sessions",
          "- `ssh.exec` — Execute a command on a remote server",
          "- `ssh.exec_batch` — Execute multiple commands in sequence",
          "- `ssh.upload` — Upload a file via SCP/SFTP",
          "- `ssh.download` — Download a file via SCP/SFTP",
          "- `ssh.check_command` — Check command safety without executing",
          "- `ssh.security_policy` — View/modify security policy",
          "- `ssh.audit_log` — View command execution audit trail",
          "",
          "### Security Rules",
          `**Mode:** ${mode}`,
          "",
          "1. **Destructive commands are BLOCKED with no exceptions.**",
          "   Commands like \`rm -rf /\`, \`mkfs\`, \`dd\`, fork bombs, etc.",
          "   are permanently blocked and cannot be overridden.",
          "",
          "2. **Risky commands require your approval EVERY time.**",
          "   Commands like \`DROP TABLE\`, \`sudo su\`, \`systemctl stop\`, etc.",
          "   will prompt you for approval each time they are executed.",
          "",
          "3. **NEVER store credentials in chat messages.**",
          "   Use \`ssh.connect\` with key-based authentication when possible.",
          "",
          "4. **Always use \`ssh.check_command\` to preview command safety**",
          "   before running potentially dangerous operations.",
          "",
          "5. **All commands are logged in the audit trail.**",
          "   Use \`ssh.audit_log\` to review execution history.",
          "",
          mode === "restricted"
            ? "**RESTRICTED MODE:** Only commands in the allowlist are permitted."
            : mode === "read_only"
              ? "**READ-ONLY MODE:** Only read-only commands + custom allowlist are permitted."
              : "**FULL MODE:** All non-blocked commands are permitted.",
        ].join("\n"),
      )

      systemInjected = true
    },

    // ═══════════════════════════════════════════════════════════════
    // Permission handling
    // ═══════════════════════════════════════════════════════════════
    "permission.ask": async (input, output) => {
      const pattern = typeof input.pattern === "string" ? input.pattern : ""

      // Auto-approve read-only operations
      if (
        pattern.includes("ssh.list_sessions") ||
        pattern.includes("ssh.check_command") ||
        pattern.includes("ssh.audit_log")
      ) {
        output.status = "allow"
        return
      }

      // For risky SSH commands: always ask (never auto-allow)
      // This ensures the user is prompted every time for risky operations
      if (pattern.includes("ssh.exec.risky") || pattern.includes("ssh.exec_batch.risky")) {
        output.status = "ask"
        return
      }

      // For safe SSH operations: allow with user confirmation
      // (the ctx.ask already showed the prompt)
      if (
        pattern.includes("ssh.connect") ||
        pattern.includes("ssh.disconnect") ||
        pattern.includes("ssh.exec") ||
        pattern.includes("ssh.exec_batch") ||
        pattern.includes("ssh.upload") ||
        pattern.includes("ssh.download") ||
        pattern.includes("ssh.security_policy")
      ) {
        // Let the user decide (the prompt is shown)
        output.status = "ask"
        return
      }
    },

    // ═══════════════════════════════════════════════════════════════
    // Pre-execution validation (additional safety net)
    // ═══════════════════════════════════════════════════════════════
    "tool.execute.before": async (input, output) => {
      // Only intercept ssh.exec calls
      if (input.tool !== "ssh.exec" && input.tool !== "ssh.exec_batch") return

      const args = output.args as Record<string, unknown>
      const command = args.command as string | undefined

      if (!command) return

      // Final safety check: validate the command one more time
      // Merge the config `allowlist` with the per-project policy allowlist.
      const customAllowlist = getEffectiveCustomAllowlist(projectDir, extraAllowlist)
      const validation = validateCommand(command, mode, extraBlocklist, customAllowlist)

      if (validation.level === "destructive") {
        throw new Error(
          [
            `🚫 DESTRUCTIVE COMMAND BLOCKED: ${command}`,
            "",
            `Reason: ${validation.reason}`,
            `Rule: ${validation.matched_rule}`,
            "",
            "This command is permanently blocked and cannot be executed.",
          ].join("\n"),
        )
      }

      if (validation.level === "not_in_allowlist") {
        throw new Error(
          [
            `🔒 COMMAND NOT ALLOWED: ${command}`,
            "",
            `Reason: ${validation.reason}`,
            "",
            "This command is not permitted in the current security mode.",
          ].join("\n"),
        )
      }
    },

    // ═══════════════════════════════════════════════════════════════
    // Post-execution metadata
    // ═══════════════════════════════════════════════════════════════
    "tool.execute.after": async (input, output) => {
      if (!input.tool.startsWith("ssh.")) return

      const timestamp = new Date().toISOString()
      if (output.metadata) {
        output.metadata.ssh_plugin = true
        output.metadata.ssh_timestamp = timestamp
      }
    },

    // ═══════════════════════════════════════════════════════════════
    // Cleanup on dispose
    // ═══════════════════════════════════════════════════════════════
    dispose: async () => {
      systemInjected = false
      // Session cleanup is handled by the manager
    },
  }
}
