import { Plugin } from "@opencode/plugin"
import { validateCommand } from "./security/validator.js"
import { getEffectiveCustomAllowlist } from "./security/policy.js"
import { PLUGIN_VERSION } from "./version.js"
import type { SecurityMode } from "./config/schema.js"

export interface SshHookOptions {
  mode?: SecurityMode
  extraBlocklist?: string[]
  extraAllowlist?: string[]
  projectDir?: string
}

/**
 * Permission actions declared by the SSH tools, mapped to a decision.
 *
 * SDK v2 replaced the v1 `permission.ask` hook and the per-call
 * `ctx.ask()` call: a tool now declares one action in `options.permission`
 * and this table owns the decision. Read-only operations are allowed;
 * anything that reaches a remote host or mutates the policy asks every
 * time, because the plugin no longer offers an "allow always" shortcut.
 */
const READ_ONLY_ACTIONS = new Set([
  "ssh.list_sessions",
  "ssh.check_command",
  "ssh.audit_log",
  "ssh.security_policy",
])

function isSshAction(action: string): boolean {
  return action === "ssh" || action.startsWith("ssh.")
}

function systemPrompt(mode: SecurityMode): string {
  return [
    "## SSH Access Plugin (opencode-ssh)",
    `**Version:** ${PLUGIN_VERSION}`,
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
    "- `ssh.security_policy` — View the current security policy",
    "- `ssh.security_policy_modify` — Add/remove blocklist or allowlist patterns",
    "- `ssh.audit_log` — View command execution audit trail",
    "",
    "### Security Rules",
    `**Mode:** ${mode}`,
    "",
    "1. **Destructive commands are BLOCKED with no exceptions.**",
    "   Commands like \`rm -rf /\`, \`mkfs\`, \`dd\`, fork bombs, etc.",
    "   are permanently blocked and cannot be overridden.",
    "",
    "2. **Every remote operation requires your approval.**",
    "   Connecting, executing, uploading, downloading and changing the",
    "   security policy all prompt you each time. Never work around the prompt.",
    "",
    "3. **NEVER store credentials in chat messages.**",
    "   Use \`ssh.connect\` with key-based authentication when possible.",
    "",
    "4. **Security policy changes are ALWAYS user-confirmed.**",
    "   Adding/removing allowlist or blocklist patterns via",
    "   \`ssh.security_policy_modify\` requires explicit user approval every",
    "   single time. Never bypass it.",
    "",
    "5. **Always use \`ssh.check_command\` to preview command safety**",
    "   before running potentially dangerous operations.",
    "",
    "6. **All commands are logged in the audit trail.**",
    "   Use \`ssh.audit_log\` to review execution history.",
    "",
    mode === "restricted"
      ? "**RESTRICTED MODE:** Only commands in the allowlist are permitted."
      : mode === "read_only"
        ? "**READ-ONLY MODE:** Only read-only commands + custom allowlist are permitted."
        : "**FULL MODE:** All non-blocked commands are permitted.",
  ].join("\n")
}

/**
 * Register the SSH plugin hooks on the SDK v2 domain APIs.
 *
 * Hooks behavior:
 * - session "context": Injects SSH availability info into the system prompt
 * - permission "evaluate": Decides allow/ask/deny for every SSH action
 * - tool "execute.before": Pre-execution validation (additional safety net)
 * - tool "execute.after": Post-execution audit metadata
 *
 * Returns the disposal functions, in registration order, so the plugin can
 * release them from the cleanup returned by `setup`.
 */
export async function registerSshHooks(
  ctx: Plugin.Context,
  options: SshHookOptions = {},
): Promise<Array<() => Promise<void>>> {
  const mode: SecurityMode = options.mode ?? "full"
  const extraBlocklist = options.extraBlocklist ?? []
  const extraAllowlist = options.extraAllowlist ?? []
  const projectDir = options.projectDir ?? ""

  const disposals: Array<() => Promise<void>> = []
  const track = async <T extends { dispose(): Promise<void> }>(registration: Promise<T>) => {
    disposals.push(() => registration.then((r) => r.dispose()))
  }

  // ═══════════════════════════════════════════════════════════════
  // System prompt injection (once per plugin instance)
  // ═══════════════════════════════════════════════════════════════
  let systemInjected = false
  await track(
    ctx.session.hook("context", (event) => {
      if (systemInjected) return
      systemInjected = true
      event.system.push({ type: "text", text: systemPrompt(mode) })
    }),
  )

  // ═══════════════════════════════════════════════════════════════
  // Permission evaluation
  //
  // Security policy MUTATIONS (add/remove allowlist or blocklist) are
  // NEVER auto-approved. The user must explicitly confirm/deny every
  // single change, regardless of any global/per-tool permission rules.
  // ═══════════════════════════════════════════════════════════════
  await track(
    ctx.permission.hook("evaluate", (event) => {
      if (!isSshAction(event.action)) return
      event.effect = READ_ONLY_ACTIONS.has(event.action) ? "allow" : "ask"
    }),
  )

  // ═══════════════════════════════════════════════════════════════
  // Pre-execution validation (additional safety net)
  // ═══════════════════════════════════════════════════════════════
  await track(
    ctx.tool.hook("execute.before", (event) => {
      if (event.tool !== "ssh.exec" && event.tool !== "ssh.exec_batch") return

      const args = event.input as { command?: string }
      const command = args?.command
      if (typeof command !== "string" || !command) return

      // Final safety check: validate the command one more time.
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
    }),
  )

  // ═══════════════════════════════════════════════════════════════
  // Post-execution metadata
  // ═══════════════════════════════════════════════════════════════
  await track(
    ctx.tool.hook("execute.after", (event) => {
      if (!isSshAction(event.tool)) return
      if (event.status !== "completed") return

      const metadata = event.result.metadata ?? {}
      event.result = {
        ...event.result,
        metadata: {
          ...metadata,
          ssh_plugin: true,
          ssh_timestamp: new Date().toISOString(),
        },
      }
    }),
  )

  return disposals
}
