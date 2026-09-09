import { tool, type ToolDefinition } from "@opencode-ai/plugin"
import { SshSessionManager } from "./ssh/manager.js"
import { executeCommand, type ExecResult } from "./ssh/executor.js"
import { validateCommand, formatValidationResult } from "./security/validator.js"
import { getPolicy, addBlocklistPattern, removeBlocklistPattern, addAllowlistPattern, removeAllowlistPattern, formatPolicy } from "./security/policy.js"
import { readAuditLog, formatAuditLog, getAuditStats } from "./ssh/audit.js"
import { sanitizeHost, sanitizeUsername, sanitizePath } from "./ssh/sanitizer.js"
import {
  loadSshConfig,
  findHostConfig,
  getAutoConnectHosts,
  expandHomePath,
  parseProxyJump,
  type SshConfigEntry,
} from "./ssh/config.js"
import { RateLimiter } from "./ssh/ratelimit.js"
import {
  formatExecResult,
  formatSessionList,
  formatConnectResult,
  formatDisconnectResult,
  formatCheckResult,
  formatSecurityPolicy,
} from "./display/formatter.js"
import type { SecurityMode } from "./config/schema.js"
import type { SshConnectionConfig } from "./ssh/connection.js"

interface ConnectInput {
  host: string
  port?: number
  username?: string
  auth_method?: "password" | "key"
  password?: string
  key_path?: string
  passphrase?: string
  alias?: string
}

/**
 * Build an ssh.connect connection config, applying defaults from the
 * ~/.ssh/config file (alias → HostName, User, Port, IdentityFile,
 * ProxyJump, ProxyCommand).
 */
function resolveHostConfig(
  args: ConnectInput,
  opts: { sshConfigPath?: string; strictHostKey?: boolean; knownHostsPath?: string; autoReconnect?: boolean } = {},
): { config: SshConnectionConfig; displayHost: string; resolvedFrom?: string; sshConfigExists: boolean } {
  const loaded = loadSshConfig(opts.sshConfigPath)
  const entry: SshConfigEntry | undefined = loaded.entries.length
    ? findHostConfig(loaded.entries, args.host)
    : undefined

  const displayHost = args.host
  const realHost = entry?.hostName && entry.hostName !== args.host ? entry.hostName : args.host
  const port = args.port || entry?.port || 22
  const username = args.username || entry?.user
  const authMethod = args.auth_method || (entry?.identityFile ? "key" : "password")
  const keyPath = args.key_path || (entry?.identityFile ? expandHomePath(entry.identityFile) : undefined)
  const alias = args.alias || (realHost !== args.host ? args.host : undefined)

  // ProxyJump / ProxyCommand from the ssh config
  let proxy: SshConnectionConfig["proxy"]
  if (entry?.proxyCommand) {
    proxy = { command: entry.proxyCommand }
  } else if (entry?.proxyJump) {
    proxy = {
      jumps: parseProxyJump(entry.proxyJump, username, keyPath),
    }
  }

  return {
    config: {
      host: realHost,
      port,
      username,
      authMethod,
      password: args.password,
      keyPath,
      passphrase: args.passphrase,
      alias,
      timeout: 10000,
      strictHostKey: opts.strictHostKey,
      knownHostsPath: opts.knownHostsPath,
      sshConfigPath: opts.sshConfigPath,
      proxy,
      autoReconnect: opts.autoReconnect ?? true,
    },
    displayHost,
    resolvedFrom: entry ? loaded.path : undefined,
    sshConfigExists: loaded.exists,
  }
}

/** Wait helper for auto-connect retries. */
function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms))
}

/**
 * Auto-connect to every ssh config host that resolves to a real HostName.
 * Best-effort with retry/backoff: each host is attempted up to MAX_ATTEMPTS
 * times with increasing delays, and individual failures are swallowed so
 * the plugin always loads.
 */
async function startAutoConnect(
  manager: SshSessionManager,
  sshConfigPath?: string,
): Promise<void> {
  const MAX_ATTEMPTS = 3
  const hosts = getAutoConnectHosts(sshConfigPath)
  for (const host of hosts) {
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      try {
        await manager.createSession({
          host: host.hostName,
          port: host.port || 22,
          username: host.user || process.env.USER || process.env.USERNAME || "root",
          authMethod: host.identityFile ? "key" : "password",
          keyPath: host.identityFile ? expandHomePath(host.identityFile) : undefined,
          alias: host.alias,
          timeout: 10000,
        })
        break // connected
      } catch {
        if (attempt < MAX_ATTEMPTS) {
          await sleep(1000 * attempt) // backoff: 1s, 2s
        }
      }
    }
  }
}

/**
 * Create all SSH tools for the plugin.
 */
export function createSshTools(
  mode: SecurityMode = "full",
  maxSessions: number = 5,
  defaultTimeout: number = 30,
  extraBlocklist: string[] = [],
  sshConfigPath?: string,
  autoConnect: boolean = false,
  opts: { strictHostKey?: boolean; knownHostsPath?: string; rateLimitPerMinute?: number; cooldownSeconds?: number; autoReconnect?: boolean } = {},
): Record<string, ToolDefinition> {
  const sessionManager = new SshSessionManager({ maxSessions })
  const rateLimiter = new RateLimiter({
    maxPerMinute: opts.rateLimitPerMinute ?? 120,
    cooldownSeconds: opts.cooldownSeconds ?? 0,
  })
  const sshOpts = {
    sshConfigPath,
    strictHostKey: opts.strictHostKey ?? false,
    knownHostsPath: opts.knownHostsPath,
    autoReconnect: opts.autoReconnect ?? true,
  }

  if (autoConnect) {
    // Best-effort auto-connect to hosts defined in the ssh config with
    // retry/backoff. Non-blocking: failures are swallowed and do not
    // prevent the plugin from loading.
    void startAutoConnect(sessionManager, sshConfigPath)
  }
  return {
    // ═══════════════════════════════════════════════════════════════
    // ssh.connect — Establish SSH connection
    // ═══════════════════════════════════════════════════════════════
    "ssh.connect": tool({
      description:
        "Establish an SSH connection to a remote server. Returns a session_id for use with other ssh.* tools. " +
        "Supports password and key-based authentication. Credentials are never stored in logs or output. " +
        "If ssh_config_path is set, host aliases from the ssh config are resolved and their " +
        "User/Port/IdentityFile defaults are applied automatically.",
      args: {
        host: tool.schema.string().describe("Remote server hostname, IP, or ssh config alias"),
        port: tool.schema.number().optional().describe("SSH port (default: 22, or port from ssh config)"),
        username: tool.schema.string().optional().describe("SSH username (default: from ssh config)"),
        auth_method: tool.schema.enum(["password", "key"]).optional().describe("Authentication method (default: key if an identity file is configured, else password)"),
        password: tool.schema.string().optional().describe("Password (only for password auth)"),
        key_path: tool.schema.string().optional().describe("Path to private key file (default: identity file from ssh config, else ~/.ssh/id_rsa)"),
        passphrase: tool.schema.string().optional().describe("Passphrase for the private key"),
        alias: tool.schema.string().optional().describe("Friendly name for this session"),
      },
      async execute(args, ctx) {
        // ── Resolve defaults from the ssh config (alias, user, port, identity, proxy) ──
        const { config: resolvedConfig, displayHost, resolvedFrom, sshConfigExists } = resolveHostConfig(args, sshOpts)

        // ── Input validation ──
        const hostCheck = sanitizeHost(displayHost)
        if (!hostCheck.clean) {
          return `❌ Invalid host: ${hostCheck.reason}`
        }

        if (resolvedConfig.username) {
          const userCheck = sanitizeUsername(resolvedConfig.username)
          if (!userCheck.clean) {
            return `❌ Invalid username: ${userCheck.reason}`
          }
        } else {
          return "❌ A username is required. Provide one or add a User directive in your ssh config."
        }

        const displayPort = args.port || resolvedConfig.port || 22

        // ── Ask for permission ──
        await ctx.ask({
          permission: "ssh.connect",
          patterns: [`${resolvedConfig.username}@${displayHost}:${displayPort}`],
          always: [`${resolvedConfig.username}@${displayHost}:${displayPort}`],
          metadata: {
            host: displayHost,
            resolved_host: resolvedConfig.host !== displayHost ? resolvedConfig.host : undefined,
            port: displayPort,
            username: resolvedConfig.username,
            auth_method: resolvedConfig.authMethod,
            alias: args.alias,
            ssh_config: resolvedFrom || undefined,
          },
        })

        // ── Connect ──
        const manager = sessionManager

        try {
          const sessionId = await manager.createSession(resolvedConfig)
          const lines = [
            formatConnectResult(
              sessionId,
              displayHost,
              displayPort,
              resolvedConfig.username!,
              args.alias,
            ),
          ]
          if (resolvedConfig.host !== displayHost) {
            lines.push(`> Resolved via ssh config: ${displayHost} → ${resolvedConfig.host}`)
          }
          if (sshConfigPath && !sshConfigExists) {
            lines.push(`> ⚠️ Configured ssh config file not found: \`${sshConfigPath}\` — defaults were not applied.`)
          }
          if (resolvedConfig.proxy) {
            lines.push(`> 🛤️ Connecting through proxy (${resolvedConfig.proxy.jumps?.length ?? 0} hop(s))`)
          }
          return lines.join("\n")
        } catch (error) {
          const msg = error instanceof Error ? error.message : String(error)
          return [
            `## ❌ SSH Connection Failed`,
            "",
            `**Host:** ${resolvedConfig.username}@${displayHost}:${displayPort}`,
            `**Error:** ${msg}`,
            "",
            "Troubleshooting:",
            "- Verify the host is reachable",
            "- Check that the username is correct",
            "- Ensure SSH is running on the remote host",
            "- Verify your credentials or key file",
          ].join("\n")
        }
      },
    }),

    // ═══════════════════════════════════════════════════════════════
    // ssh.disconnect — Close SSH session
    // ═══════════════════════════════════════════════════════════════
    "ssh.disconnect": tool({
      description: "Close an active SSH session and free resources.",
      args: {
        session_id: tool.schema.string().describe("Session ID or alias to disconnect"),
      },
      async execute(args, ctx) {
        await ctx.ask({
          permission: "ssh.disconnect",
          patterns: [args.session_id],
          always: [],
          metadata: { session_id: args.session_id },
        })

        const manager = sessionManager
        const closed = await manager.closeSession(args.session_id)

        if (!closed) {
          return `Session \`${args.session_id}\` not found or already closed.`
        }

        return formatDisconnectResult(args.session_id)
      },
    }),

    // ═══════════════════════════════════════════════════════════════
    // ssh.list_sessions — List active SSH sessions
    // ═══════════════════════════════════════════════════════════════
    "ssh.list_sessions": tool({
      description: "List all active SSH sessions with their status, host, and uptime.",
      args: {},
      async execute(_args, _ctx) {
        const manager = sessionManager
        const sessions = manager.listSessions()
        return formatSessionList(sessions)
      },
    }),

    // ═══════════════════════════════════════════════════════════════
    // ssh.exec — Execute command on remote server
    // ═══════════════════════════════════════════════════════════════
    "ssh.exec": tool({
      description:
        "Execute a command on a remote server via SSH. " +
        "Destructive commands (rm -rf /, mkfs, etc.) are automatically blocked with no exceptions. " +
        "Risky commands (DROP TABLE, sudo su, systemctl stop, etc.) require your explicit approval every time. " +
        "All output is streamed and displayed in real-time.",
      args: {
        session_id: tool.schema.string().describe("Session ID or alias"),
        command: tool.schema.string().describe("Command to execute on the remote server"),
        cwd: tool.schema.string().optional().describe("Working directory for the command"),
        timeout: tool.schema.number().optional().describe("Timeout in seconds (default: 30)"),
        sudo: tool.schema.boolean().optional().describe("Run command with sudo"),
      },
      async execute(args, ctx) {
        // ── Validate session ──
        const manager = sessionManager
        const connection = manager.getSession(args.session_id)
        if (!connection) {
          return `❌ Session \`${args.session_id}\` not found. Use ssh.list_sessions to see active sessions.`
        }

        // ── Rate limit per host ──
        const hostKey = connection.config.alias || connection.config.host
        const rateCheck = rateLimiter.check(hostKey)
        if (!rateCheck.allowed) {
          return [
            `## ⏳ Command Rate Limited`,
            "",
            `**Host:** \`${hostKey}\``,
            `**Reason:** ${rateCheck.reason}`,
            rateCheck.retryAfterSeconds ? `**Retry after:** ~${rateCheck.retryAfterSeconds}s` : "",
          ]
            .filter(Boolean)
            .join("\n")
        }

        // ── Validate command against blocklist BEFORE asking for permission ──
        const validation = validateCommand(args.command, mode, extraBlocklist)

        // DESTRUCTIVE: 100% blocked, no permission prompt, no override
        if (validation.level === "destructive") {
          return [
            "## 🚫 Command Blocked (Destructive)",
            "",
            `**Command:** \`${args.command}\``,
            `**Reason:** ${validation.reason}`,
            `**Rule:** ${validation.matched_rule}`,
            "",
            "This command is **permanently blocked** for safety.",
            "Destructive commands cannot be executed under any circumstances.",
          ].join("\n")
        }

        // NOT IN ALLOWLIST: blocked in restricted/read_only mode
        if (validation.level === "not_in_allowlist") {
          return [
            "## 🔒 Command Not Allowed",
            "",
            `**Command:** \`${args.command}\``,
            `**Reason:** ${validation.reason}`,
            "",
            "This command is not in the allowlist for the current security mode.",
            "Use ssh.security_policy to view or modify the policy.",
          ].join("\n")
        }

        // RISKY: Ask for permission EVERY TIME (no "always" pattern)
        if (validation.level === "risky") {
          await ctx.ask({
            permission: "ssh.exec.risky",
            patterns: [args.command],
            always: [], // Empty = ask EVERY time
            metadata: {
              session_id: args.session_id,
              command: args.command,
              host: connection.config.host,
              username: connection.config.username,
              reason: validation.reason,
              rule: validation.matched_rule,
            },
          })
        } else {
          // Safe command: ask once with "always" pattern
          await ctx.ask({
            permission: "ssh.exec",
            patterns: [args.command],
            always: [args.command],
            metadata: {
              session_id: args.session_id,
              command: args.command,
              host: connection.config.host,
              username: connection.config.username,
            },
          })
        }

        // ── Execute ──
        let result: ExecResult
        try {
          result = await executeCommand(
            connection,
            args.command,
            mode,
            extraBlocklist,
            args.session_id,
            {
              cwd: args.cwd,
              timeout: args.timeout || defaultTimeout,
              sudo: args.sudo,
            },
            ctx.directory,
          )
        } finally {
          rateLimiter.record(hostKey, true)
        }

        return formatExecResult(result)
      },
    }),

    // ═══════════════════════════════════════════════════════════════
    // ssh.exec_batch — Execute multiple commands in sequence
    // ═══════════════════════════════════════════════════════════════
    "ssh.exec_batch": tool({
      description:
        "Execute multiple commands in sequence on a remote server. " +
        "Each command is validated against the security policy. " +
        "If stop_on_error is true, execution stops on the first failed command.",
      args: {
        session_id: tool.schema.string().describe("Session ID or alias"),
        commands: tool.schema.string().describe("Commands separated by newlines"),
        stop_on_error: tool.schema.boolean().optional().describe("Stop if a command fails (default: true)"),
        cwd: tool.schema.string().optional().describe("Working directory"),
        timeout: tool.schema.number().optional().describe("Timeout per command in seconds"),
      },
      async execute(args, ctx) {
        const manager = sessionManager
        const connection = manager.getSession(args.session_id)
        if (!connection) {
          return `❌ Session \`${args.session_id}\` not found.`
        }

        // ── Rate limit per host ──
        const batchHostKey = connection.config.alias || connection.config.host
        const batchRateCheck = rateLimiter.check(batchHostKey)
        if (!batchRateCheck.allowed) {
          return [
            `## ⏳ Batch Rate Limited`,
            "",
            `**Host:** \`${batchHostKey}\``,
            `**Reason:** ${batchRateCheck.reason}`,
            batchRateCheck.retryAfterSeconds ? `**Retry after:** ~${batchRateCheck.retryAfterSeconds}s` : "",
          ]
            .filter(Boolean)
            .join("\n")
        }

        const commands = args.commands.split("\n").filter((c) => c.trim())
        if (commands.length === 0) {
          return "No commands to execute."
        }

        // ── Validate all commands first ──
        const validations: Array<{ command: string; validation: ReturnType<typeof validateCommand> }> = []
        for (const cmd of commands) {
          const v = validateCommand(cmd.trim(), mode, extraBlocklist)
          validations.push({ command: cmd.trim(), validation: v })
        }

        // Check for destructive commands
        const destructive = validations.filter((v) => v.validation.level === "destructive")
        if (destructive.length > 0) {
          const lines = ["## 🚫 Batch Blocked (Destructive Commands Found)", ""]
          for (const d of destructive) {
            lines.push(`- \`${d.command}\`: ${d.validation.reason}`)
          }
          lines.push("")
          lines.push("Destructive commands cannot be executed. Remove them and try again.")
          return lines.join("\n")
        }

        // Check for risky commands and ask permission
        const risky = validations.filter((v) => v.validation.level === "risky")
        if (risky.length > 0) {
          await ctx.ask({
            permission: "ssh.exec_batch.risky",
            patterns: risky.map((r) => r.command),
            always: [], // Ask EVERY time for risky batch commands
            metadata: {
              session_id: args.session_id,
              commands: risky.map((r) => ({
                command: r.command,
                reason: r.validation.reason,
                rule: r.validation.matched_rule,
              })),
              host: connection.config.host,
            },
          })
        } else {
          // Safe batch
          await ctx.ask({
            permission: "ssh.exec_batch",
            patterns: commands.map((c) => c.trim()),
            always: [],
            metadata: {
              session_id: args.session_id,
              command_count: commands.length,
              host: connection.config.host,
            },
          })
        }

        // ── Execute commands sequentially ──
        const results: ExecResult[] = []
        const stopOnError = args.stop_on_error !== false

        for (const cmd of commands) {
          let result: ExecResult
          try {
            result = await executeCommand(
              connection,
              cmd.trim(),
              mode,
              extraBlocklist,
              args.session_id,
              {
                cwd: args.cwd,
                timeout: args.timeout || defaultTimeout,
              },
              ctx.directory,
            )
          } finally {
            rateLimiter.record(batchHostKey, true)
          }

          results.push(result)

          if (stopOnError && result.exitCode !== 0) {
            break
          }
        }

        // ── Format batch results ──
        const lines = [`## SSH Batch Results (${results.length}/${commands.length} executed)\n`]
        for (let i = 0; i < results.length; i++) {
          const r = results[i]
          const icon = r.exitCode === 0 ? "✅" : "❌"
          lines.push(`${icon} **${i + 1}.** \`${r.command}\` — exit: ${r.exitCode}`)
          if (r.stdout.trim()) {
            lines.push(`   ${r.stdout.trim().split("\n")[0]}`)
          }
          if (r.stderr.trim()) {
            lines.push(`   stderr: ${r.stderr.trim().split("\n")[0]}`)
          }
          lines.push("")
        }

        return lines.join("\n")
      },
    }),

    // ═══════════════════════════════════════════════════════════════
    // ssh.upload — Upload file via SCP
    // ═══════════════════════════════════════════════════════════════
    "ssh.upload": tool({
      description: "Upload a local file to the remote server via SCP/SFTP.",
      args: {
        session_id: tool.schema.string().describe("Session ID or alias"),
        local_path: tool.schema.string().describe("Local file path"),
        remote_path: tool.schema.string().describe("Remote destination path"),
      },
      async execute(args, ctx) {
        const manager = sessionManager
        const connection = manager.getSession(args.session_id)
        if (!connection) {
          return `❌ Session \`${args.session_id}\` not found.`
        }

        // Validate paths
        const pathCheck = sanitizePath(args.local_path)
        if (!pathCheck.clean) return `❌ Invalid local path: ${pathCheck.reason}`

        const remoteCheck = sanitizePath(args.remote_path)
        if (!remoteCheck.clean) return `❌ Invalid remote path: ${remoteCheck.reason}`

        await ctx.ask({
          permission: "ssh.upload",
          patterns: [args.local_path, args.remote_path],
          always: [],
          metadata: {
            session_id: args.session_id,
            local_path: args.local_path,
            remote_path: args.remote_path,
            host: connection.config.host,
          },
        })

        try {
          const sftp = await connection.sftp()
          await new Promise<void>((resolve, reject) => {
            sftp.fastPut(args.local_path, args.remote_path, (err: Error | null) => {
              if (err) reject(err)
              else resolve()
            })
          })

          return [
            "## 📤 File Uploaded",
            "",
            `- **Local:** \`${args.local_path}\``,
            `- **Remote:** \`${args.remote_path}\``,
            `- **Session:** \`${args.session_id}\``,
          ].join("\n")
        } catch (error) {
          const msg = error instanceof Error ? error.message : String(error)
          return `❌ Upload failed: ${msg}`
        }
      },
    }),

    // ═══════════════════════════════════════════════════════════════
    // ssh.download — Download file via SCP
    // ═══════════════════════════════════════════════════════════════
    "ssh.download": tool({
      description: "Download a file from the remote server to local via SCP/SFTP.",
      args: {
        session_id: tool.schema.string().describe("Session ID or alias"),
        remote_path: tool.schema.string().describe("Remote file path"),
        local_path: tool.schema.string().describe("Local destination path"),
      },
      async execute(args, ctx) {
        const manager = sessionManager
        const connection = manager.getSession(args.session_id)
        if (!connection) {
          return `❌ Session \`${args.session_id}\` not found.`
        }

        const pathCheck = sanitizePath(args.local_path)
        if (!pathCheck.clean) return `❌ Invalid local path: ${pathCheck.reason}`

        const remoteCheck = sanitizePath(args.remote_path)
        if (!remoteCheck.clean) return `❌ Invalid remote path: ${remoteCheck.reason}`

        await ctx.ask({
          permission: "ssh.download",
          patterns: [args.remote_path, args.local_path],
          always: [],
          metadata: {
            session_id: args.session_id,
            remote_path: args.remote_path,
            local_path: args.local_path,
            host: connection.config.host,
          },
        })

        try {
          const sftp = await connection.sftp()
          await new Promise<void>((resolve, reject) => {
            sftp.fastGet(args.remote_path, args.local_path, (err: Error | null) => {
              if (err) reject(err)
              else resolve()
            })
          })

          return [
            "## 📥 File Downloaded",
            "",
            `- **Remote:** \`${args.remote_path}\``,
            `- **Local:** \`${args.local_path}\``,
            `- **Session:** \`${args.session_id}\``,
          ].join("\n")
        } catch (error) {
          const msg = error instanceof Error ? error.message : String(error)
          return `❌ Download failed: ${msg}`
        }
      },
    }),

    // ═══════════════════════════════════════════════════════════════
    // ssh.check_command — Validate command safety (dry-run)
    // ═══════════════════════════════════════════════════════════════
    "ssh.check_command": tool({
      description:
        "Check if a command is safe to execute without actually running it. " +
        "Returns the safety level, any matched blocklist rules, and suggestions. " +
        "Use this to preview command safety before execution.",
      args: {
        command: tool.schema.string().describe("Command to validate"),
      },
      async execute(args, _ctx) {
        const validation = validateCommand(args.command, mode, extraBlocklist)
        return formatCheckResult(args.command, validation)
      },
    }),

    // ═══════════════════════════════════════════════════════════════
    // ssh.security_policy — View/manage security policy
    // ═══════════════════════════════════════════════════════════════
    "ssh.security_policy": tool({
      description:
        "View or modify the SSH security policy. " +
        "Can add/remove patterns from the blocklist or allowlist, " +
        "and view the current security mode.",
      args: {
        action: tool.schema
          .enum(["view", "add_blocklist", "remove_blocklist", "add_allowlist", "remove_allowlist"])
          .describe("Action to perform"),
        pattern: tool.schema.string().optional().describe("Regex pattern to add/remove"),
      },
      async execute(args, ctx) {
        if (!args.pattern && args.action !== "view") {
          return "❌ A pattern is required for add/remove actions."
        }

        if (args.pattern) {
          // Validate regex
          try {
            new RegExp(args.pattern)
          } catch {
            return `❌ Invalid regex pattern: \`${args.pattern}\``
          }
        }

        await ctx.ask({
          permission: "ssh.security_policy",
          patterns: [`${args.action}: ${args.pattern || ""}`],
          always: [],
          metadata: {
            action: args.action,
            pattern: args.pattern,
          },
        })

        switch (args.action) {
          case "view": {
            const policy = getPolicy(ctx.directory, mode)
            return formatSecurityPolicy(policy)
          }
          case "add_blocklist": {
            const policy = addBlocklistPattern(ctx.directory, args.pattern!)
            return [
              "## ✅ Blocklist Pattern Added",
              "",
              `Added: \`${args.pattern}\``,
              "",
              formatSecurityPolicy(policy),
            ].join("\n")
          }
          case "remove_blocklist": {
            const policy = removeBlocklistPattern(ctx.directory, args.pattern!)
            return [
              "## ✅ Blocklist Pattern Removed",
              "",
              `Removed: \`${args.pattern}\``,
              "",
              formatSecurityPolicy(policy),
            ].join("\n")
          }
          case "add_allowlist": {
            const policy = addAllowlistPattern(ctx.directory, args.pattern!)
            return [
              "## ✅ Allowlist Pattern Added",
              "",
              `Added: \`${args.pattern}\``,
              "",
              formatSecurityPolicy(policy),
            ].join("\n")
          }
          case "remove_allowlist": {
            const policy = removeAllowlistPattern(ctx.directory, args.pattern!)
            return [
              "## ✅ Allowlist Pattern Removed",
              "",
              `Removed: \`${args.pattern}\``,
              "",
              formatSecurityPolicy(policy),
            ].join("\n")
          }
          default:
            return `❌ Unknown action: ${args.action}`
        }
      },
    }),

    // ═══════════════════════════════════════════════════════════════
    // ssh.audit_log — View command audit trail
    // ═══════════════════════════════════════════════════════════════
    "ssh.audit_log": tool({
      description:
        "View the SSH command audit log. Shows all executed, blocked, and approved commands " +
        "with timestamps, results, and details. Supports filtering by session and command.",
      args: {
        limit: tool.schema.number().optional().describe("Maximum entries to show (default: 20)"),
        session_id: tool.schema.string().optional().describe("Filter by session ID"),
        command_filter: tool.schema.string().optional().describe("Filter by command text"),
      },
      async execute(args, ctx) {
        const entries = readAuditLog(ctx.directory, {
          limit: args.limit || 20,
          sessionId: args.session_id,
          commandFilter: args.command_filter,
        })

        if (entries.length === 0) {
          // Show stats even if no entries match
          const stats = getAuditStats(ctx.directory)
          if (stats.total === 0) {
            return "📋 No audit entries yet. Commands executed via ssh.exec will be logged here."
          }

          return [
            `## SSH Audit Stats`,
            "",
            `- **Total:** ${stats.total}`,
            `- **Success:** ${stats.success}`,
            `- **Blocked:** ${stats.blocked}`,
            `- **Approved (risky):** ${stats.approved}`,
            `- **Errors:** ${stats.error}`,
            "",
            "No entries match the current filters.",
          ].join("\n")
        }

        // Show stats header
        const stats = getAuditStats(ctx.directory)
        const header = [
          `### Stats: ${stats.total} total | ${stats.success} ✅ | ${stats.blocked} 🚫 | ${stats.approved} ⚠️ | ${stats.error} ❌`,
          "",
        ].join("\n")

        return header + formatAuditLog(entries)
      },
    }),
  }
}
