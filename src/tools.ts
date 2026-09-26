import type { ToolContext } from "@opencode/plugin/promise/tool"
import { SshSessionManager } from "./ssh/manager.js"
import { executeCommand, type ExecResult } from "./ssh/executor.js"
import { validateCommand, formatValidationResult } from "./security/validator.js"
import {
  getPolicy,
  getEffectiveCustomAllowlist,
  addBlocklistPattern,
  removeBlocklistPattern,
  addAllowlistPattern,
  removeAllowlistPattern,
} from "./security/policy.js"
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

// ═══════════════════════════════════════════════════════════════════
// Tool definition helpers
//
// SDK v2 tools declare a JSON Schema `input` instead of the v1 Zod args
// map, and return a `Tool.Result` instead of a bare string. The specs
// below describe flat argument shapes; the mapping to JSON Schema and to
// a statically typed `args` object happens in one place so every tool
// body keeps the exact same shape as before.
// ═══════════════════════════════════════════════════════════════════

export type ToolOutput = { content: string }

type PropSpec = { description: string } & (
  | { kind: "string"; optional: false }
  | { kind: "string"; optional: true }
  | { kind: "number"; optional: false }
  | { kind: "number"; optional: true }
  | { kind: "boolean"; optional: false }
  | { kind: "boolean"; optional: true }
  | { kind: "enum"; values: readonly string[]; optional: false }
  | { kind: "enum"; values: readonly string[]; optional: true }
)

type PropValue<P extends PropSpec> = P extends { kind: "number" }
  ? number
  : P extends { kind: "boolean" }
    ? boolean
    : P extends { kind: "enum"; values: infer V extends readonly string[] }
      ? V[number]
      : string

type ArgsOf<S extends Record<string, PropSpec>> = {
  [K in keyof S as S[K]["optional"] extends true ? never : K]: PropValue<S[K]>
} & {
  [K in keyof S as S[K]["optional"] extends true ? K : never]?: PropValue<S[K]>
}

export type SshToolInput = {
  type: "object"
  properties: Record<string, { type: string; enum?: string[]; description?: string }>
  required?: string[]
  additionalProperties: false
}

export type SshToolDefinition<S extends Record<string, PropSpec>> = {
  name: string
  description: string
  input: SshToolInput
  options: { permission: string }
  execute: (args: ArgsOf<S>, context: ToolContext) => Promise<ToolOutput>
}

/** Catalog element type. Each tool keeps its own argument typing; the
 *  heterogeneous array widens it here, at the single catalog boundary. */
export type SshToolCatalogEntry = Omit<SshToolDefinition<any>, "execute"> & {
  execute: (args: any, context: ToolContext) => Promise<ToolOutput>
}

function stringArg(description: string): { kind: "string"; description: string; optional: false }
function stringArg(description: string, optional: true): { kind: "string"; description: string; optional: true }
function stringArg(description: string, optional: boolean): { kind: "string"; description: string; optional: boolean }
function stringArg(description: string, optional = false) {
  return { kind: "string", description, optional }
}

function numberArg(description: string): { kind: "number"; description: string; optional: false }
function numberArg(description: string, optional: true): { kind: "number"; description: string; optional: true }
function numberArg(description: string, optional: boolean): { kind: "number"; description: string; optional: boolean }
function numberArg(description: string, optional = false) {
  return { kind: "number", description, optional }
}

function booleanArg(description: string): { kind: "boolean"; description: string; optional: false }
function booleanArg(description: string, optional: true): { kind: "boolean"; description: string; optional: true }
function booleanArg(description: string, optional: boolean): { kind: "boolean"; description: string; optional: boolean }
function booleanArg(description: string, optional = false) {
  return { kind: "boolean", description, optional }
}

function enumArg<const V extends readonly string[]>(
  values: V,
  description: string,
): { kind: "enum"; values: V; description: string; optional: false }
function enumArg<const V extends readonly string[]>(
  values: V,
  description: string,
  optional: true,
): { kind: "enum"; values: V; description: string; optional: true }
function enumArg<const V extends readonly string[]>(
  values: V,
  description: string,
  optional = false,
) {
  return { kind: "enum", values, description, optional }
}

function toJsonSchema<S extends Record<string, PropSpec>>(shape: S): SshToolInput {
  const properties: SshToolInput["properties"] = {}
  const required: string[] = []
  for (const [name, spec] of Object.entries(shape)) {
    const property =
      spec.kind === "enum"
        ? { type: "string", enum: [...spec.values], description: spec.description }
        : { type: spec.kind, description: spec.description }
    properties[name] = property
    if (!spec.optional) required.push(name)
  }
  return {
    type: "object",
    properties,
    ...(required.length > 0 ? { required } : {}),
    additionalProperties: false,
  }
}

type ToolSpec<S extends Record<string, PropSpec>> = {
  name: string
  description: string
  shape: S
  permission: string
  execute: (args: ArgsOf<S>, context: ToolContext) => Promise<ToolOutput>
}

function defineTool<S extends Record<string, PropSpec>>(
  spec: ToolSpec<S>,
): SshToolDefinition<S> {
  return {
    name: spec.name,
    description: spec.description,
    input: toJsonSchema(spec.shape),
    options: { permission: spec.permission },
    execute: spec.execute,
  }
}

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
 *
 * Every tool declares the permission it needs in `options.permission`; the
 * decision to allow, ask, or deny is owned by the permission hook in
 * hooks.ts. `projectDir` is the plugin instance location and replaces the
 * v1 per-call `ctx.directory`.
 */
export function createSshTools(
  mode: SecurityMode = "full",
  maxSessions: number = 5,
  defaultTimeout: number = 30,
  extraBlocklist: string[] = [],
  extraAllowlist: string[] = [],
  sshConfigPath?: string,
  autoConnect: boolean = false,
  opts: { strictHostKey?: boolean; knownHostsPath?: string; rateLimitPerMinute?: number; cooldownSeconds?: number; autoReconnect?: boolean } = {},
  projectDir: string = "",
): SshToolCatalogEntry[] {
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

  // ═══════════════════════════════════════════════════════════════
  // ssh.connect — Establish SSH connection
  // ═══════════════════════════════════════════════════════════════
  const connectShape = {
    host: stringArg("Remote server hostname, IP, or ssh config alias"),
    port: numberArg("SSH port (default: 22, or port from ssh config)", true),
    username: stringArg("SSH username (default: from ssh config)", true),
    auth_method: enumArg(["password", "key"], "Authentication method (default: key if an identity file is configured, else password)", true),
    password: stringArg("Password (only for password auth)", true),
    key_path: stringArg("Path to private key file (default: identity file from ssh config, else ~/.ssh/id_rsa)", true),
    passphrase: stringArg("Passphrase for the private key", true),
    alias: stringArg("Friendly name for this session", true),
  }

  const disconnectShape = {
    session_id: stringArg("Session ID or alias to disconnect"),
  }

  const execShape = {
    session_id: stringArg("Session ID or alias"),
    command: stringArg("Command to execute on the remote server"),
    cwd: stringArg("Working directory for the command", true),
    timeout: numberArg("Timeout in seconds (default: 30)", true),
    sudo: booleanArg("Run command with sudo", true),
  }

  const execBatchShape = {
    session_id: stringArg("Session ID or alias"),
    commands: stringArg("Commands separated by newlines"),
    stop_on_error: booleanArg("Stop if a command fails (default: true)", true),
    cwd: stringArg("Working directory", true),
    timeout: numberArg("Timeout per command in seconds", true),
  }

  const uploadShape = {
    session_id: stringArg("Session ID or alias"),
    local_path: stringArg("Local file path"),
    remote_path: stringArg("Remote destination path"),
  }

  const downloadShape = {
    session_id: stringArg("Session ID or alias"),
    remote_path: stringArg("Remote file path"),
    local_path: stringArg("Local destination path"),
  }

  const checkCommandShape = {
    command: stringArg("Command to validate"),
  }

  const policyViewShape = {}

  const policyModifyShape = {
    action: enumArg(
      ["add_blocklist", "remove_blocklist", "add_allowlist", "remove_allowlist"],
      "Policy change to perform",
    ),
    pattern: stringArg("Regex pattern to add/remove"),
  }

  const auditLogShape = {
    limit: numberArg("Maximum entries to show (default: 20)", true),
    session_id: stringArg("Filter by session ID", true),
    command_filter: stringArg("Filter by command text", true),
  }

  return [
    defineTool({
      name: "ssh.connect",
      description:
        "Establish an SSH connection to a remote server. Returns a session_id for use with other ssh.* tools. " +
        "Supports password and key-based authentication. Credentials are never stored in logs or output. " +
        "If ssh_config_path is set, host aliases from the ssh config are resolved and their " +
        "User/Port/IdentityFile defaults are applied automatically.",
      shape: connectShape,
      permission: "ssh.connect",
      async execute(args) {
        // ── Resolve defaults from the ssh config (alias, user, port, identity, proxy) ──
        const { config: resolvedConfig, displayHost, resolvedFrom, sshConfigExists } = resolveHostConfig(args, sshOpts)

        // ── Input validation ──
        const hostCheck = sanitizeHost(displayHost)
        if (!hostCheck.clean) {
          return { content: `❌ Invalid host: ${hostCheck.reason}` }
        }

        if (resolvedConfig.username) {
          const userCheck = sanitizeUsername(resolvedConfig.username)
          if (!userCheck.clean) {
            return { content: `❌ Invalid username: ${userCheck.reason}` }
          }
        } else {
          return { content: "❌ A username is required. Provide one or add a User directive in your ssh config." }
        }

        const displayPort = args.port || resolvedConfig.port || 22

        // ── Connect ──
        try {
          const sessionId = await sessionManager.createSession(resolvedConfig)
          const lines = [
            formatConnectResult(sessionId, displayHost, displayPort, resolvedConfig.username!, args.alias),
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
          return { content: lines.join("\n") }
        } catch (error) {
          const msg = error instanceof Error ? error.message : String(error)
          return {
            content: [
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
            ].join("\n"),
          }
        }
      },
    }),

    // ═══════════════════════════════════════════════════════════════
    // ssh.disconnect — Close SSH session
    // ═══════════════════════════════════════════════════════════════
    defineTool({
      name: "ssh.disconnect",
      description: "Close an active SSH session and free resources.",
      shape: disconnectShape,
      permission: "ssh.disconnect",
      async execute(args) {
        const closed = await sessionManager.closeSession(args.session_id)
        if (!closed) {
          return { content: `Session \`${args.session_id}\` not found or already closed.` }
        }
        return { content: formatDisconnectResult(args.session_id) }
      },
    }),

    // ═══════════════════════════════════════════════════════════════
    // ssh.list_sessions — List active SSH sessions (read-only)
    // ═══════════════════════════════════════════════════════════════
    defineTool({
      name: "ssh.list_sessions",
      description: "List all active SSH sessions with their status, host, and uptime.",
      shape: {},
      permission: "ssh.list_sessions",
      async execute() {
        return { content: formatSessionList(sessionManager.listSessions()) }
      },
    }),

    // ═══════════════════════════════════════════════════════════════
    // ssh.exec — Execute command on remote server
    // ═══════════════════════════════════════════════════════════════
    defineTool({
      name: "ssh.exec",
      description:
        "Execute a command on a remote server via SSH. " +
        "Destructive commands (rm -rf /, mkfs, etc.) are automatically blocked with no exceptions. " +
        "Risky commands (DROP TABLE, sudo su, systemctl stop, etc.) require your explicit approval every time. " +
        "All output is streamed and displayed in real-time.",
      shape: execShape,
      permission: "ssh.exec",
      async execute(args) {
        // ── Validate session ──
        const connection = sessionManager.getSession(args.session_id)
        if (!connection) {
          return {
            content: `❌ Session \`${args.session_id}\` not found. Use ssh.list_sessions to see active sessions.`,
          }
        }

        // ── Rate limit per host ──
        const hostKey = connection.config.alias || connection.config.host
        const rateCheck = rateLimiter.check(hostKey)
        if (!rateCheck.allowed) {
          return {
            content: [
              `## ⏳ Command Rate Limited`,
              "",
              `**Host:** \`${hostKey}\``,
              `**Reason:** ${rateCheck.reason}`,
              rateCheck.retryAfterSeconds ? `**Retry after:** ~${rateCheck.retryAfterSeconds}s` : "",
            ]
              .filter(Boolean)
              .join("\n"),
          }
        }

        // ── Validate command against blocklist BEFORE any permission prompt ──
        // Custom allowlist = plugin config `allowlist` + per-project policy patterns.
        const customAllowlist = getEffectiveCustomAllowlist(projectDir, extraAllowlist)
        const validation = validateCommand(args.command, mode, extraBlocklist, customAllowlist)

        // DESTRUCTIVE: 100% blocked, no permission prompt, no override
        if (validation.level === "destructive") {
          return {
            content: [
              "## 🚫 Command Blocked (Destructive)",
              "",
              `**Command:** \`${args.command}\``,
              `**Reason:** ${validation.reason}`,
              `**Rule:** ${validation.matched_rule}`,
              "",
              "This command is **permanently blocked** for safety.",
              "Destructive commands cannot be executed under any circumstances.",
            ].join("\n"),
          }
        }

        // NOT IN ALLOWLIST: blocked in restricted/read_only mode
        if (validation.level === "not_in_allowlist") {
          return {
            content: [
              "## 🔒 Command Not Allowed",
              "",
              `**Command:** \`${args.command}\``,
              `**Reason:** ${validation.reason}`,
              "",
              "This command is not in the allowlist for the current security mode.",
              "Use ssh.security_policy to view the policy.",
            ].join("\n"),
          }
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
            projectDir,
            customAllowlist,
          )
        } finally {
          rateLimiter.record(hostKey, true)
        }

        return { content: formatExecResult(result) }
      },
    }),

    // ═══════════════════════════════════════════════════════════════
    // ssh.exec_batch — Execute multiple commands in sequence
    // ═══════════════════════════════════════════════════════════════
    defineTool({
      name: "ssh.exec_batch",
      description:
        "Execute multiple commands in sequence on a remote server. " +
        "Each command is validated against the security policy. " +
        "If stop_on_error is true, execution stops on the first failed command.",
      shape: execBatchShape,
      permission: "ssh.exec_batch",
      async execute(args) {
        const connection = sessionManager.getSession(args.session_id)
        if (!connection) {
          return { content: `❌ Session \`${args.session_id}\` not found.` }
        }

        // ── Rate limit per host ──
        const batchHostKey = connection.config.alias || connection.config.host
        const batchRateCheck = rateLimiter.check(batchHostKey)
        if (!batchRateCheck.allowed) {
          return {
            content: [
              `## ⏳ Batch Rate Limited`,
              "",
              `**Host:** \`${batchHostKey}\``,
              `**Reason:** ${batchRateCheck.reason}`,
              batchRateCheck.retryAfterSeconds ? `**Retry after:** ~${batchRateCheck.retryAfterSeconds}s` : "",
            ]
              .filter(Boolean)
              .join("\n"),
          }
        }

        const commands = args.commands.split("\n").filter((c) => c.trim())
        if (commands.length === 0) {
          return { content: "No commands to execute." }
        }

        // ── Validate all commands first ──
        const customAllowlist = getEffectiveCustomAllowlist(projectDir, extraAllowlist)
        const validations: Array<{ command: string; validation: ReturnType<typeof validateCommand> }> = []
        for (const cmd of commands) {
          const v = validateCommand(cmd.trim(), mode, extraBlocklist, customAllowlist)
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
          return { content: lines.join("\n") }
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
              projectDir,
              customAllowlist,
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

        return { content: lines.join("\n") }
      },
    }),

    // ═══════════════════════════════════════════════════════════════
    // ssh.upload — Upload file via SCP
    // ═══════════════════════════════════════════════════════════════
    defineTool({
      name: "ssh.upload",
      description: "Upload a local file to the remote server via SCP/SFTP.",
      shape: uploadShape,
      permission: "ssh.upload",
      async execute(args) {
        const connection = sessionManager.getSession(args.session_id)
        if (!connection) {
          return { content: `❌ Session \`${args.session_id}\` not found.` }
        }

        // Validate paths
        const pathCheck = sanitizePath(args.local_path)
        if (!pathCheck.clean) return { content: `❌ Invalid local path: ${pathCheck.reason}` }

        const remoteCheck = sanitizePath(args.remote_path)
        if (!remoteCheck.clean) return { content: `❌ Invalid remote path: ${remoteCheck.reason}` }

        try {
          const sftp = await connection.sftp()
          await new Promise<void>((resolve, reject) => {
            sftp.fastPut(args.local_path, args.remote_path, (err: Error | null) => {
              if (err) reject(err)
              else resolve()
            })
          })

          return {
            content: [
              "## 📤 File Uploaded",
              "",
              `- **Local:** \`${args.local_path}\``,
              `- **Remote:** \`${args.remote_path}\``,
              `- **Session:** \`${args.session_id}\``,
            ].join("\n"),
          }
        } catch (error) {
          const msg = error instanceof Error ? error.message : String(error)
          return { content: `❌ Upload failed: ${msg}` }
        }
      },
    }),

    // ═══════════════════════════════════════════════════════════════
    // ssh.download — Download file via SCP
    // ═══════════════════════════════════════════════════════════════
    defineTool({
      name: "ssh.download",
      description: "Download a file from the remote server to local via SCP/SFTP.",
      shape: downloadShape,
      permission: "ssh.download",
      async execute(args) {
        const connection = sessionManager.getSession(args.session_id)
        if (!connection) {
          return { content: `❌ Session \`${args.session_id}\` not found.` }
        }

        const pathCheck = sanitizePath(args.local_path)
        if (!pathCheck.clean) return { content: `❌ Invalid local path: ${pathCheck.reason}` }

        const remoteCheck = sanitizePath(args.remote_path)
        if (!remoteCheck.clean) return { content: `❌ Invalid remote path: ${remoteCheck.reason}` }

        try {
          const sftp = await connection.sftp()
          await new Promise<void>((resolve, reject) => {
            sftp.fastGet(args.remote_path, args.local_path, (err: Error | null) => {
              if (err) reject(err)
              else resolve()
            })
          })

          return {
            content: [
              "## 📥 File Downloaded",
              "",
              `- **Remote:** \`${args.remote_path}\``,
              `- **Local:** \`${args.local_path}\``,
              `- **Session:** \`${args.session_id}\``,
            ].join("\n"),
          }
        } catch (error) {
          const msg = error instanceof Error ? error.message : String(error)
          return { content: `❌ Download failed: ${msg}` }
        }
      },
    }),

    // ═══════════════════════════════════════════════════════════════
    // ssh.check_command — Validate command safety (dry-run, read-only)
    // ═══════════════════════════════════════════════════════════════
    defineTool({
      name: "ssh.check_command",
      description:
        "Check if a command is safe to execute without actually running it. " +
        "Returns the safety level, any matched blocklist rules, and suggestions. " +
        "Use this to preview command safety before execution.",
      shape: checkCommandShape,
      permission: "ssh.check_command",
      async execute(args) {
        const customAllowlist = getEffectiveCustomAllowlist(projectDir, extraAllowlist)
        const validation = validateCommand(args.command, mode, extraBlocklist, customAllowlist)
        return { content: formatCheckResult(args.command, validation) }
      },
    }),

    // ═══════════════════════════════════════════════════════════════
    // ssh.security_policy — View the current security policy (read-only)
    // ═══════════════════════════════════════════════════════════════
    defineTool({
      name: "ssh.security_policy",
      description:
        "View the SSH security policy: the active security mode, the blocklist, and the allowlist. " +
        "Read-only. Use ssh.security_policy_modify to change any pattern.",
      shape: policyViewShape,
      permission: "ssh.security_policy",
      async execute() {
        const policy = getPolicy(projectDir, mode)
        return { content: formatSecurityPolicy(policy, extraAllowlist) }
      },
    }),

    // ═══════════════════════════════════════════════════════════════
    // ssh.security_policy_modify — Add/remove blocklist or allowlist patterns
    //
    // Split from ssh.security_policy so the permission it needs is static:
    // in SDK v2 a tool declares one action, and the permission hook maps
    // `ssh.security_policy_modify` to "ask" unconditionally.
    // ═══════════════════════════════════════════════════════════════
    defineTool({
      name: "ssh.security_policy_modify",
      description:
        "Add or remove a pattern from the SSH security blocklist or allowlist. " +
        "Every change requires explicit user confirmation and is never self-granted. " +
        "Use ssh.security_policy to inspect the current policy.",
      shape: policyModifyShape,
      permission: "ssh.security_policy_modify",
      async execute(args) {
        // Validate regex
        try {
          new RegExp(args.pattern)
        } catch {
          return { content: `❌ Invalid regex pattern: \`${args.pattern}\`` }
        }

        switch (args.action) {
          case "add_blocklist": {
            const policy = addBlocklistPattern(projectDir, args.pattern)
            return {
              content: ["## ✅ Blocklist Pattern Added", "", `Added: \`${args.pattern}\``, "", formatSecurityPolicy(policy)].join(
                "\n",
              ),
            }
          }
          case "remove_blocklist": {
            const policy = removeBlocklistPattern(projectDir, args.pattern)
            return {
              content: [
                "## ✅ Blocklist Pattern Removed",
                "",
                `Removed: \`${args.pattern}\``,
                "",
                formatSecurityPolicy(policy),
              ].join("\n"),
            }
          }
          case "add_allowlist": {
            const policy = addAllowlistPattern(projectDir, args.pattern)
            return {
              content: [
                "## ✅ Allowlist Pattern Added",
                "",
                `Added: \`${args.pattern}\``,
                "",
                formatSecurityPolicy(policy),
              ].join("\n"),
            }
          }
          case "remove_allowlist": {
            const policy = removeAllowlistPattern(projectDir, args.pattern)
            return {
              content: [
                "## ✅ Allowlist Pattern Removed",
                "",
                `Removed: \`${args.pattern}\``,
                "",
                formatSecurityPolicy(policy),
              ].join("\n"),
            }
          }
        }
      },
    }),

    // ═══════════════════════════════════════════════════════════════
    // ssh.audit_log — View command audit trail (read-only)
    // ═══════════════════════════════════════════════════════════════
    defineTool({
      name: "ssh.audit_log",
      description:
        "View the SSH command audit log. Shows all executed, blocked, and approved commands " +
        "with timestamps, results, and details. Supports filtering by session and command.",
      shape: auditLogShape,
      permission: "ssh.audit_log",
      async execute(args) {
        const entries = readAuditLog(projectDir, {
          limit: args.limit || 20,
          sessionId: args.session_id,
          commandFilter: args.command_filter,
        })

        if (entries.length === 0) {
          // Show stats even if no entries match
          const stats = getAuditStats(projectDir)
          if (stats.total === 0) {
            return { content: "📋 No audit entries yet. Commands executed via ssh.exec will be logged here." }
          }

          return {
            content: [
              `## SSH Audit Stats`,
              "",
              `- **Total:** ${stats.total}`,
              `- **Success:** ${stats.success}`,
              `- **Blocked:** ${stats.blocked}`,
              `- **Approved (risky):** ${stats.approved}`,
              `- **Errors:** ${stats.error}`,
              "",
              "No entries match the current filters.",
            ].join("\n"),
          }
        }

        // Show stats header
        const stats = getAuditStats(projectDir)
        const header = [
          `### Stats: ${stats.total} total | ${stats.success} ✅ | ${stats.blocked} 🚫 | ${stats.approved} ⚠️ | ${stats.error} ❌`,
          "",
        ].join("\n")

        return { content: header + formatAuditLog(entries) }
      },
    }),
  ]
}
