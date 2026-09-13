import type { SshConnection } from "./connection.js"
import { validateCommand, type ValidationResult } from "../security/validator.js"
import { sanitizeCommand } from "./sanitizer.js"
import { logCommand, type AuditEntry } from "./audit.js"
import type { SecurityMode } from "../config/schema.js"

export interface ExecOptions {
  cwd?: string
  timeout?: number
  sudo?: boolean
}

export interface ExecResult {
  /** Command that was executed */
  command: string
  /** Standard output */
  stdout: string
  /** Standard error output */
  stderr: string
  /** Exit code */
  exitCode: number | null
  /** Signal that killed the process (if any) */
  signal?: string
  /** Duration in milliseconds */
  duration: number
  /** Session ID */
  sessionId: string
  /** Validation result */
  validation: ValidationResult
}

export interface ExecStreamCallbacks {
  onStdout?: (data: string) => void
  onStderr?: (data: string) => void
  onExit?: (code: number | null) => void
  onError?: (error: Error) => void
}

/**
 * Execute a command on an SSH connection with security validation.
 *
 * This is the main execution function that:
 * 1. Validates the command against the security policy
 * 2. Sanitizes the input
 * 3. Executes the command
 * 4. Logs the result to audit
 * 5. Returns structured output
 */
export async function executeCommand(
  connection: SshConnection,
  command: string,
  mode: SecurityMode,
  extraBlocklist: string[],
  sessionId: string,
  options: ExecOptions = {},
  projectDir: string = "",
  customAllowlist: string[] = [],
): Promise<ExecResult> {
  const startTime = Date.now()

  // ── Step 1: Input sanitization ──
  const sanitization = sanitizeCommand(command)
  if (!sanitization.clean) {
    const result: ExecResult = {
      command,
      stdout: "",
      stderr: sanitization.reason || "Command rejected by sanitizer",
      exitCode: 1,
      duration: Date.now() - startTime,
      sessionId,
      validation: {
        safe: false,
        level: "destructive",
        reason: sanitization.reason,
      },
    }

    // Log to audit
    if (projectDir) {
      logCommand(projectDir, {
        sessionId,
        command,
        result: "blocked",
        exitCode: 1,
        duration: result.duration,
        reason: sanitization.reason,
      })
    }

    return result
  }

  // ── Step 2: Security validation ──
  const validation = validateCommand(command, mode, extraBlocklist, customAllowlist)

  // Destructive: ALWAYS blocked, no exception
  if (validation.level === "destructive") {
    const result: ExecResult = {
      command,
      stdout: "",
      stderr: validation.reason || "Command is destructively blocked",
      exitCode: 1,
      duration: Date.now() - startTime,
      sessionId,
      validation,
    }

    if (projectDir) {
      logCommand(projectDir, {
        sessionId,
        command,
        result: "blocked",
        exitCode: 1,
        duration: result.duration,
        reason: validation.reason,
        matchedRule: validation.matched_rule,
      })
    }

    return result
  }

  // Risky: The tool.ts caller handles the permission prompt via ctx.ask()
  // If we reach here, the permission was already granted by the hook system.
  // We just log that it was a risky command that was approved.

  // Not in allowlist: blocked in restricted/read_only mode
  if (validation.level === "not_in_allowlist") {
    const result: ExecResult = {
      command,
      stdout: "",
      stderr: validation.reason || "Command not in allowlist",
      exitCode: 1,
      duration: Date.now() - startTime,
      sessionId,
      validation,
    }

    if (projectDir) {
      logCommand(projectDir, {
        sessionId,
        command,
        result: "blocked",
        exitCode: 1,
        duration: result.duration,
        reason: validation.reason,
      })
    }

    return result
  }

  // ── Step 3: Prepare command ──
  let execCommand = command
  if (options.sudo) {
    execCommand = `sudo ${command}`
  }

  // ── Step 4: Execute ──
  try {
    const execResult = await connection.exec(execCommand, {
      cwd: options.cwd,
      timeout: options.timeout,
    })

    const duration = Date.now() - startTime
    const result: ExecResult = {
      command: execCommand,
      stdout: execResult.stdout,
      stderr: execResult.stderr,
      exitCode: execResult.code,
      signal: execResult.signal,
      duration,
      sessionId,
      validation,
    }

    // ── Step 5: Audit log ──
    if (projectDir) {
      logCommand(projectDir, {
        sessionId,
        command: execCommand,
        result: validation.level === "risky" ? "approved" : "success",
        exitCode: execResult.code ?? 1,
        duration,
        matchedRule: validation.matched_rule,
      })
    }

    return result
  } catch (error) {
    const duration = Date.now() - startTime
    const errMsg = error instanceof Error ? error.message : String(error)

    const result: ExecResult = {
      command: execCommand,
      stdout: "",
      stderr: errMsg,
      exitCode: 1,
      duration,
      sessionId,
      validation,
    }

    if (projectDir) {
      logCommand(projectDir, {
        sessionId,
        command: execCommand,
        result: "error",
        exitCode: 1,
        duration,
        reason: errMsg,
      })
    }

    return result
  }
}

/**
 * Execute a command with real-time streaming output.
 * Calls the callbacks as data arrives.
 */
export async function executeCommandStream(
  connection: SshConnection,
  command: string,
  mode: SecurityMode,
  extraBlocklist: string[],
  sessionId: string,
  options: ExecOptions = {},
  projectDir: string = "",
  customAllowlist: string[] = [],
  callbacks: ExecStreamCallbacks = {},
): Promise<ExecResult> {
  const startTime = Date.now()

  // ── Step 1 & 2: Validate and sanitize (same as non-streaming) ──
  const sanitization = sanitizeCommand(command)
  if (!sanitization.clean) {
    callbacks.onError?.(new Error(sanitization.reason))
    return {
      command,
      stdout: "",
      stderr: sanitization.reason || "Command rejected",
      exitCode: 1,
      duration: Date.now() - startTime,
      sessionId,
      validation: {
        safe: false,
        level: "destructive",
        reason: sanitization.reason,
      },
    }
  }

  const validation = validateCommand(command, mode, extraBlocklist, customAllowlist)

  if (validation.level === "destructive") {
    callbacks.onError?.(new Error(validation.reason))
    return {
      command,
      stdout: "",
      stderr: validation.reason || "Command blocked",
      exitCode: 1,
      duration: Date.now() - startTime,
      sessionId,
      validation,
    }
  }

  if (validation.level === "not_in_allowlist") {
    callbacks.onError?.(new Error(validation.reason))
    return {
      command,
      stdout: "",
      stderr: validation.reason || "Not in allowlist",
      exitCode: 1,
      duration: Date.now() - startTime,
      sessionId,
      validation,
    }
  }

  // ── Step 3: Execute with streaming ──
  let execCommand = command
  if (options.sudo) {
    execCommand = `sudo ${command}`
  }

  try {
    // Use the exec method which returns stdout/stderr
    // For true streaming, we'd need access to the raw ssh2 stream
    // This implementation collects output and calls callbacks
    const execResult = await connection.exec(execCommand, {
      cwd: options.cwd,
      timeout: options.timeout,
    })

    // Simulate streaming by calling callbacks with the collected output
    if (execResult.stdout) {
      callbacks.onStdout?.(execResult.stdout)
    }
    if (execResult.stderr) {
      callbacks.onStderr?.(execResult.stderr)
    }
    callbacks.onExit?.(execResult.code)

    const duration = Date.now() - startTime

    if (projectDir) {
      logCommand(projectDir, {
        sessionId,
        command: execCommand,
        result: validation.level === "risky" ? "approved" : "success",
        exitCode: execResult.code ?? 1,
        duration,
        matchedRule: validation.matched_rule,
      })
    }

    return {
      command: execCommand,
      stdout: execResult.stdout,
      stderr: execResult.stderr,
      exitCode: execResult.code,
      signal: execResult.signal,
      duration,
      sessionId,
      validation,
    }
  } catch (error) {
    const duration = Date.now() - startTime
    const errMsg = error instanceof Error ? error.message : String(error)
    callbacks.onError?.(error instanceof Error ? error : new Error(errMsg))
    callbacks.onExit?.(1)

    if (projectDir) {
      logCommand(projectDir, {
        sessionId,
        command: execCommand,
        result: "error",
        exitCode: 1,
        duration,
        reason: errMsg,
      })
    }

    return {
      command: execCommand,
      stdout: "",
      stderr: errMsg,
      exitCode: 1,
      duration,
      sessionId,
      validation,
    }
  }
}
