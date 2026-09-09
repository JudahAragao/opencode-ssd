/**
 * Real-time SSH output stream handler.
 * Formats and prepares output chunks for display as they arrive.
 */

export interface StreamChunk {
  /** Type of output */
  type: "stdout" | "stderr" | "info" | "error"
  /** The data chunk */
  data: string
  /** Timestamp */
  timestamp: number
  /** Session identifier */
  sessionId: string
}

/**
 * Create a stream handler that collects and formats output chunks.
 */
export function createStreamHandler(sessionId: string): {
  chunks: StreamChunk[]
  onStdout: (data: string) => void
  onStderr: (data: string) => void
  onInfo: (data: string) => void
  onError: (data: string) => void
  getOutput: () => { stdout: string; stderr: string }
  formatOutput: () => string
} {
  const chunks: StreamChunk[] = []
  let stdout = ""
  let stderr = ""

  return {
    chunks,

    onStdout: (data: string) => {
      chunks.push({
        type: "stdout",
        data,
        timestamp: Date.now(),
        sessionId,
      })
      stdout += data
    },

    onStderr: (data: string) => {
      chunks.push({
        type: "stderr",
        data,
        timestamp: Date.now(),
        sessionId,
      })
      stderr += data
    },

    onInfo: (data: string) => {
      chunks.push({
        type: "info",
        data,
        timestamp: Date.now(),
        sessionId,
      })
    },

    onError: (data: string) => {
      chunks.push({
        type: "error",
        data,
        timestamp: Date.now(),
        sessionId,
      })
      stderr += data
    },

    getOutput: () => ({
      stdout,
      stderr,
    }),

    formatOutput: () => {
      const lines: string[] = []

      for (const chunk of chunks) {
        switch (chunk.type) {
          case "stdout":
          case "stderr":
            // Output is collected and shown as a whole
            break
          case "info":
            lines.push(`ℹ️ ${chunk.data}`)
            break
          case "error":
            lines.push(`❌ ${chunk.data}`)
            break
        }
      }

      if (stdout.trim()) {
        lines.push(stdout.trim())
      }
      if (stderr.trim()) {
        lines.push(`\`\`\`\n${stderr.trim()}\n\`\`\``)
      }

      return lines.join("\n")
    },
  }
}

/**
 * Format a progress indicator for long-running commands.
 */
export function formatProgress(sessionId: string, command: string, elapsed: number): string {
  const elapsedStr =
    elapsed < 1000
      ? `${elapsed}ms`
      : `${(elapsed / 1000).toFixed(1)}s`

  return `⏳ [${sessionId}] \`${command}\` — running for ${elapsedStr}...`
}

/**
 * Format a timeout warning.
 */
export function formatTimeout(sessionId: string, command: string, timeout: number): string {
  return [
    `⏰ **Command timed out**`,
    "",
    `- Session: \`${sessionId}\``,
    `- Command: \`${command}\``,
    `- Timeout: ${timeout}s`,
    "",
    "The command was terminated after exceeding the timeout limit.",
  ].join("\n")
}
