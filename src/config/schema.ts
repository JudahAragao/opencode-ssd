import { z } from "zod"

/**
 * Security mode for SSH command execution.
 * - "full": All commands allowed except blocklist
 * - "restricted": Only allowlist + read-only commands
 * - "read_only": Only read-only commands (ls, cat, grep, etc.)
 */
export const SecurityMode = z.enum(["full", "restricted", "read_only"])
export type SecurityMode = z.infer<typeof SecurityMode>

/**
 * Configuration schema for the opencode-ssh plugin.
 */
export const SshPluginConfig = z
  .object({
    /** Security mode for command execution */
    mode: SecurityMode.default("full"),

    /** Maximum concurrent SSH sessions */
    max_sessions: z.number().int().min(1).max(50).default(5),

    /** Default command timeout in seconds */
    default_timeout: z.number().int().min(1).max(600).default(30),

    /** Whether to enable audit logging */
    audit_enabled: z.boolean().default(true),

    /** Additional command patterns to block (regex strings) */
    blocklist_extra: z.array(z.string()).default([]),

    /** Additional command patterns to allow (used in restricted mode) */
    allowlist: z.array(z.string()).default([]),

    /** Path to SSH config file (~/.ssh/config) */
    ssh_config_path: z.string().optional(),

    /** Auto-connect on plugin boot (requires saved session) */
    auto_connect: z.boolean().default(false),
  })
  .strict()

export type SshPluginConfigType = z.infer<typeof SshPluginConfig>

export const DEFAULT_CONFIG: SshPluginConfigType = {
  mode: "full",
  max_sessions: 5,
  default_timeout: 30,
  audit_enabled: true,
  blocklist_extra: [],
  allowlist: [],
  auto_connect: false,
}
