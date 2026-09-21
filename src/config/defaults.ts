import { SshPluginConfig, type SshPluginConfigType } from "./schema.js"

/**
 * Get merged configuration with user overrides.
 * Uses Zod parsing to validate input, apply defaults, and reject unknown keys.
 */
export function resolveConfig(userConfig?: Record<string, unknown>): SshPluginConfigType {
  if (!userConfig || Object.keys(userConfig).length === 0) {
    return SshPluginConfig.parse({})
  }
  return SshPluginConfig.parse(userConfig)
}

/**
 * Get the SSH data directory path for a project.
 * Stores sessions, audit logs, and policy files.
 */
export function getSshDataDir(projectDir: string): string {
  return `${projectDir}/.opencode-ssh`
}
