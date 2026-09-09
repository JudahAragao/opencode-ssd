import { DEFAULT_CONFIG, type SshPluginConfigType } from "./schema.js"

/**
 * Get merged configuration with user overrides.
 */
export function resolveConfig(userConfig?: Record<string, unknown>): SshPluginConfigType {
  if (!userConfig) return { ...DEFAULT_CONFIG }

  const merged: Record<string, unknown> = { ...DEFAULT_CONFIG }

  for (const [key, value] of Object.entries(userConfig)) {
    if (value !== undefined && value !== null) {
      merged[key] = value
    }
  }

  return merged as SshPluginConfigType
}

/**
 * Get the SSH data directory path for a project.
 * Stores sessions, audit logs, and policy files.
 */
export function getSshDataDir(projectDir: string): string {
  return `${projectDir}/.opencode-ssh`
}
