import type { Plugin } from "@opencode-ai/plugin"
import { createSshTools } from "./tools.js"
import { createSshHooks } from "./hooks.js"
import { resolveConfig } from "./config/defaults.js"
import type { SshPluginConfigType } from "./config/schema.js"

const SshPlugin: Plugin = async (input, options) => {
  // ── Resolve configuration ──
  const config: SshPluginConfigType = resolveConfig(options as Record<string, unknown>)

  // Project directory is used to resolve the per-project policy allowlist
  // (customAllowlist) that is merged with the config `allowlist`.
  const projectDir = input.directory

  // ── Create tools and hooks with resolved config ──
  const tools = createSshTools(
    config.mode,
    config.max_sessions,
    config.default_timeout,
    config.blocklist_extra,
    config.allowlist,
    config.ssh_config_path,
    config.auto_connect,
    {
      strictHostKey: config.strict_host_key,
      rateLimitPerMinute: config.rate_limit_per_minute,
      cooldownSeconds: config.cooldown_seconds,
      autoReconnect: config.auto_reconnect,
    },
  )
  const hooks = createSshHooks(
    config.mode,
    config.blocklist_extra,
    config.allowlist,
    projectDir,
  )

  return {
    tool: tools,
    ...hooks,
  }
}

export default {
  id: "opencode-ssh",
  server: SshPlugin,
}