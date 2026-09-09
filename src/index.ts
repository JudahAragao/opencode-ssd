import type { Plugin } from "@opencode-ai/plugin"
import { createSshTools } from "./tools.js"
import { createSshHooks } from "./hooks.js"
import { resolveConfig } from "./config/defaults.js"
import type { SshPluginConfigType } from "./config/schema.js"

const SshPlugin: Plugin = async (_ctx, options) => {
  // ── Resolve configuration ──
  const config = resolveConfig(options as Record<string, unknown>)

  // ── Create tools and hooks with resolved config ──
  const tools = createSshTools(
    config.mode,
    config.max_sessions,
    config.default_timeout,
    config.blocklist_extra,
    config.ssh_config_path,
    config.auto_connect,
  )
  const hooks = createSshHooks(config.mode, config.blocklist_extra)

  return {
    tool: tools,
    ...hooks,
  }
}

export default {
  id: "opencode-ssh",
  server: SshPlugin,
}
