import type { Plugin } from "@opencode-ai/plugin"
import { createSshTools } from "./tools.js"
import { createSshHooks } from "./hooks.js"
import { resolveConfig } from "./config/defaults.js"
import type { SshPluginConfigType } from "./config/schema.js"

/**
 * Validate that the host opencode runtime exposes the tool-building API this
 * plugin depends on. If the runtime is too old/incompatible, tools are
 * disabled instead of crashing at call time.
 */
function validatePluginApi(ctx: unknown): { ok: boolean; reason?: string } {
  const c = ctx as { tool?: unknown; hooks?: unknown }
  if (!c || typeof c !== "object") {
    return { ok: false, reason: "Plugin context is invalid" }
  }
  if (typeof c.tool !== "function") {
    return { ok: false, reason: "ctx.tool is not available — runtime too old for tool-based plugins" }
  }
  const toolNs = c.tool as { schema?: unknown }
  if (!toolNs.schema || typeof toolNs.schema !== "object") {
    return { ok: false, reason: "ctx.tool.schema (Zod-backed schema helpers) is missing — incompatible @opencode-ai/plugin" }
  }
  return { ok: true }
}

const SshPlugin: Plugin = async (ctx, options) => {
  // ── Resolve configuration ──
  const config: SshPluginConfigType = resolveConfig(options as Record<string, unknown>)

  // ── Compatibility check against the host runtime ──
  const api = validatePluginApi(ctx)
  if (!api.ok) {
    console.warn(`[opencode-ssh] Plugin API incompatible: ${api.reason}. SSH tools are disabled.`)
    return {}
  }

  // ── Create tools and hooks with resolved config ──
  const tools = createSshTools(
    config.mode,
    config.max_sessions,
    config.default_timeout,
    config.blocklist_extra,
    config.ssh_config_path,
    config.auto_connect,
    {
      strictHostKey: config.strict_host_key,
      rateLimitPerMinute: config.rate_limit_per_minute,
      cooldownSeconds: config.cooldown_seconds,
      autoReconnect: config.auto_reconnect,
    },
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