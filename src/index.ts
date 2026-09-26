import { Plugin } from "@opencode/plugin"
import { createSshTools } from "./tools.js"
import { registerSshHooks } from "./hooks.js"
import { resolveConfig } from "./config/defaults.js"

export default Plugin.define({
  id: "opencode-ssh",
  async setup(ctx) {
    // ── Resolve configuration ──
    const config = resolveConfig(ctx.options as Record<string, unknown>)

    // Project directory is used to resolve the per-project policy allowlist
    // (customAllowlist) that is merged with the config `allowlist`.
    const projectDir = ctx.location.directory

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
      projectDir,
    )

    const toolsRegistration = await ctx.tool.transform((editor) => {
      for (const definition of tools) editor.add(definition)
    })

    const disposals = await registerSshHooks(ctx, {
      mode: config.mode,
      extraBlocklist: config.blocklist_extra,
      extraAllowlist: config.allowlist,
      projectDir,
    })

    return async () => {
      await toolsRegistration.dispose()
      for (const dispose of disposals) await dispose()
    }
  },
})
