import { Plugin } from "@opencode/plugin"
import { createSshTools } from "./tools.js"
import { registerSshHooks } from "./hooks.js"
import { resolveConfig } from "./config/defaults.js"
import { SSH_NAMESPACE } from "./naming.js"

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

    // ── Register the tool catalog through the SDK v2 tool transform ──
    //
    // Registration declares the `ssh` namespace and adds each tool with a
    // short leaf name plus `options.namespace: "ssh"`. The host derives the
    // effective tool id by joining namespace and leaf with `_` (dots in
    // namespaces and provider-unsupported characters normalize to `_`), so
    // every tool is exposed as `ssh_connect`, `ssh_exec`, `ssh_exec_batch`,
    // … — valid for every provider and identical to the ids the permission
    // hook evaluates.
    const toolsRegistration = await ctx.tool.transform((editor) => {
      editor.namespace({
        name: SSH_NAMESPACE,
        description:
          "Secure SSH access to remote servers: session management, command execution with " +
          "destructive-command blocking, file transfer, security policy, and audit trail.",
      })
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
