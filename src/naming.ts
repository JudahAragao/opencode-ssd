/**
 * Tool naming — single source of truth.
 *
 * The OpenCode v2 plugin SDK registers tools under a namespace and derives an
 * "effective name" per tool: namespace segments and the leaf name are joined
 * with `_`, and dots in namespaces (and characters unsupported by providers in
 * tool names) become `_` automatically. See
 * https://opencode.ai/v2/docs/build/plugins/ (Tools section).
 *
 * This plugin registers through that official mechanism:
 *   editor.namespace({ name: "ssh", description: ... }) + tools named `connect`,
 *   `exec`, … with `options.namespace: "ssh"`.
 *
 * The resulting effective ids are `ssh_connect`, `ssh_exec`, `ssh_exec_batch`,
 * … — the same shape the host itself derives, so the dotted catalog names
 * (`ssh.exec`, …) and the effective ids are the two canonical spellings of the
 * same tool. Every hook, permission decision, and user-facing string goes
 * through the helpers below, which accept BOTH forms automatically, so neither
 * the plugin nor the model ever needs to know which spelling arrived.
 */

/** The plugin namespace. */
export const SSH_NAMESPACE = "ssh"

/** Ordered leaf names — also the registration order of the tool catalog. */
export const SSH_TOOL_LEAVES = [
  "connect",
  "disconnect",
  "list_sessions",
  "exec",
  "exec_batch",
  "upload",
  "download",
  "check_command",
  "security_policy",
  "security_policy_modify",
  "audit_log",
] as const

export type SshToolLeaf = (typeof SSH_TOOL_LEAVES)[number]

/** Effective tool ids as the host exposes them (`ssh_connect`, `ssh_exec`, …). */
export type SshToolId = `ssh_${SshToolLeaf}`

/** Dotted canonical names (`ssh.exec`, `ssh.exec_batch`, …). */
export type SshToolDottedName = `ssh.${SshToolLeaf}`

const PREFIX_UNDERSCORE = `${SSH_NAMESPACE}_`

/**
 * Normalize any tool-name/action spelling into the underscored effective form:
 * `ssh.exec_batch` → `ssh_exec_batch`, `ssh_exec_batch` → `ssh_exec_batch`.
 * Names outside the `ssh` namespace are returned flattened but untouched
 * (`other.tool` → `other_tool`, `bash` → `bash`).
 */
export function toEffectiveName(name: string): string {
  return name.replaceAll(".", "_")
}

/** Normalize to the dotted canonical form (`ssh.exec_batch`). SSH-only input. */
export function toDottedName(name: string): string {
  const flat = toEffectiveName(name)
  return flat === SSH_NAMESPACE ? SSH_NAMESPACE : flat.replace(PREFIX_UNDERSCORE, `${SSH_NAMESPACE}.`)
}

/** The tool leaf (`exec`, `exec_batch`, …) from either spelling. Non-SSH input returns the input flattened. */
export function toLeafName(name: string): string {
  const flat = toEffectiveName(name)
  return flat.startsWith(PREFIX_UNDERSCORE) ? flat.slice(PREFIX_UNDERSCORE.length) : flat
}

/** True when `name` refers to an SSH tool in either spelling (`ssh.exec` or `ssh_exec`). */
export function isSshToolName(name: string): boolean {
  const flat = toEffectiveName(name)
  return flat === SSH_NAMESPACE || flat.startsWith(PREFIX_UNDERSCORE)
}

/** True when `name` is a known SSH tool (either spelling); false for unknown leaves. */
export function isKnownSshTool(name: string): boolean {
  if (!isSshToolName(name)) return false
  return (SSH_TOOL_LEAVES as readonly string[]).includes(toLeafName(name))
}

/**
 * True when `name` matches one of the given leaves in either spelling.
 * Accepts full names (`ssh.exec`, `ssh_exec`) and bare leaves (`exec`);
 * anything outside the ssh namespace is false.
 */
export function isSshTool(name: string, leaves: ReadonlyArray<string>): boolean {
  if (!isSshToolName(name)) return false
  return leaves.includes(toLeafName(name))
}
