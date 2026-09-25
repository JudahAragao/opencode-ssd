import { mkdirSync, readFileSync, writeFileSync } from "fs"
import { join } from "path"

export type ToolNameMode = "canonical" | "safe"

const SAFE_TOOL_NAMES_ENV = "OPENCODE_SAFE_TOOL_NAMES"
const TOOL_NAMES_CONFIG = ".opencode/tool-names.json"

function envMode(): ToolNameMode | undefined {
  const value = process.env[SAFE_TOOL_NAMES_ENV]?.trim().toLowerCase()
  if (["1", "true", "yes", "on", "safe"].includes(value ?? "")) return "safe"
  if (["0", "false", "no", "off", "canonical"].includes(value ?? "")) return "canonical"
  return undefined
}

export function getToolNameMode(projectDir?: string): ToolNameMode {
  const configured = envMode()
  if (configured) return configured
  if (projectDir) {
    try {
      const value = JSON.parse(readFileSync(join(projectDir, TOOL_NAMES_CONFIG), "utf8")) as { mode?: unknown }
      if (value.mode === "safe" || value.mode === "canonical") return value.mode
    } catch {
      // Missing or malformed optional configuration falls back to canonical names.
    }
  }
  return "canonical"
}

export function safeToolNamesEnabled(projectDir?: string): boolean {
  return getToolNameMode(projectDir) === "safe"
}

export function setToolNameMode(projectDir: string, mode: ToolNameMode): string {
  const path = join(projectDir, TOOL_NAMES_CONFIG)
  mkdirSync(join(projectDir, ".opencode"), { recursive: true })
  writeFileSync(path, `${JSON.stringify({ mode }, null, 2)}\n`, "utf8")
  return path
}

export function toWireToolName(name: string, safe: boolean): string {
  return safe ? name.replaceAll(".", "_") : name
}

export function toCanonicalToolName(name: string, canonicalNames: readonly string[], safe: boolean): string {
  if (!safe) return name
  return canonicalNames.find((canonical) => toWireToolName(canonical, true) === name) ?? name
}

export function rewriteToolNames(text: string, canonicalNames: readonly string[], safe: boolean): string {
  if (!safe) return text
  return [...canonicalNames]
    .sort((a, b) => b.length - a.length)
    .reduce((result, canonical) => result.split(canonical).join(toWireToolName(canonical, true)), text)
}

export function restoreToolNames(text: string, canonicalNames: readonly string[], safe: boolean): string {
  if (!safe) return text
  return [...canonicalNames]
    .sort((a, b) => b.length - a.length)
    .reduce((result, canonical) => result.split(toWireToolName(canonical, true)).join(canonical), text)
}

export function projectToolNames<T extends { description: string }>(
  tools: Record<string, T>,
  safe: boolean,
): Record<string, T> {
  if (!safe) return tools

  const canonicalNames = Object.keys(tools)
  const projected: Record<string, T> = {}
  for (const [canonical, tool] of Object.entries(tools)) {
    const wire = toWireToolName(canonical, true)
    if (projected[wire]) {
      throw new Error(`Tool name collision after OpenAI compatibility projection: ${canonical} -> ${wire}`)
    }
    projected[wire] = {
      ...tool,
      description: rewriteToolNames(tool.description, canonicalNames, true),
    }
  }
  return projected
}

export function rewriteToolText(text: string, safe: boolean): string {
  return rewriteToolNames(text, SSH_TOOL_NAMES, safe)
}

export function canonicalToolName(name: string, safe: boolean): string {
  return toCanonicalToolName(name, SSH_TOOL_NAMES, safe)
}

export const SSH_TOOL_NAMES = [
  "ssh.connect",
  "ssh.disconnect",
  "ssh.list_sessions",
  "ssh.exec",
  "ssh.exec_batch",
  "ssh.upload",
  "ssh.download",
  "ssh.check_command",
  "ssh.security_policy",
  "ssh.audit_log",
] as const
