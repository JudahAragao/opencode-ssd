import { describe, expect, it } from "bun:test"
import { mkdtempSync } from "fs"
import { tmpdir } from "os"
import { join } from "path"
import {
  getToolNameMode,
  projectToolNames,
  setToolNameMode,
  toCanonicalToolName,
  toWireToolName,
} from "../src/tool-names"
import { createSshTools } from "../src/tools"

describe("OpenAI-compatible tool names", () => {
  it("keeps canonical names by default", () => {
    expect(toWireToolName("ssh.exec", false)).toBe("ssh.exec")
  })

  it("projects dots to underscores and restores the canonical name", () => {
    const projected = projectToolNames(
      { "ssh.connect": { description: "Call ssh.connect" }, "ssh.exec": { description: "Call ssh.exec" } },
      true,
    )
    expect(Object.keys(projected)).toEqual(["ssh_connect", "ssh_exec"])
    expect(projected.ssh_exec.description).toBe("Call ssh_exec")
    expect(toCanonicalToolName("ssh_connect", ["ssh.connect"], true)).toBe("ssh.connect")
  })

  it("rejects deterministic collisions", () => {
    expect(() => projectToolNames({ "a.b": { description: "one" }, a_b: { description: "two" } }, true)).toThrow(
      "Tool name collision",
    )
  })

  it("projects the complete SSH catalog to valid wire names", () => {
    const projected = projectToolNames(createSshTools(), true)
    expect(Object.keys(projected).every((name) => /^[A-Za-z0-9_-]{1,64}$/.test(name))).toBe(true)
    expect(projected.ssh_connect).toBeDefined()
    expect(toCanonicalToolName("ssh_exec", Object.keys(createSshTools()), true)).toBe("ssh.exec")
  })

  it("reads the shared mode file", () => {
    const directory = mkdtempSync(join(tmpdir(), "ssh-tool-names-"))
    setToolNameMode(directory, "safe")
    expect(getToolNameMode(directory)).toBe("safe")
  })
})
