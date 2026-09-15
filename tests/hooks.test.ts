import { describe, test, expect } from "bun:test"
import { createSshHooks } from "../src/hooks.js"

const output = () => ({ status: "ask" as "ask" | "allow" | "deny" })

function invoke(pattern: string | string[]): Promise<"ask" | "allow" | "deny"> {
  const hooks = createSshHooks()
  const out = output()
  return hooks["permission.ask"]!({ pattern } as never, out).then(() => out.status)
}

describe("permission.ask hook — security policy confirmation", () => {
  test("viewing the policy is auto-approved (read-only)", async () => {
    expect(await invoke("ssh.security_policy.view")).toBe("allow")
    expect(await invoke(["ssh.security_policy.view", "view"])).toBe("allow")
  })

  test("add_allowlist always asks (never auto-approved)", async () => {
    expect(await invoke("ssh.security_policy.modify: add_allowlist: docker stop .*")).toBe("ask")
  })

  test("remove_allowlist always asks", async () => {
    expect(await invoke(["ssh.security_policy.modify", "remove_allowlist: docker stop .*"])).toBe("ask")
  })

  test("add_blocklist / remove_blocklist always ask", async () => {
    expect(await invoke("ssh.security_policy.modify: add_blocklist: bad-.*")).toBe("ask")
    expect(await invoke("ssh.security_policy.modify: remove_blocklist: bad-.*")).toBe("ask")
  })

  test("array patterns that include a mutation keyword always ask", async () => {
    expect(await invoke(["ssh.security_policy", "add_allowlist: rm -rf /tmp/app"])).toBe("ask")
  })
})

describe("permission.ask hook — read-only operations", () => {
  test("list_sessions / check_command / audit_log are auto-approved", async () => {
    expect(await invoke("ssh.list_sessions")).toBe("allow")
    expect(await invoke("ssh.check_command")).toBe("allow")
    expect(await invoke("ssh.audit_log")).toBe("allow")
  })
})

describe("permission.ask hook — execution commands", () => {
  test("risky exec commands always ask", async () => {
    expect(await invoke("ssh.exec.risky")).toBe("ask")
    expect(await invoke("ssh.exec_batch.risky")).toBe("ask")
  })

  test("generic exec / connect remain ask", async () => {
    expect(await invoke("ssh.exec")).toBe("ask")
    expect(await invoke("ssh.connect")).toBe("ask")
  })
})