import { describe, expect, test } from "bun:test"
import { registerSshHooks, type SshHookOptions } from "../src/hooks.js"

/**
 * Minimal stand-in for the SDK v2 plugin context. It records the callback
 * registered for each (domain, hook) pair so a test can invoke it directly
 * with a mutable event, which is exactly the contract `ctx.*.hook` exposes.
 */
function createFakeContext() {
  const registered = {
    session: {} as Record<string, (event: any) => void>,
    permission: {} as Record<string, (event: any) => void>,
    tool: {} as Record<string, (event: any) => void>,
  }

  const register =
    (domain: "session" | "permission" | "tool") =>
    (name: string, callback: (event: any) => void) => {
      registered[domain][name] = callback
      return Promise.resolve({ dispose: () => Promise.resolve() })
    }

  const ctx = {
    session: { hook: register("session") },
    permission: { hook: register("permission") },
    tool: { hook: register("tool") },
  } as unknown as Parameters<typeof registerSshHooks>[0]

  return { ctx, registered }
}

async function evaluate(
  action: string,
  options: SshHookOptions = {},
): Promise<string | undefined> {
  const { ctx, registered } = createFakeContext()
  await registerSshHooks(ctx, options)
  const event: { action: string; effect: string } = { action, effect: "pending" }
  registered.permission.evaluate?.(event)
  return event.effect === "pending" ? undefined : event.effect
}

describe("permission evaluate — security policy confirmation", () => {
  test("viewing the policy is auto-approved (read-only)", async () => {
    expect(await evaluate("ssh.security_policy")).toBe("allow")
  })

  test("policy mutations always ask (never auto-approved)", async () => {
    expect(await evaluate("ssh.security_policy_modify")).toBe("ask")
  })
})

describe("permission evaluate — read-only operations", () => {
  test("list_sessions / check_command / audit_log are auto-approved", async () => {
    expect(await evaluate("ssh.list_sessions")).toBe("allow")
    expect(await evaluate("ssh.check_command")).toBe("allow")
    expect(await evaluate("ssh.audit_log")).toBe("allow")
  })
})

describe("permission evaluate — execution commands", () => {
  test("exec and exec_batch always ask", async () => {
    expect(await evaluate("ssh.exec")).toBe("ask")
    expect(await evaluate("ssh.exec_batch")).toBe("ask")
  })

  test("connect, disconnect and transfers always ask", async () => {
    expect(await evaluate("ssh.connect")).toBe("ask")
    expect(await evaluate("ssh.disconnect")).toBe("ask")
    expect(await evaluate("ssh.upload")).toBe("ask")
    expect(await evaluate("ssh.download")).toBe("ask")
  })
})

describe("permission evaluate — scope", () => {
  test("non-SSH actions are left untouched", async () => {
    expect(await evaluate("read")).toBeUndefined()
    expect(await evaluate("bash")).toBeUndefined()
  })
})

describe("session context hook — system prompt", () => {
  test("injects the SSH surface exactly once", async () => {
    const { ctx, registered } = createFakeContext()
    await registerSshHooks(ctx, { mode: "restricted" })

    const first: { system: Array<{ type: string; text: string }> } = { system: [] }
    registered.session.context?.(first)
    expect(first.system).toHaveLength(1)
    expect(first.system[0].type).toBe("text")
    expect(first.system[0].text).toContain("SSH Access Plugin")
    expect(first.system[0].text).toContain("RESTRICTED MODE")
    expect(first.system[0].text).toContain("ssh.security_policy_modify")

    const second: { system: unknown[] } = { system: [] }
    registered.session.context?.(second)
    expect(second.system).toHaveLength(0)
  })
})

describe("tool execute.before — command validation", () => {
  async function before(tool: string, input: unknown) {
    const { ctx, registered } = createFakeContext()
    await registerSshHooks(ctx, { mode: "full" })
    registered.tool["execute.before"]?.({ tool, input })
  }

  test("destructive commands are blocked before execution", async () => {
    await expect(before("ssh.exec", { command: "rm -rf /" })).rejects.toThrow(
      "DESTRUCTIVE COMMAND BLOCKED",
    )
  })

  test("commands outside the allowlist are blocked in restricted mode", async () => {
    const { ctx, registered } = createFakeContext()
    await registerSshHooks(ctx, { mode: "restricted" })
    // `curl` without `-I` is neither read-only nor allowlisted in restricted mode.
    expect(() =>
      registered.tool["execute.before"]?.({ tool: "ssh.exec", input: { command: "curl http://example.com" } }),
    ).toThrow("COMMAND NOT ALLOWED")
  })

  test("safe commands pass through", async () => {
    await before("ssh.exec", { command: "echo hi" })
  })

  test("non-exec tools and non-ssh tools are ignored", async () => {
    await before("ssh.connect", { host: "example.com" })
    await before("read", { command: "rm -rf /" })
  })
})

describe("disposal", () => {
  test("returns one disposal per registered hook", async () => {
    const { ctx } = createFakeContext()
    const disposals = await registerSshHooks(ctx)
    expect(disposals).toHaveLength(4)
    await Promise.all(disposals.map((dispose) => dispose()))
  })
})
