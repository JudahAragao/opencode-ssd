import { describe, expect, test } from "bun:test"
import plugin from "../src/index.js"
import { createSshTools } from "../src/tools.js"

/**
 * Smoke coverage for the SDK v2 entrypoint contract: the default export must
 * be a plugin definition, `setup` must register the tool catalog through the
 * tool transform, every tool must declare a JSON Schema input and a
 * permission, and the returned cleanup must release the registrations.
 */
function createFakeContext() {
  const transforms: Array<(editor: any) => void> = []
  const hookRegistrations: Array<{ dispose(): Promise<void> }> = []
  let disposed = 0

  const track = <T extends { dispose(): Promise<void> }>(registration: Promise<T>) => {
    const resolved = registration.then((r) => {
      const dispose = r.dispose.bind(r)
      r.dispose = () => {
        disposed++
        return dispose()
      }
      return r
    })
    hookRegistrations.push({
      dispose: () => resolved.then((r) => r.dispose()),
    })
    return resolved
  }

  const ctx = {
    app: { version: "2.0.0" },
    location: { directory: "/tmp/opencode-ssh-v2", project: { id: "test", directory: "/tmp", canonical: "/tmp" } },
    options: { mode: "full" },
    tool: {
      transform: (callback: (editor: any) => void) => {
        transforms.push(callback)
        return track(Promise.resolve({ dispose: async () => {} }))
      },
      hook: (n: string, cb: any) => track(Promise.resolve({ dispose: async () => {} })),
    },
    session: { hook: (n: string, cb: any) => track(Promise.resolve({ dispose: async () => {} })) },
    permission: { hook: (n: string, cb: any) => track(Promise.resolve({ dispose: async () => {} })) },
    storage: { get: async () => undefined, set: async () => {}, remove: async () => {} },
  } as any

  return { ctx, transforms, hookRegistrations, disposedCount: () => disposed }
}

describe("SDK v2 plugin definition", () => {
  test("default export is a plugin definition with a stable id", () => {
    expect(plugin.id).toBe("opencode-ssh")
    expect(typeof plugin.setup).toBe("function")
  })

  test("setup registers the whole tool catalog through the tool transform", async () => {
    const { ctx, transforms } = createFakeContext()
    await plugin.setup(ctx)

    expect(transforms).toHaveLength(1)
    const added: any[] = []
    transforms[0]({ add: (t: any) => added.push(t) })

    const catalog = createSshTools()
    expect(added).toHaveLength(catalog.length)
    expect(added.map((t) => t.name).sort()).toEqual(catalog.map((t) => t.name).sort())
  })

  test("every tool declares a valid JSON Schema object input", async () => {
    const { ctx, transforms } = createFakeContext()
    await plugin.setup(ctx)
    const added: any[] = []
    transforms[0]({ add: (t: any) => added.push(t) })

    for (const tool of added) {
      expect(tool.input.type).toBe("object")
      expect(tool.input.additionalProperties).toBe(false)
      expect(typeof tool.input.properties).toBe("object")
      for (const required of tool.input.required ?? []) {
        expect(tool.input.properties[required]).toBeDefined()
      }
      for (const [name, prop] of Object.entries<any>(tool.input.properties)) {
        expect(["string", "number", "boolean"]).toContain(prop.type)
        expect(typeof prop.description).toBe("string")
        if (prop.type === "string" && prop.enum) {
          expect(Array.isArray(prop.enum)).toBe(true)
          expect(prop.enum.length).toBeGreaterThan(0)
        }
        expect(name).toMatch(/^[a-z][a-z0-9_]*$/)
      }
    }
  })

  test("every tool declares the permission its action is evaluated by", async () => {
    const { ctx, transforms } = createFakeContext()
    await plugin.setup(ctx)
    const added: any[] = []
    transforms[0]({ add: (t: any) => added.push(t) })

    for (const tool of added) {
      expect(tool.options?.permission).toBe(tool.name)
    }
  })

  test("read-only and mutating tools are distinguishable by their permission action", async () => {
    const tools = createSshTools()
    const byName = new Map(tools.map((t) => [t.name, t]))

    expect(byName.get("ssh.list_sessions")?.options.permission).toBe("ssh.list_sessions")
    expect(byName.get("ssh.check_command")?.options.permission).toBe("ssh.check_command")
    expect(byName.get("ssh.audit_log")?.options.permission).toBe("ssh.audit_log")
    expect(byName.get("ssh.security_policy")?.options.permission).toBe("ssh.security_policy")

    expect(byName.get("ssh.security_policy_modify")?.options.permission).toBe("ssh.security_policy_modify")
    expect(byName.get("ssh.exec")?.options.permission).toBe("ssh.exec")
  })

  test("policy view and policy mutation are separate tools", () => {
    const tools = createSshTools()
    const view = tools.find((t) => t.name === "ssh.security_policy")
    const modify = tools.find((t) => t.name === "ssh.security_policy_modify")

    // The view tool must not be able to mutate, so it takes no action argument.
    expect(view?.input.properties.action).toBeUndefined()
    expect(Object.keys(modify?.input.properties ?? {}).sort()).toEqual(["action", "pattern"])
  })

  test("setup returns a cleanup that releases every registration", async () => {
    const { ctx, hookRegistrations, disposedCount } = createFakeContext()
    const cleanup = await plugin.setup(ctx)

    // 1 tool transform + 4 hooks.
    expect(hookRegistrations).toHaveLength(5)
    await cleanup?.()
    expect(disposedCount()).toBe(5)
  })
})

describe("no tool-name compatibility layer remains", () => {
  test("the catalog exposes canonical dotted names only", () => {
    for (const tool of createSshTools()) {
      // The namespace separator is a dot; there is no underscored projection
      // of the form `ssh_<something>` that replaced it.
      expect(tool.name).toMatch(/^ssh\.[a-z_]+$/)
      expect(tool.name).not.toMatch(/^ssh_/)
    }
  })
})
