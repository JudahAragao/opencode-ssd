import { describe, expect, test } from "bun:test"
import plugin from "../src/index.js"
import { createSshTools } from "../src/tools.js"
import { SSH_TOOL_LEAVES, isSshToolName, toDottedName, toEffectiveName } from "../src/naming.js"

/**
 * Smoke coverage for the SDK v2 entrypoint contract: the default export must
 * be a plugin definition, `setup` must declare the `ssh` namespace and
 * register the tool catalog through the tool transform, every tool must
 * declare a JSON Schema input and an effective-id permission, and the
 * returned cleanup must release the registrations.
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

function runTransform(transforms: Array<(editor: any) => void>) {
  const added: any[] = []
  const namespaces: Array<{ name: string; description: string }> = []
  transforms[0]({
    namespace: (ns: { name: string; description: string }) => namespaces.push(ns),
    add: (t: any) => added.push(t),
  })
  return { added, namespaces }
}

describe("SDK v2 plugin definition", () => {
  test("default export is a plugin definition with a stable id", () => {
    expect(plugin.id).toBe("opencode-ssh")
    expect(typeof plugin.setup).toBe("function")
  })

  test("setup declares the ssh namespace and registers the catalog through the tool transform", async () => {
    const { ctx, transforms } = createFakeContext()
    await plugin.setup(ctx)

    expect(transforms).toHaveLength(1)
    const { added, namespaces } = runTransform(transforms)

    // The namespace must be declared exactly once, before any add().
    expect(namespaces).toHaveLength(1)
    expect(namespaces[0].name).toBe("ssh")
    expect(typeof namespaces[0].description).toBe("string")

    const catalog = createSshTools()
    expect(added).toHaveLength(catalog.length)
    expect(added.map((t) => t.name).sort()).toEqual(catalog.map((t) => t.name).sort())
  })

  test("every tool is a short leaf registered under the ssh namespace", async () => {
    const { ctx, transforms } = createFakeContext()
    await plugin.setup(ctx)
    const { added, namespaces } = runTransform(transforms)

    expect(namespaces[0].name).toBe("ssh")
    for (const tool of added) {
      // Leaf names are namespace-free; the host joins them into ssh_<leaf>.
      expect(tool.name).not.toContain(".")
      expect(tool.name).not.toMatch(/^ssh_/)
      expect((SSH_TOOL_LEAVES as readonly string[])).toContain(tool.name)
    }
  })

  test("every tool declares a valid JSON Schema object input", async () => {
    const { ctx, transforms } = createFakeContext()
    await plugin.setup(ctx)
    const { added } = runTransform(transforms)

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

  test("every tool declares the effective-id permission its action is evaluated by", async () => {
    const { ctx, transforms } = createFakeContext()
    await plugin.setup(ctx)
    const { added } = runTransform(transforms)

    for (const tool of added) {
      // options.namespace makes the effective id deterministic: ssh_<leaf>.
      expect(tool.options?.namespace).toBe("ssh")
      expect(tool.options?.permission).toBe(`ssh_${tool.name}`)
    }
  })

  test("read-only and mutating tools are distinguishable by their permission action", () => {
    const tools = createSshTools()
    const byId = new Map(tools.map((t) => [t.options.permission, t]))

    expect(byId.get("ssh_list_sessions")?.options.permission).toBe("ssh_list_sessions")
    expect(byId.get("ssh_check_command")?.options.permission).toBe("ssh_check_command")
    expect(byId.get("ssh_audit_log")?.options.permission).toBe("ssh_audit_log")
    expect(byId.get("ssh_security_policy")?.options.permission).toBe("ssh_security_policy")

    expect(byId.get("ssh_security_policy_modify")?.options.permission).toBe("ssh_security_policy_modify")
    expect(byId.get("ssh_exec")?.options.permission).toBe("ssh_exec")
  })

  test("policy view and policy mutation are separate tools", () => {
    const tools = createSshTools()
    const view = tools.find((t) => t.name === "security_policy")
    const modify = tools.find((t) => t.name === "security_policy_modify")

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

describe("automatic dual-form name normalization", () => {
  test("effective ids match the dotted canonical names one-to-one", () => {
    for (const leaf of SSH_TOOL_LEAVES) {
      expect(toEffectiveName(`ssh.${leaf}`)).toBe(`ssh_${leaf}`)
      expect(toEffectiveName(`ssh_${leaf}`)).toBe(`ssh_${leaf}`)
      expect(toDottedName(`ssh_${leaf}`)).toBe(`ssh.${leaf}`)
      expect(toDottedName(`ssh.${leaf}`)).toBe(`ssh.${leaf}`)
    }
  })

  test("both spellings are recognized as SSH tools", () => {
    for (const leaf of SSH_TOOL_LEAVES) {
      expect(isSshToolName(`ssh.${leaf}`)).toBe(true)
      expect(isSshToolName(`ssh_${leaf}`)).toBe(true)
    }
    expect(isSshToolName("read")).toBe(false)
    expect(isSshToolName("bash")).toBe(false)
  })
})
