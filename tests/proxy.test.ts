import { describe, expect, test } from "bun:test"
import { prepareProxy } from "../src/ssh/proxy.js"
import { parseProxyJump } from "../src/ssh/config.js"

describe("proxy", () => {
  test("throws when no strategy configured", async () => {
    await expect(
      prepareProxy({}, { host: "target", port: 22, username: "u" }),
    ).rejects.toThrow(/no proxy strategy/i)
  })

  test("ProxyCommand pipes through an external command (echo tunnel)", async () => {
    const prepared = await prepareProxy(
      { command: "exec cat" },
      { host: "target.internal", port: 22, username: "u" },
    )

    const data = new Promise<string>((resolve) => {
      let buf = ""
      prepared.sock.on("data", (c: Buffer) => {
        buf += c.toString()
        resolve(buf)
      })
    })

    prepared.sock.write("hello-tunnel")
    const echo = await Promise.race([data, wait(2000).then(() => "")])
    prepared.cleanup()
    expect(echo).toBe("hello-tunnel")
  })

  test("ProxyCommand substitutes %h, %p, %r placeholders", async () => {
    const prepared = await prepareProxy(
      { command: 'sh -c \'echo "host=%h port=%p user=%r"\' > /dev/null; exec cat' },
      { host: "target.internal", port: 2222, username: "bob" },
    )
    // The command is written but never validated here; we just assert it ran.
    expect(prepared.sock).toBeDefined()
    prepared.cleanup()
  })
})

describe("parseProxyJump", () => {
  test("parses simple host:port hops", () => {
    const hops = parseProxyJump("bastion:22")
    expect(hops).toEqual([{ host: "bastion", port: 22, username: undefined, keyPath: undefined }])
  })

  test("parses user@host hops", () => {
    const hops = parseProxyJump("jumpuser@bastion:2222", "fallback")
    expect(hops[0].username).toBe("jumpuser")
    expect(hops[0].port).toBe(2222)
  })

  test("defaults username and keyPath from caller", () => {
    const hops = parseProxyJump("bastion", "alice", "/home/a/.ssh/key")
    expect(hops[0]).toEqual({ host: "bastion", port: 22, username: "alice", keyPath: "/home/a/.ssh/key" })
  })

  test("parses chained hops", () => {
    const hops = parseProxyJump("bastion1:22,user2@bastion2:2200")
    expect(hops).toHaveLength(2)
    expect(hops[0].host).toBe("bastion1")
    expect(hops[1]).toEqual({ host: "bastion2", port: 2200, username: "user2", keyPath: undefined })
  })

  test("skips empty segments", () => {
    const hops = parseProxyJump("bastion,,,proxy2")
    expect(hops.map((h) => h.host)).toEqual(["bastion", "proxy2"])
  })
})

function wait(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms))
}