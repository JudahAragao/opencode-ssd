import { describe, expect, test, afterAll } from "bun:test"
import { generateKeyPairSync } from "crypto"
import { mkdtempSync, writeFileSync } from "fs"
import { join } from "path"
import { tmpdir } from "os"
import { Server, Client, utils } from "ssh2"
import { SshConnection, type SshConnectionConfig } from "../src/ssh/connection.js"

// ── In-process SSH server ──
// ssh2's key parser only accepts traditional PKCS#1 PEM ("BEGIN RSA PRIVATE KEY")
// and OpenSSH-format keys. A PKCS#8 export ("BEGIN PRIVATE KEY") is rejected with
// "Unsupported key format", for both `hostKeys` and client keys, so use PKCS#1.
const { privateKey: hostPriv, publicKey: _hostPub } = generateKeyPairSync("rsa", { modulusLength: 2048 })
const hostKeyPem = hostPriv.export({ type: "pkcs1", format: "pem" }).toString()
void _hostPub

// Client identity used for key-based auth (temp PEM file + wire pub blob).
const { privateKey: userPriv } = generateKeyPairSync("rsa", { modulusLength: 2048 })
const userKeyPem = userPriv.export({ type: "pkcs1", format: "pem" }).toString()
// Derive the expected public-key blob with ssh2's own parser rather than
// hand-encoding the wire format.
const userPubBlob = (utils.parseKey(userKeyPem) as { getPublicSSH(): Buffer }).getPublicSSH()

const keyFile = (() => {
  const dir = mkdtempSync(join(tmpdir(), "it-key-"))
  const f = join(dir, "id_rsa")
  writeFileSync(f, userKeyPem)
  return f
})()

interface TestServer {
  port: number
  close(): Promise<void>
}

function startServer(): Promise<TestServer> {
  return new Promise((resolve, reject) => {
    const server = new Server({ hostKeys: [hostKeyPem] }, (client) => {
      client
        .on("authentication", (ctx) => {
          if (ctx.method === "password" && ctx.username === "testuser" && ctx.password === "secret") {
            ctx.accept()
          } else if (ctx.method === "publickey" && ctx.key.algo === "ssh-rsa" && ctx.key.data.equals(userPubBlob)) {
            ctx.accept()
          } else {
            ctx.reject(["password", "publickey"])
          }
        })
        .on("ready", () => {
          client.on("session", (accept: () => any) => {
            const session = accept()
            session.on("exec", (execAccept: () => any, _reject: any, info: { command: string }) => {
              const stream = execAccept()
              if (info.command === "echo hi") {
                stream.write("hi\n")
                stream.exit(0)
              } else if (info.command === "whoami") {
                stream.write("testuser\n")
                stream.exit(0)
              } else if (info.command === "fail") {
                stream.stderr.write("boom\n")
                stream.exit(1)
              } else {
                stream.exit(127)
              }
              stream.end()
            })
          })
        })
    })

    server.on("error", reject)
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as { port: number }
      resolve({
        port: addr.port,
        close: () =>
          new Promise((r) => {
            server.close(() => r())
            server.unref?.()
          }),
      })
    })
  })
}

// If the server cannot start these tests must fail loudly. Silently
// degrading to `port: 0` used to make every test in this file a no-op that
// reported success without ever opening a connection.
const server: TestServer = await startServer()

afterAll(async () => {
  await server.close()
})

function connConfig(overrides: Partial<SshConnectionConfig> = {}): SshConnectionConfig {
  return {
    host: "127.0.0.1",
    port: server.port,
    username: "testuser",
    authMethod: "password",
    password: "secret",
    timeout: 5000,
    ...overrides,
  }
}

describe("SSH integration (in-process server)", () => {
  test("connects with password and execs a command", async () => {
    const conn = new SshConnection("it-001", connConfig())
    await conn.connect()
    expect(conn.connected).toBe(true)

    const result = await conn.exec("echo hi")
    expect(result.stdout.trim()).toBe("hi")
    expect(result.code).toBe(0)

    conn.disconnect()
    expect(conn.connected).toBe(false)
  })

  test("clears the password from memory after a successful connect", async () => {
    const conn = new SshConnection("it-002", connConfig())
    await conn.connect()
    expect((conn.config as any).password).toBeUndefined()
    conn.disconnect()
  })

  test("captures the real host key and validates it via strict_host_key", async () => {

    // 1) Capture the wire-format host key the server actually sends.
    const captured: Buffer[] = []
    await new Promise<void>((resolve, reject) => {
      const probe = new Client()
      probe
        .on("ready", () => {
          probe.end()
          resolve()
        })
        .on("error", reject)
        .connect({
          host: "127.0.0.1",
          port: server.port,
          username: "testuser",
          password: "secret",
          hostVerifier: (key: Buffer) => {
            captured.push(key)
            return true
          },
        })
    })

    expect(captured.length).toBeGreaterThan(0)
    const realKey = captured[0]

    // 2) strict_host_key against a known_hosts file containing the real key.
    const dir = mkdtempSync(join(tmpdir(), "it-kh-"))
    const kh = join(dir, "known_hosts")
    writeFileSync(kh, `127.0.0.1 ssh-ed25519 ${realKey.toString("base64")}\n`)

    const ok = new SshConnection("it-003", connConfig({ strictHostKey: true, knownHostsPath: kh }))
    await ok.connect()
    expect(ok.hostKeyVerdict).toBe("ok")
    ok.disconnect()
  })

  test("strict_host_key REJECTS a changed host key (MITM protection)", async () => {

    const dir = mkdtempSync(join(tmpdir(), "it-kh-"))
    const kh = join(dir, "known_hosts")
    writeFileSync(kh, `127.0.0.1 ssh-rsa ${Buffer.from("attacker-key-blob-0001").toString("base64")}\n`)

    const bad = new SshConnection(
      "it-004",
      connConfig({ strictHostKey: true, knownHostsPath: kh, autoReconnect: false }),
    )
    await expect(bad.connect()).rejects.toThrow()
  })

  test("auto-reconnects a dropped key session before running a command", async () => {
    const conn = new SshConnection(
      "it-005",
      connConfig({ authMethod: "key", keyPath: keyFile, password: undefined }),
    )
    await conn.connect()

    conn.disconnect()
    expect(conn.connected).toBe(false)

    // Lazy reconnect kicks in (autoReconnect defaults to true).
    const result = await conn.exec("whoami")
    expect(result.stdout.trim()).toBe("testuser")

    // The key session doesn't hold a password; reconnect worked from disk.
    expect((conn.config as any).password).toBeUndefined()
    conn.disconnect()
  })

  test("propagates a non-zero exit code", async () => {
    const conn = new SshConnection("it-006", connConfig())
    await conn.connect()
    const result = await conn.exec("fail")
    expect(result.code).toBe(1)
    expect(result.stderr.trim()).toBe("boom")
    conn.disconnect()
  })
})