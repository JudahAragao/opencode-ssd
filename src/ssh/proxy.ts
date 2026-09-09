/**
 * Proxy support for SSH connections:
 *  - ProxyJump: hop through one or more jump hosts (OpenSSH ProxyJump).
 *  - ProxyCommand: use an external command to open the tunnel
 *    (OpenSSH ProxyCommand), e.g. `ssh -W %h:%p bastion`.
 */
import { Client } from "ssh2"
import { spawn, type ChildProcess } from "child_process"
import { Duplex } from "stream"
import { readFileSync, existsSync } from "fs"

export interface JumpHost {
  host: string
  port: number
  username?: string
  keyPath?: string
}

export interface ProxySpec {
  jumps?: JumpHost[]
  command?: string
}

export interface ProxyTarget {
  host: string
  port: number
  username?: string
  keyPath?: string
  passphrase?: string
}

export interface PreparedProxy {
  /** Stream the main connection should use instead of a fresh TCP socket. */
  sock: Duplex
  /** Release intermediate resources (jump clients / child processes). */
  cleanup(): void
}

function loadPrivateKey(keyPath?: string): Buffer | undefined {
  if (!keyPath) return undefined
  const path = keyPath
  if (!existsSync(path)) return undefined
  return readFileSync(path)
}

function connectClient(
  opts: { host: string; port: number; username: string; keyPath?: string; passphrase?: string; timeoutMs: number },
  sock?: Duplex,
): Promise<Client> {
  const privateKey = loadPrivateKey(opts.keyPath)
  return new Promise((resolve, reject) => {
    const client = new Client()
    const timer = setTimeout(() => {
      client.destroy()
      reject(new Error(`Proxy connection to ${opts.username}@${opts.host}:${opts.port} timed out`))
    }, opts.timeoutMs)

    client
      .on("ready", () => {
        clearTimeout(timer)
        resolve(client)
      })
      .on("error", (err: Error) => {
        clearTimeout(timer)
        reject(err)
      })
      .connect({
        host: opts.host,
        port: opts.port,
        username: opts.username,
        readyTimeout: opts.timeoutMs,
        ...(sock ? { sock } : {}),
        ...(privateKey ? { privateKey } : {}),
        ...(opts.passphrase ? { passphrase: opts.passphrase } : {}),
      })
  })
}

function forwardOut(client: Client, srcIP: string, srcPort: number, dstIP: string, dstPort: number): Promise<Duplex> {
  return new Promise((resolve, reject) => {
    client.forwardOut(srcIP, srcPort, dstIP, dstPort, (err, stream) => {
      if (err) reject(err)
      else resolve(stream as Duplex)
    })
  })
}

/**
 * Build a tunnel to `target` through the given proxy. The returned stream is
 * passed as the `sock` of the target connection.
 */
export async function prepareProxy(proxy: ProxySpec, target: ProxyTarget): Promise<PreparedProxy> {
  const timeoutMs = 10_000

  // ── ProxyCommand: spawn and use its stdio as the socket ──
  if (proxy.command && proxy.command.trim()) {
    const cmd = proxy.command
      .replaceAll("%h", target.host)
      .replaceAll("%p", String(target.port))
      .replaceAll("%r", target.username || process.env.USER || "")
    const child: ChildProcess = spawn("sh", ["-c", cmd], { stdio: ["pipe", "pipe", "inherit"] })

    const tunnel = new Duplex({
      read() {
        // Data is pushed manually from child.stdout below.
      },
      write(chunk, _enc, cb) {
        child.stdin?.write(chunk, cb)
      },
      final(cb) {
        child.stdin?.end(cb)
      },
    })

    child.stdout?.on("data", (chunk) => tunnel.push(chunk))
    child.stdout?.on("end", () => tunnel.push(null))
    child.stdout?.on("error", (err) => tunnel.destroy(err))
    child.on("error", (err) => tunnel.destroy(err))

    return {
      sock: tunnel,
      cleanup: () => {
        if (!child.killed) child.kill()
      },
    }
  }

  // ── ProxyJump: chain clients through hops, last hop receives the target ──
  const jumps = proxy.jumps || []
  if (jumps.length === 0) {
    throw new Error("No proxy strategy configured")
  }

  const clients: Client[] = []
  let sock: Duplex | undefined

  try {
    for (let i = 0; i < jumps.length; i++) {
      const hop = jumps[i]
      const next = jumps[i + 1]
      const destHost = next ? next.host : target.host
      const destPort = next ? next.port : target.port
      const destUser = next ? next.username || hop.username || target.username : target.username

      const username = hop.username || target.username || process.env.USER || "root"
      const keyPath = hop.keyPath || target.keyPath

      // The next-hop client talks over the previous hop's forwarded stream
      const client = await connectClient(
        { host: hop.host, port: hop.port, username, keyPath, timeoutMs },
        sock,
      )
      clients.push(client)

      // Open the outbound channel to the next destination
      sock = await forwardOut(client, "127.0.0.1", 0, destHost, destPort)
      void destUser
    }

    if (!sock) throw new Error("Failed to build proxy tunnel")
    const finalSock = sock
    return {
      sock: finalSock,
      cleanup: () => {
        for (const c of clients) c.end()
      },
    }
  } catch (err) {
    for (const c of clients) c.end()
    throw err
  }
}