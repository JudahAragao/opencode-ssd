import { Client, type ConnectConfig } from "ssh2"
import { readFileSync, existsSync } from "fs"
import { resolve as pathResolve } from "path"
import { escapeShellArg } from "./sanitizer.js"
import { verifyHostKey } from "./known_hosts.js"
import { prepareProxy, type ProxySpec } from "./proxy.js"

export interface SshConnectionConfig {
  host: string
  port: number
  /** SSH username, resolved from args or the ssh config. */
  username?: string
  authMethod: "password" | "key"
  password?: string
  keyPath?: string
  passphrase?: string
  /** Timeout in milliseconds */
  timeout?: number
  /** Connection alias for display */
  alias?: string
  /** Reject hosts whose key is not (an identical match) in known_hosts. */
  strictHostKey?: boolean
  /** Custom path to a known_hosts file. */
  knownHostsPath?: string
  /** SSH config default path, used to locate known_hosts next to it. */
  sshConfigPath?: string
  /** ProxyJump / ProxyCommand support. */
  proxy?: ProxySpec
  /** Automatically reconnect a dropped session on the next exec/sftp. */
  autoReconnect?: boolean
}

export interface SshConnectionInfo {
  id: string
  config: SshConnectionConfig
  connected: boolean
  connectedAt?: string
  lastActivity?: string
}

const DEFAULT_KNOWN_HOSTS = () => pathResolve(process.env.HOME || "", ".ssh", "known_hosts")

export class SshConnection {
  private client!: Client
  private _config: SshConnectionConfig
  private _id: string
  private _connected = false
  private _connectedAt?: Date
  private _lastActivity?: Date
  private _maxAttempts = 3
  private _attempts = 0
  private _proxyCleanup?: () => void
  private _hostKeyVerdict?: "ok" | "changed" | "unknown"

  constructor(id: string, config: SshConnectionConfig) {
    this._id = id
    this._config = config
    this._config.strictHostKey = this._config.strictHostKey ?? false
    this._config.autoReconnect = this._config.autoReconnect ?? true
  }

  get id(): string {
    return this._id
  }

  get config(): SshConnectionConfig {
    return this._config
  }

  get connected(): boolean {
    return this._connected
  }

  get connectedAt(): Date | undefined {
    return this._connectedAt
  }

  get lastActivity(): Date | undefined {
    return this._lastActivity
  }

  /** Result of the last known_hosts check (undefined when disabled). */
  get hostKeyVerdict(): "ok" | "changed" | "unknown" | undefined {
    return this._hostKeyVerdict
  }

  /**
   * Connect to the SSH server, with bounded retries.
   */
  async connect(): Promise<void> {
    if (!this._config.username) {
      throw new Error("A username is required to connect (provide one or set User in the ssh config).")
    }

    this._attempts = 0
    await this.connectWithBackoff()

    // Credentials are only needed for the handshake; drop them from memory
    // once the connection is established so they are not retained.
    this._config.password = undefined
  }

  private async connectWithBackoff(): Promise<void> {
    try {
      const cfg = await this.buildConnectConfig()
      await this.openConnection(cfg)
    } catch (err) {
      this._attempts++
      if (this._attempts < this._maxAttempts) {
        await new Promise((r) => setTimeout(r, 1000 * this._attempts))
        return this.connectWithBackoff()
      }
      throw err
    }
  }

  private async buildConnectConfig(): Promise<ConnectConfig> {
    const connectConfig: ConnectConfig = {
      host: this._config.host,
      port: this._config.port,
      username: this._config.username,
      readyTimeout: this._config.timeout || 10000,
      keepaliveInterval: 10000,
      keepaliveCountMax: 3,
    }

    // ── Host key verification (MITM protection) ──
    if (this._config.strictHostKey) {
      const knownHostsPath = this._config.knownHostsPath || DEFAULT_KNOWN_HOSTS()
      connectConfig.hostVerifier = (key: Buffer): boolean => {
        const verdict = verifyHostKey(this._config.host, key, knownHostsPath, this._config.port)
        this._hostKeyVerdict = verdict
        // A changed key is always rejected. An unknown key is only accepted
        // in non-strict mode; here strict mode requires it to be present.
        return verdict === "ok"
      }
    }

    // ── Proxy tunnel (ProxyJump / ProxyCommand) ──
    if (this._config.proxy) {
      const prepared = await prepareProxy(this._config.proxy, {
        host: this._config.host,
        port: this._config.port,
        username: this._config.username,
        keyPath: this._config.keyPath,
        passphrase: this._config.passphrase,
      })
      this._proxyCleanup = prepared.cleanup
      connectConfig.sock = prepared.sock
    }

    // ── Authentication ──
    if (this._config.authMethod === "password") {
      if (this._config.password) {
        connectConfig.password = this._config.password
      }
    } else {
      const keyPath = this._config.keyPath
        ? pathResolve(this._config.keyPath.replace("~", process.env.HOME || ""))
        : pathResolve(process.env.HOME || "", ".ssh", "id_rsa")

      if (!existsSync(keyPath)) {
        throw new Error(`SSH key not found: ${keyPath}`)
      }

      connectConfig.privateKey = readFileSync(keyPath, "utf-8")
      if (this._config.passphrase) {
        connectConfig.passphrase = this._config.passphrase
      }
    }

    return connectConfig
  }

  private async openConnection(cfg: ConnectConfig): Promise<void> {
    // A fresh Client per attempt so a failed handshake never leaves the
    // previous transport in an unusable state.
    const client = new Client()
    this.client = client

    return new Promise((resolve, reject) => {
      client.on("ready", () => {
        this._connected = true
        this._connectedAt = new Date()
        this._lastActivity = new Date()
        resolve()
      })
      client.on("error", (err: Error) => {
        this._connected = false
        reject(err)
      })
      client.on("close", () => {
        this._connected = false
      })
      client.on("end", () => {
        this._connected = false
      })
      client.connect(cfg)
    })
  }

  /**
   * Execute a command on the remote server. Automatically reconnects a
   * dropped session before running.
   */
  async exec(
    command: string,
    options?: { cwd?: string; timeout?: number },
  ): Promise<{ stdout: string; stderr: string; code: number | null; signal: string | undefined }> {
    if (!this._connected) {
      if (this._config.autoReconnect === false) {
        throw new Error("SSH connection is not active")
      }
      await this.connect()
    }

    this._lastActivity = new Date()

    const wrappedCommand = options?.cwd
      ? `cd ${escapeShellArg(options.cwd)} && ${command}`
      : command

    return new Promise((resolve, reject) => {
      const timeoutMs = (options?.timeout || 30) * 1000
      let timeoutId: ReturnType<typeof setTimeout> | undefined

      this.client.exec(wrappedCommand, (err, stream) => {
        if (err) {
          reject(err)
          return
        }

        let stdout = ""
        let stderr = ""
        let killed = false

        if (timeoutMs > 0) {
          timeoutId = setTimeout(() => {
            killed = true
            stream.close()
            reject(new Error(`Command timed out after ${timeoutMs / 1000}s`))
          }, timeoutMs)
        }

        stream.on("data", (data: Buffer) => {
          stdout += data.toString("utf-8")
        })

        stream.stderr.on("data", (data: Buffer) => {
          stderr += data.toString("utf-8")
        })

        stream.on("close", (code: number | null, signal: string | null) => {
          if (timeoutId) clearTimeout(timeoutId)
          if (killed) return

          resolve({
            stdout,
            stderr,
            code: code ?? 1,
            signal: signal ?? undefined,
          })
        })

        stream.on("error", (streamErr: Error) => {
          if (timeoutId) clearTimeout(timeoutId)
          reject(streamErr)
        })
      })
    })
  }

  /**
   * Execute a command and return it as a readable stream (for real-time output).
   */
  execStream(
    command: string,
    options?: { cwd?: string; timeout?: number },
  ): NodeJS.ReadableStream | null {
    if (!this._connected) {
      return null
    }

    this._lastActivity = new Date()

    const wrappedCommand = options?.cwd
      ? `cd ${escapeShellArg(options.cwd)} && ${command}`
      : command

    // This returns a stream that can be consumed externally
    // The actual streaming is handled by the executor
    return null as any // Placeholder - actual streaming handled in executor.ts
  }

  /**
   * Get an SFTP session for file transfers. Automatically reconnects a
   * dropped session before returning.
   */
  async sftp(): Promise<any> {
    if (!this._connected) {
      if (this._config.autoReconnect === false) {
        throw new Error("SSH connection is not active")
      }
      await this.connect()
    }

    this._lastActivity = new Date()

    return new Promise((resolve, reject) => {
      this.client.sftp((err, sftp) => {
        if (err) {
          reject(err)
          return
        }
        resolve(sftp)
      })
    })
  }

  /**
   * Disconnect from the SSH server.
   */
  disconnect(): void {
    if (this.client) {
      this.client.end()
    }
    this._connected = false
    this._proxyCleanup?.()
    this._proxyCleanup = undefined
  }

  /**
   * Get connection info for display.
   */
  getInfo(): SshConnectionInfo {
    return {
      id: this._id,
      config: {
        host: this._config.host,
        port: this._config.port,
        username: this._config.username,
        authMethod: this._config.authMethod,
        alias: this._config.alias,
        // NEVER expose password or key in info
      },
      connected: this._connected,
      connectedAt: this._connectedAt?.toISOString(),
      lastActivity: this._lastActivity?.toISOString(),
    }
  }
}