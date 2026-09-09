import { Client, type ConnectConfig } from "ssh2"
import { readFileSync, existsSync } from "fs"
import { resolve as pathResolve } from "path"
import { escapeShellArg } from "./sanitizer.js"

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
}

export interface SshConnectionInfo {
  id: string
  config: SshConnectionConfig
  connected: boolean
  connectedAt?: string
  lastActivity?: string
}

export class SshConnection {
  private client: Client
  private _config: SshConnectionConfig
  private _id: string
  private _connected = false
  private _connectedAt?: Date
  private _lastActivity?: Date
  private _reconnectAttempts = 0
  private _maxReconnectAttempts = 3

  constructor(id: string, config: SshConnectionConfig) {
    this._id = id
    this._config = config
    this.client = new Client()
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

  /**
   * Connect to the SSH server.
   */
  async connect(): Promise<void> {
    if (!this._config.username) {
      throw new Error("A username is required to connect (provide one or set User in the ssh config).")
    }

    return new Promise((resolve, reject) => {
      const connectConfig: ConnectConfig = {
        host: this._config.host,
        port: this._config.port,
        username: this._config.username,
        readyTimeout: this._config.timeout || 10000,
        keepaliveInterval: 10000,
        keepaliveCountMax: 3,
      }

      // Configure authentication
      if (this._config.authMethod === "password") {
        connectConfig.password = this._config.password
      } else {
        // Key-based authentication
        const keyPath = this._config.keyPath
          ? pathResolve(this._config.keyPath.replace("~", process.env.HOME || ""))
          : pathResolve(process.env.HOME || "", ".ssh", "id_rsa")

        if (!existsSync(keyPath)) {
          reject(new Error(`SSH key not found: ${keyPath}`))
          return
        }

        connectConfig.privateKey = readFileSync(keyPath, "utf-8")
        if (this._config.passphrase) {
          connectConfig.passphrase = this._config.passphrase
        }
      }

      this.client.on("ready", () => {
        this._connected = true
        this._connectedAt = new Date()
        this._lastActivity = new Date()
        this._reconnectAttempts = 0
        resolve()
      })

      this.client.on("error", (err: Error) => {
        this._connected = false
        if (this._reconnectAttempts < this._maxReconnectAttempts) {
          this._reconnectAttempts++
          // Attempt reconnect after delay
          setTimeout(() => {
            this.connect().catch(() => {})
          }, 1000 * this._reconnectAttempts)
        }
        reject(err)
      })

      this.client.on("close", () => {
        this._connected = false
      })

      this.client.on("end", () => {
        this._connected = false
      })

      this.client.connect(connectConfig)
    })
  }

  /**
   * Execute a command on the remote server.
   * Returns a stream for real-time output.
   */
  async exec(
    command: string,
    options?: { cwd?: string; timeout?: number },
  ): Promise<{ stdout: string; stderr: string; code: number | null; signal: string | undefined }> {
    if (!this._connected) {
      throw new Error("SSH connection is not active")
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

        // Set timeout
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
   * Get an SFTP session for file transfers.
   */
  async sftp(): Promise<any> {
    if (!this._connected) {
      throw new Error("SSH connection is not active")
    }

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
    if (this._connected) {
      this.client.end()
      this._connected = false
    }
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
