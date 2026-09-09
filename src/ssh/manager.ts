import { SshConnection, type SshConnectionConfig, type SshConnectionInfo } from "./connection.js"
import { randomBytes } from "crypto"

export interface SessionManagerOptions {
  maxSessions: number
}

export class SshSessionManager {
  private sessions: Map<string, SshConnection> = new Map()
  private aliases: Map<string, string> = new Map() // alias → session id
  private options: SessionManagerOptions

  constructor(options: SessionManagerOptions = { maxSessions: 5 }) {
    this.options = options
  }

  /**
   * Create a new SSH session.
   */
  async createSession(config: SshConnectionConfig): Promise<string> {
    // Check max sessions limit
    if (this.sessions.size >= this.options.maxSessions) {
      // Close the oldest session
      const oldestId = this.sessions.keys().next().value
      if (oldestId) {
        await this.closeSession(oldestId)
      }
    }

    const id = this.generateId()
    const connection = new SshConnection(id, config)

    await connection.connect()

    this.sessions.set(id, connection)

    if (config.alias) {
      this.aliases.set(config.alias.toLowerCase(), id)
    }

    return id
  }

  /**
   * Get a session by ID or alias.
   */
  getSession(identifier: string): SshConnection | undefined {
    // Try direct ID first
    const byId = this.sessions.get(identifier)
    if (byId) return byId

    // Try alias
    const aliasId = this.aliases.get(identifier.toLowerCase())
    if (aliasId) {
      return this.sessions.get(aliasId)
    }

    return undefined
  }

  /**
   * Close a session by ID.
   */
  async closeSession(id: string): Promise<boolean> {
    const connection = this.sessions.get(id)
    if (!connection) return false

    connection.disconnect()

    // Remove alias if exists
    if (connection.config.alias) {
      this.aliases.delete(connection.config.alias.toLowerCase())
    }

    this.sessions.delete(id)
    return true
  }

  /**
   * Close all sessions.
   */
  async closeAll(): Promise<void> {
    for (const [id] of this.sessions) {
      await this.closeSession(id)
    }
  }

  /**
   * List all active sessions.
   */
  listSessions(): SshConnectionInfo[] {
    const list: SshConnectionInfo[] = []
    for (const connection of this.sessions.values()) {
      list.push(connection.getInfo())
    }
    return list
  }

  /**
   * Get the count of active sessions.
   */
  get sessionCount(): number {
    return this.sessions.size
  }

  /**
   * Check if a session exists.
   */
  hasSession(id: string): boolean {
    return this.getSession(id) !== undefined
  }

  /**
   * Generate a unique session ID.
   */
  private generateId(): string {
    return `ssh-${randomBytes(8).toString("hex")}`
  }
}
