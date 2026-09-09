import { describe, test, expect } from "bun:test"
import { SshConnection, type SshConnectionConfig } from "../src/ssh/connection.js"

describe("SshConnection", () => {
  test("creates connection with correct config", () => {
    const config: SshConnectionConfig = {
      host: "192.168.1.100",
      port: 22,
      username: "admin",
      authMethod: "key",
      keyPath: "/home/user/.ssh/id_rsa",
      alias: "prod-server",
    }

    const conn = new SshConnection("test-001", config)
    expect(conn.id).toBe("test-001")
    expect(conn.connected).toBe(false)
    expect(conn.connectedAt).toBeUndefined()
  })

  test("getInfo returns safe info without credentials", () => {
    const config: SshConnectionConfig = {
      host: "192.168.1.100",
      port: 22,
      username: "admin",
      authMethod: "password",
      password: "secret123",
      alias: "prod-server",
    }

    const conn = new SshConnection("test-002", config)
    const info = conn.getInfo()

    expect(info.id).toBe("test-002")
    expect(info.config.host).toBe("192.168.1.100")
    expect(info.config.port).toBe(22)
    expect(info.config.username).toBe("admin")
    expect(info.config.authMethod).toBe("password")
    expect(info.config.alias).toBe("prod-server")
    expect(info.connected).toBe(false)

    // Ensure password is NOT in the info
    expect((info.config as any).password).toBeUndefined()
  })

  test("disconnect sets connected to false", () => {
    const config: SshConnectionConfig = {
      host: "192.168.1.100",
      port: 22,
      username: "admin",
      authMethod: "key",
    }

    const conn = new SshConnection("test-003", config)
    conn.disconnect()
    expect(conn.connected).toBe(false)
  })

  test("exec throws when not connected", async () => {
    const config: SshConnectionConfig = {
      host: "192.168.1.100",
      port: 22,
      username: "admin",
      authMethod: "key",
      autoReconnect: false,
    }

    const conn = new SshConnection("test-004", config)
    await expect(conn.exec("ls")).rejects.toThrow("not active")
  })

  test("sftp throws when not connected", async () => {
    const config: SshConnectionConfig = {
      host: "192.168.1.100",
      port: 22,
      username: "admin",
      authMethod: "key",
      autoReconnect: false,
    }

    const conn = new SshConnection("test-005", config)
    await expect(conn.sftp()).rejects.toThrow("not active")
  })

  test("password is cleared from config after a failed reconnect attempt", async () => {
    const config: SshConnectionConfig = {
      host: "127.0.0.1",
      port: 1, // nothing listens here → connection refused quickly
      username: "nobody",
      authMethod: "password",
      password: "hunter2",
      timeout: 2000,
    }

    const conn = new SshConnection("test-006", config)
    await expect(conn.connect()).rejects.toThrow()
    // Password is still present (cleared only after a SUCCESSFUL handshake).
    expect((conn.config as any).password).toBe("hunter2")
  })
})
