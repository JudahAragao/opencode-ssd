import { describe, expect, test } from "bun:test"
import { writeFileSync, mkdtempSync } from "fs"
import { join } from "path"
import { tmpdir } from "os"
import {
  parseSshConfig,
  findHostConfig,
  resolveSshConfigPath,
  expandHomePath,
  getAutoConnectHosts,
} from "../src/ssh/config.js"

const SAMPLE_CONFIG = `
# Production servers
Host prod-web
    HostName 10.0.0.10
    User deploy
    Port 2222
    IdentityFile ~/.ssh/prod_key

Host prod-*
    User deploy
    ForwardAgent yes

Host *.company.com
    User alice
    Port 2020

Host "quoted alias"
    HostName 10.0.0.99

Match host example
    User matchuser

Host github.com
    User git
    IdentityFile ~/.ssh/id_ed25519
    ProxyJump jumpuser@jump-host:2200

Host prod-db
    HostName 10.0.0.50
    ProxyCommand ssh -W %h:%p bastion
`

describe("SSH Config parser", () => {
  test("parses host blocks with HostName, User, Port, IdentityFile", () => {
    const entries = parseSshConfig(SAMPLE_CONFIG)
    const prodWeb = findHostConfig(entries, "prod-web")
    expect(prodWeb?.patterns).toEqual(["prod-web"])
    expect(prodWeb?.hostName).toBe("10.0.0.10")
    expect(prodWeb?.user).toBe("deploy")
    expect(prodWeb?.port).toBe(2222)
    expect(prodWeb?.identityFile).toBe("~/.ssh/prod_key")
  })

  test("matches wildcard host patterns", () => {
    const entries = parseSshConfig(SAMPLE_CONFIG)
    const match = findHostConfig(entries, "prod-api")
    expect(match?.user).toBe("deploy")
    expect(match?.hostName).toBeUndefined()

    const company = findHostConfig(entries, "server.company.com")
    expect(company?.user).toBe("alice")
    expect(company?.port).toBe(2020)
  })

  test("prefers exact matches over glob patterns", () => {
    const entries = parseSshConfig(SAMPLE_CONFIG)
    // "prod-web" matches both prod-web (exact) and prod-* (glob)
    const match = findHostConfig(entries, "prod-web")
    expect(match?.hostName).toBe("10.0.0.10")
  })

  test("matches quoted host aliases", () => {
    const entries = parseSshConfig(SAMPLE_CONFIG)
    const match = findHostConfig(entries, "quoted alias")
    expect(match?.hostName).toBe("10.0.0.99")
  })

  test("returns undefined when no host matches", () => {
    const entries = parseSshConfig(SAMPLE_CONFIG)
    expect(findHostConfig(entries, "unknown-host")).toBeUndefined()
  })

  test("parses ProxyJump directive", () => {
    const entries = parseSshConfig(SAMPLE_CONFIG)
    const github = findHostConfig(entries, "github.com")
    expect(github?.proxyJump).toBe("jumpuser@jump-host:2200")
  })

  test("parses ProxyCommand directive", () => {
    const entries = parseSshConfig(SAMPLE_CONFIG)
    const db = findHostConfig(entries, "prod-db")
    expect(db?.proxyCommand).toBe("ssh -W %h:%p bastion")
  })

  test("resolves default ssh config path", () => {
    const home = process.env.HOME || "/home/test"
    expect(resolveSshConfigPath()).toBe(`${home}/.ssh/config`)
    expect(resolveSshConfigPath("~/.ssh/custom")).toBe(`${home}/.ssh/custom`)
  })

  test("expands home paths", () => {
    const home = process.env.HOME || "/home/test"
    expect(expandHomePath("~/keys/id_rsa")).toBe(`${home}/keys/id_rsa`)
    expect(expandHomePath("/abs/path")).toBe("/abs/path")
  })

  test("getAutoConnectHosts returns hosts that resolve to a HostName", () => {
    const hosts = getAutoConnectHosts()
    // Only asserts it is always an array (no crash when ~/.ssh/config missing)
    expect(Array.isArray(hosts)).toBe(true)
  })

  test("getAutoConnectHosts reads from a custom config path", () => {
    const dir = mkdtempSync(join(tmpdir(), "sshcfg-"))
    const file = join(dir, "config")

    writeFileSync(
      file,
      [
        "Host web1",
        "    HostName 10.0.0.1",
        "    User deploy",
        "    Port 22",
        "",
        "Host web2",
        "    HostName 10.0.0.2",
        "    IdentityFile ~/.ssh/web2_key",
        "",
        "Host noserver",
        "    User foo",
      ].join("\n"),
    )

    const hosts = getAutoConnectHosts(file)
    expect(hosts).toEqual([
      { alias: "web1", hostName: "10.0.0.1", user: "deploy", port: 22 },
      { alias: "web2", hostName: "10.0.0.2", identityFile: "~/.ssh/web2_key" },
    ])
  })
})