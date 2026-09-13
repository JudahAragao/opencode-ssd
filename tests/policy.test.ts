import { describe, test, expect, beforeEach, afterEach } from "bun:test"
import { mkdtempSync, rmSync } from "fs"
import { join } from "path"
import { tmpdir } from "os"
import { getEffectiveCustomAllowlist, savePolicy, addAllowlistPattern } from "../src/security/policy.js"

describe("getEffectiveCustomAllowlist", () => {
  let dir: string

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "ssh-policy-"))
  })

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true })
  })

  test("returns only config allowlist when no policy exists", () => {
    expect(getEffectiveCustomAllowlist(dir, ["docker stop .*"])).toEqual(["docker stop .*"])
  })

  test("merges policy customAllowlist with config allowlist (deduped)", () => {
    savePolicy(dir, {
      mode: "restricted",
      extraBlocklist: [],
      customAllowlist: ["docker stop .*", "rm -rf /opt/apps"],
      updatedAt: new Date().toISOString(),
    })

    expect(
      getEffectiveCustomAllowlist(dir, ["docker stop .*", "docker rm .*"]),
    ).toEqual(["docker stop .*", "docker rm .*", "rm -rf /opt/apps"])
  })

  test("addAllowlistPattern persists to disk and is picked up", () => {
    addAllowlistPattern(dir, "docker network rm .*")
    expect(getEffectiveCustomAllowlist(dir, [])).toEqual(["docker network rm .*"])
    expect(getEffectiveCustomAllowlist(dir, ["docker rm .*"])).toEqual([
      "docker rm .*",
      "docker network rm .*",
    ])
  })

  test("returns empty when nothing is configured", () => {
    expect(getEffectiveCustomAllowlist(dir, [])).toEqual([])
  })
})