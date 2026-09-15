"use strict"
/**
 * Propagates the canonical version (package.json -> version) to every other
 * place that currently keeps the value static:
 *
 *   - src/version.ts   (PLUGIN_VERSION, between GENERATED markers)
 *   - marketplace.json (version)
 *
 * Run via `bun run version:sync`. `bun run build` calls this script before
 * tsc, so the dist and marketplace never carry a stale version.
 */

const fs = require("fs")
const path = require("path")

const ROOT = path.resolve(__dirname, "..")

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
}

function fail(message) {
  console.error(`❌ sync-version: ${message}`)
  process.exit(1)
}

if (!fs.existsSync(path.join(ROOT, "package.json"))) {
  fail("package.json not found")
}

const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"))
const version = pkg.version
if (typeof version !== "string" || version.trim().length === 0) {
  fail('package.json has no valid "version" field')
}

// ── src/version.ts ──────────────────────────────────────────────────
const MARKER_START = "// BEGIN GENERATED: PLUGIN_VERSION (scripts/sync-version.cjs)"
const MARKER_END = "// END GENERATED: PLUGIN_VERSION"
const versionModulePath = path.join(ROOT, "src", "version.ts")

if (!fs.existsSync(versionModulePath)) {
  fail("src/version.ts not found")
}

const versionModule = fs.readFileSync(versionModulePath, "utf8")
const blockPattern = new RegExp(
  `${escapeRegExp(MARKER_START)}[\\s\\S]*?${escapeRegExp(MARKER_END)}`,
)
if (!blockPattern.test(versionModule)) {
  fail(`src/version.ts is missing the GENERATED markers (${MARKER_START} ... ${MARKER_END})`)
}

const nextModule = versionModule.replace(
  blockPattern,
  `${MARKER_START}\nexport const PLUGIN_VERSION = ${JSON.stringify(version)}\n${MARKER_END}`,
)
if (nextModule !== versionModule) {
  fs.writeFileSync(versionModulePath, nextModule)
}

// ── marketplace.json ────────────────────────────────────────────────
const marketplacePath = path.join(ROOT, "marketplace.json")
if (fs.existsSync(marketplacePath)) {
  const marketplace = JSON.parse(fs.readFileSync(marketplacePath, "utf8"))
  if (marketplace.version !== version) {
    marketplace.version = version
    fs.writeFileSync(marketplacePath, `${JSON.stringify(marketplace, null, 2)}\n`)
  }
}

console.log(`✅ version synced: ${version}`)