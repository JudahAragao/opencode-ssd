/**
 * Single source of truth for version identifiers.
 *
 * `PLUGIN_VERSION` mirrors the `version` field of package.json and is kept in
 * sync by `scripts/sync-version.cjs` (run automatically by `bun run build`,
 * and available as `bun run version:sync`). Do not edit the value by hand —
 * edit package.json and run the script.
 */

// BEGIN GENERATED: PLUGIN_VERSION (scripts/sync-version.cjs)
export const PLUGIN_VERSION = "1.4.1"
// END GENERATED: PLUGIN_VERSION