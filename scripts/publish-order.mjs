#!/usr/bin/env node
/**
 * Emit the publishable packages in DEPENDENCY ORDER — a package after everything it depends on.
 *
 * WHY THIS EXISTS. `lcp-mcp-server` depends on `agentic-terms` at an exact version, so publishing it first
 * leaves a window in which it is on the registry and uninstallable: npm accepts a publish whose dependency
 * does not exist yet, and the first stranger to `npm install` is the one who finds out. A version is
 * permanent, so that window is not something to open by accident.
 *
 * Alphabetical order happens to be correct for these two names, which is exactly why it is not relied on: a
 * glob over the packages directory is one rename away from silently inverting, and nothing would fail until
 * a release had already gone out. So the order is DERIVED from the dependency graph the manifests already
 * declare, rather than asserted in a list someone has to remember to update. A third package, or a renamed
 * one, is ordered correctly on the day it is added, by someone who never reads this file.
 *
 * THE RULE IS `private`, NOT A NAME. A private package has nothing to publish and is excluded here, the
 * same way the pack and publish loops exclude it. Deriving from `private` means the next private package is
 * handled the day it is created; a name pattern can only be corrected after it has already broken a
 * release.
 *
 * PEER DEPENDENCIES COUNT AS EDGES. A peer is not installed by us, but a consumer resolving it still needs
 * it to exist, so a package whose peer is a sibling must not go first. Ordering by `dependencies` alone
 * would be right today and wrong the moment a sibling peer appears.
 *
 * A CYCLE IS FATAL, not a warning. Two packages that depend on each other cannot both be published
 * consistently, and the honest response is to refuse rather than to pick a side and leave one of them
 * briefly broken on the registry.
 *
 *   node scripts/publish-order.mjs                    packages/<name>/ per line, dependency order
 *   node scripts/publish-order.mjs --tarballs <dir>   the matching .tgz paths, same order
 *   node scripts/publish-order.mjs --json             the package names as a JSON array
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = process.cwd();
const PACKAGES = join(ROOT, "packages");

/** dir -> manifest, for every package that actually publishes. */
const publishable = new Map();
for (const entry of readdirSync(PACKAGES, { withFileTypes: true })) {
  if (!entry.isDirectory()) continue;
  const manifest = join(PACKAGES, entry.name, "package.json");
  if (!existsSync(manifest)) continue;
  const pkg = JSON.parse(readFileSync(manifest, "utf8"));
  if (pkg.private) continue;
  publishable.set(entry.name, pkg);
}
if (publishable.size === 0)
  throw new Error(
    "publish-order found no publishable package. An empty order would make every publish loop a silent no-op.",
  );

const byName = new Map([...publishable].map(([dir, pkg]) => [pkg.name, dir]));

/** dir -> Set<dir> it must follow. */
const needs = new Map([...publishable.keys()].map((d) => [d, new Set()]));
for (const [dir, pkg] of publishable) {
  for (const field of [
    "dependencies",
    "peerDependencies",
    "optionalDependencies",
  ]) {
    for (const dep of Object.keys(pkg[field] ?? {})) {
      const depDir = byName.get(dep);
      // A sibling that is private, or not a sibling at all, is not an edge: nothing here publishes it.
      if (depDir !== undefined && depDir !== dir) needs.get(dir)?.add(depDir);
    }
  }
}

// Kahn, with an alphabetical tiebreak so the output is deterministic run to run. Two packages with no
// relationship have no correct relative order, and an order that shuffles between runs makes a diff of two
// release logs unreadable.
const order = [];
const remaining = new Map([...needs].map(([d, s]) => [d, new Set(s)]));
while (remaining.size > 0) {
  const ready = [...remaining]
    .filter(([, deps]) => deps.size === 0)
    .map(([d]) => d)
    .sort();
  if (ready.length === 0) {
    const cycle = [...remaining.keys()].sort().join(", ");
    console.error(
      `publish-order — CYCLE among publishable packages: ${cycle}\n` +
        "Two packages that depend on each other cannot both be published consistently. Break the cycle; " +
        "do not pick a side here.",
    );
    process.exit(1);
  }
  for (const dir of ready) {
    order.push(dir);
    remaining.delete(dir);
  }
  for (const deps of remaining.values())
    for (const dir of ready) deps.delete(dir);
}

if (order.length !== publishable.size)
  throw new Error(
    `publish-order emitted ${order.length} of ${publishable.size} packages — a partial order would publish an incomplete set`,
  );

const args = process.argv.slice(2);
if (args[0] === "--json") {
  console.log(JSON.stringify(order.map((d) => publishable.get(d).name)));
} else if (args[0] === "--tarballs") {
  const dir = args[1];
  if (!dir) throw new Error("--tarballs needs a directory");
  for (const d of order) {
    const pkg = publishable.get(d);
    // `pnpm pack` names the file after the manifest: @scope/name -> scope-name-version.tgz.
    const file = `${pkg.name.replace(/^@/, "").replace("/", "-")}-${pkg.version}.tgz`;
    const path = join(dir, file);
    if (!existsSync(path))
      throw new Error(
        `no packed tarball for ${pkg.name}@${pkg.version} at ${path}`,
      );
    console.log(path);
  }
} else {
  for (const d of order) console.log(`packages/${d}/`);
}
