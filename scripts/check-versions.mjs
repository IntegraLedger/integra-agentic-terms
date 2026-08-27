#!/usr/bin/env node
/**
 * Refuse a publishable package sitting at `0.0.0`. Runs FIRST in `pnpm verify`, before the build, because
 * it costs milliseconds and the thing it prevents is not recoverable.
 *
 * THIS IS NOT HYGIENE. `changeset publish` ships any package whose `package.json` version is absent from
 * the registry. A package scaffolded at the changesets "never released" sentinel therefore publishes
 * `0.0.0` as a REAL, installable version the first time a release runs — before `changeset version` has
 * ever run, and without anyone deciding to release it.
 *
 * This is not hypothetical: a release wave elsewhere published a stray `0.0.0` beside the real version for
 * every package that had been scaffolded at the sentinel, and for none that had not.
 *
 * Cleaning up afterwards is worse than it sounds: deleting a package's SOLE registry version deletes the
 * package and BURNS THE NAME, so a stray cannot be removed until a real version sits beside it, and the git
 * tag it created has to be swept separately because deleting a registry version does not touch its tag.
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import {
  declaredProtocolDeps,
  installedVersion,
  isExact,
  readManifests,
  satisfies,
  workspaceNames,
} from "./protocol-deps.mjs";

const root = new URL("..", import.meta.url).pathname;
const SENTINEL = "0.0.0";

const offenders = [];
for (const dir of readdirSync(`${root}/packages`)) {
  const manifest = `${root}/packages/${dir}/package.json`;
  // A stray file in packages/ must not crash the gate that every verify now depends on.
  if (!statSync(`${root}/packages/${dir}`).isDirectory()) continue;
  if (!existsSync(manifest)) continue;
  const pkg = JSON.parse(readFileSync(manifest, "utf8"));
  // Private packages never reach a registry, so the sentinel is harmless there and stays allowed.
  if (pkg.private === true) continue;
  if (typeof pkg.version !== "string" || pkg.version.length === 0)
    offenders.push([dir, "declares no version at all"]);
  else if (pkg.version === SENTINEL)
    offenders.push([dir, `is publishable and sits at ${SENTINEL}`]);
}

if (offenders.length > 0) {
  const lines = offenders.map(([dir, why]) => `  - packages/${dir} ${why}`);
  console.error(
    `\nRefusing to verify: ${offenders.length} publishable package(s) would publish a version nobody chose.\n\n${lines.join("\n")}\n\n` +
      `\`changeset publish\` ships any version absent from the registry, so ${SENTINEL} would go out as a\n` +
      `real, installable version before \`changeset version\` has ever run. Scaffold a new package at 0.1.0\n` +
      `and let changesets take it from there.\n\n` +
      `This is not reversible in place: deleting a package's only registry version burns the name.\n`,
  );
  process.exit(1);
}

/* ---------- the installed tree is the one the manifests pin ---------- */

/**
 * THE MANIFESTS STATE AN INTENT; `node_modules` STATES A FACT, AND NOTHING WAS COMPARING THEM.
 *
 * A checkout can sit for weeks with a protocol line installed that no manifest names — and every gate
 * downstream still reports on the version it READ OUT OF `package.json`. That is not hypothetical: this
 * check was written because the working tree held 0.10.1 under a 0.12.0 lockfile while `check:wire`
 * printed `✓ one exercised protocol line (0.12.0)`. Three minor lines of drift, every gate green, and the
 * one sentence a person would have trusted was the one that was wrong.
 *
 * It lives HERE, first in `verify`, because it is a precondition of every later stage rather than a fact
 * about any of them: once this passes, `check:wire`, `check:vocab`, the build and the suite may all assume
 * the tree is the tree the manifests describe. It costs milliseconds and the failure it prevents is a
 * green that means nothing.
 */
const manifests = readManifests(root);
const workspace = workspaceNames(manifests);
const drifted = [];

for (const { where, manifestPath, field, dep, spec } of declaredProtocolDeps(
  manifests,
  workspace,
)) {
  const actual = installedVersion(manifestPath, dep);
  if (actual === null) {
    drifted.push(
      `  - ${where} → ${dep} (${field} "${spec}") is declared but resolves to nothing installed`,
    );
    continue;
  }
  // An exact pin must be met exactly — it is the only version CI can claim to have exercised. A range is
  // met by anything inside it, which is the whole point of declaring one.
  const ok = isExact(spec) ? actual === spec : satisfies(spec, actual);
  if (!ok)
    drifted.push(
      `  - ${where} → ${dep} (${field} "${spec}") has ${actual} installed`,
    );
}

if (drifted.length > 0) {
  console.error(
    `\nRefusing to verify: the tree does not match the pins.\n\n${drifted.join("\n")}\n\n` +
      `Run \`pnpm install\`. Until the installed packages are the ones the manifests name, every later\n` +
      `stage reports on a version it read from \`package.json\` rather than the one it actually loaded.\n`,
  );
  process.exit(1);
}

console.log(
  `check:versions — no publishable package is at the changesets sentinel; the installed tree matches all ${
    declaredProtocolDeps(manifests, workspace).length
  } protocol pins.`,
);
