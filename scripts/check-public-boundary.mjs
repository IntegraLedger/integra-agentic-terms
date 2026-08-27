#!/usr/bin/env node
/**
 * EVERYTHING IN THIS REPOSITORY IS PUBLIC, and this gate is what makes that a checked invariant rather
 * than a description. It refuses:
 *
 *   - a publishable package that is not `access: public` — this repo has no restricted layer, and a
 *     package that silently stopped being public would break the "free forever, no account, no token"
 *     commitment these two packages carry;
 *   - a public package missing anything it owes a stranger who finds it on the registry — `description`,
 *     `keywords`, `license`, `repository`, `bugs`, `homepage`, `engines`;
 *   - a public package whose `files` fails to SHIP its LICENSE and NOTICE — an Apache-2.0 package
 *     carrying no licence text;
 *   - a public package depending on any `@integraledger/*` package that is neither in this workspace nor
 *     on the public `lcp-*` protocol line. The licensed seller packages are the live risk: such a
 *     dependency resolves here and breaks only for the first stranger to `npm install`, after the version
 *     is burned on the registry — and it discloses the name of a private package.
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";

const root = new URL("..", import.meta.url).pathname;

/** Everything a public package owes a stranger who finds it on the registry. */
const REQUIRED_FIELDS = [
  "description",
  "keywords",
  "license",
  "repository",
  "bugs",
  "homepage",
  "engines",
];
/** Files a public Apache-2.0 package must actually SHIP, not merely have on disk. */
const REQUIRED_SHIPPED = ["LICENSE", "NOTICE"];

const manifests = new Map();
for (const dir of readdirSync(`${root}/packages`)) {
  if (!statSync(`${root}/packages/${dir}`).isDirectory()) continue;
  const manifest = `${root}/packages/${dir}/package.json`;
  if (!existsSync(manifest)) continue;
  manifests.set(dir, JSON.parse(readFileSync(manifest, "utf8")));
}

const workspaceNames = new Set([...manifests.values()].map((p) => p.name));

/**
 * An `@integraledger/*` dependency is legitimate only if it is a workspace sibling or on the public
 * protocol line. Everything else under the scope — the licensed seller packages above all — is refused by
 * name shape, because this script cannot ask the registry and a publish must not depend on the network.
 */
const isAllowedIntegraDep = (name) =>
  workspaceNames.has(name) || name.startsWith("@integraledger/lcp-");

const offenders = [];
for (const [dir, pkg] of manifests) {
  if (pkg.private === true) continue;

  if (pkg.publishConfig?.access !== "public") {
    offenders.push([
      dir,
      "is publishable but not `access: public` — this repository has no restricted layer",
    ]);
    continue;
  }

  for (const field of REQUIRED_FIELDS) {
    if (pkg[field] === undefined)
      offenders.push([dir, `is public and declares no \`${field}\``]);
  }
  if (pkg.license !== "Apache-2.0")
    offenders.push([
      dir,
      `is public and its licence is \`${pkg.license}\`, not Apache-2.0`,
    ]);

  const files = Array.isArray(pkg.files) ? pkg.files : [];
  for (const owed of REQUIRED_SHIPPED) {
    if (!existsSync(`${root}/packages/${dir}/${owed}`))
      offenders.push([dir, `is public and has no ${owed} file`]);
    else if (!files.includes(owed))
      offenders.push([dir, `is public and \`files\` does not ship ${owed}`]);
  }

  // The one that cannot be recovered after a publish.
  for (const field of [
    "dependencies",
    "peerDependencies",
    "optionalDependencies",
  ]) {
    for (const dep of Object.keys(pkg[field] ?? {})) {
      if (dep.startsWith("@integraledger/") && !isAllowedIntegraDep(dep))
        offenders.push([
          dir,
          `takes a ${field} on \`${dep}\`, which is neither a workspace sibling nor on the public lcp-* line`,
        ]);
    }
  }
}

if (offenders.length > 0) {
  const lines = offenders.map(([dir, why]) => `  - packages/${dir} ${why}`);
  console.error(
    `\nRefusing to verify: ${offenders.length} problem(s) with the public boundary.\n\n${lines.join("\n")}\n\n` +
      `A public package that depends on a non-public one passes every other gate in this repo and then\n` +
      `fails for the first stranger who installs it, after the version is already burned on the registry.\n`,
  );
  process.exit(1);
}

const publicNames = [...manifests.values()]
  .filter((p) => p.private !== true)
  .map((p) => p.name);
console.log(
  `check:public-boundary — ${publicNames.length} public package(s) carry their metadata, ship LICENSE + NOTICE, and depend only on public packages.`,
);
