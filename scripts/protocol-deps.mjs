/**
 * One derivation of "what is the protocol line, and where is it", shared by every gate that asks.
 *
 * WHY THIS FILE EXISTS. Three gates need the same three answers — which package names are this
 * workspace's own, which `@integraledger/lcp-*` dependencies the tree declares, and what version of each
 * is actually installed. Before this module the derivation was written twice and ONE COPY WAS WRONG:
 * `check-wire-identities.mjs` knew that a `workspace:*` sibling is not the protocol line and carried a
 * docblock explaining that the `lcp-` prefix cannot tell `lcp-mcp-server` from `lcp-kernel`;
 * `check-vocab.mjs` did not, and read 118 of its 150 "protocol vocabulary" files out of this repository's
 * own source. The knowledge existed in one file and not the other. That is the shape this module exists to
 * make impossible, and the reason it is a module rather than a copied helper.
 *
 * NOTHING HERE READS A VERSION OUT OF A MANIFEST AND CALLS IT THE INSTALLED VERSION. The manifests state
 * an intent; `node_modules` states a fact; a gate that conflates them agrees with itself. Every function
 * below is explicit about which of the two it is answering.
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";

/** Names under the scope that belong to the published protocol line, by shape. Membership still decides. */
const PROTOCOL = /^@integraledger\/lcp-/;

/**
 * pnpm materialises `node_modules/@scope/name` as a SYMLINK into the content-addressed store, and
 * `Dirent.isDirectory()` is FALSE for a symlink. Every walk here must follow the link or read nothing.
 *
 * Module-local: `check-vocab.mjs` needs the same predicate for its own walk and keeps its own copy with
 * the reasoning beside it. Exporting this one as well would offer two identical answers from two places,
 * which is the shape this module exists to remove rather than add.
 */
function isDir(path) {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}

/**
 * The installed `package.json` that OWNS `dep`, resolved from `manifestPath`, or null.
 *
 * ⭐ ONE COPY, DELIBERATELY. Resolving a dependency means resolving its entry point and then walking UP to
 * the manifest whose `name` matches — a package is under no obligation to export its own `package.json`,
 * and resolving `<dep>/package.json` directly would read "not installed" for one that does not, an absence
 * indistinguishable from a clean answer. That walk was written twice in this file, which is precisely the
 * defect the whole module exists to prevent: the same derivation in two places, free to drift apart.
 */
function ownerManifest(manifestPath, dep) {
  let entry;
  try {
    entry = createRequire(manifestPath).resolve(dep);
  } catch {
    return null;
  }
  for (let dir = dirname(entry); ; dir = dirname(dir)) {
    const candidate = join(dir, "package.json");
    if (existsSync(candidate)) {
      const pkg = JSON.parse(readFileSync(candidate, "utf8"));
      if (pkg.name === dep) return { pkg, dir };
    }
    if (dirname(dir) === dir) return null;
  }
}

/**
 * Every manifest in the workspace, root first. `name` is the directory (or `<root>`), NOT the package
 * name — callers report locations with it, and `pkg.name` is what identifies the package.
 */
export function readManifests(root) {
  const out = [["<root>", join(root, "package.json")]];
  for (const dir of readdirSync(join(root, "packages"))) {
    const path = join(root, "packages", dir, "package.json");
    if (isDir(join(root, "packages", dir)) && existsSync(path))
      out.push([dir, path]);
  }
  return out.map(([name, path]) => ({
    name,
    path,
    pkg: JSON.parse(readFileSync(path, "utf8")),
  }));
}

/**
 * The package NAMES this workspace publishes. `@integraledger/lcp-mcp-server` is published from this
 * repository and matches the protocol prefix exactly as `@integraledger/lcp-kernel` does, so the prefix
 * cannot tell them apart. Membership in this set is the only thing that can.
 */
export function workspaceNames(manifests) {
  return new Set(
    manifests
      .filter((m) => m.name !== "<root>")
      .map((m) => m.pkg.name)
      .filter(Boolean),
  );
}

/** A dependency on the published protocol line — prefix AND not one of our own packages. */
export function isProtocolDep(dep, workspace) {
  return PROTOCOL.test(dep) && !workspace.has(dep);
}

/** The three manifest fields a protocol dependency can be declared in, in the order gates report them. */
const FIELDS = ["dependencies", "devDependencies", "peerDependencies"];

/**
 * Every protocol dependency this tree DECLARES, as `{ where, manifestPath, field, dep, spec }`.
 * `spec` is the manifest string — an intent, never a fact about `node_modules`.
 */
export function declaredProtocolDeps(manifests, workspace) {
  const out = [];
  for (const { name, path, pkg } of manifests)
    for (const field of FIELDS)
      for (const [dep, spec] of Object.entries(pkg[field] ?? {}))
        if (isProtocolDep(dep, workspace))
          out.push({ where: name, manifestPath: path, field, dep, spec });
  return out;
}

/**
 * The version of `dep` ACTUALLY INSTALLED as seen from `manifestPath`, or null when it resolves to
 * nothing there. A fact about `node_modules`, never a restatement of the manifest.
 */
export function installedVersion(manifestPath, dep) {
  return ownerManifest(manifestPath, dep)?.pkg.version ?? null;
}

/**
 * Every installed protocol package, deduplicated by name: `{ dep, version, dir }`.
 *
 * Derived from what the manifests declare rather than from a directory listing, which is why it finds the
 * nine peers pnpm materialises under `packages/*​/node_modules` and not just whatever happens to sit in the
 * root scope directory. Callers that need to prove they read the whole line compare `.length` against
 * the declared set — an independently derived count, which is the only thing that distinguishes "read
 * everything" from "read one package and matched nothing".
 */
export function installedProtocolPackages(manifests, workspace) {
  const seen = new Map();
  for (const { manifestPath, dep } of declaredProtocolDeps(
    manifests,
    workspace,
  )) {
    if (seen.has(dep)) continue;
    const owner = ownerManifest(manifestPath, dep);
    if (owner)
      seen.set(dep, {
        dep,
        version: owner.pkg.version ?? null,
        dir: owner.dir,
      });
  }
  return [...seen.values()];
}

/** The distinct package names declared, so a caller can state how many it EXPECTED to read. */
export function declaredProtocolNames(manifests, workspace) {
  return new Set(declaredProtocolDeps(manifests, workspace).map((d) => d.dep));
}

/**
 * The resolved ENTRY POINT of `dep`, from the first manifest that both declares and resolves it — what a
 * caller needs in order to `import()` the real installed module rather than reason about it.
 */
export function resolveEntry(manifests, dep) {
  for (const { path, pkg } of manifests) {
    if (!FIELDS.some((f) => pkg[f]?.[dep])) continue;
    try {
      return createRequire(path).resolve(dep);
    } catch {
      /* declared here but not installed here — keep looking */
    }
  }
  return null;
}

/** An exact `1.2.3`, as opposed to a range. The only spec shape CI can claim to have exercised. */
export const isExact = (spec) => /^\d+\.\d+\.\d+$/.test(spec);

/**
 * `^1.2.3` / `~1.2.3` / `1.2.3` → is `exact` inside it? Caret and tilde only; no other syntax is used in
 * this repository, and an unrecognised one returns false rather than being waved through.
 *
 * Caret on a `0.x` version pins the MINOR, which is why `^0.12.0` admits `0.12.2` and not `0.13.0`.
 */
export function satisfies(range, exact) {
  const [rMajor, rMinor, rPatch] = range
    .replace(/^[\^~]/, "")
    .split(".")
    .map(Number);
  const [eMajor, eMinor, ePatch] = exact.split(".").map(Number);
  if ([rMajor, rMinor, rPatch, eMajor, eMinor, ePatch].some(Number.isNaN))
    return false;
  const atLeast =
    eMajor > rMajor ||
    (eMajor === rMajor &&
      (eMinor > rMinor || (eMinor === rMinor && ePatch >= rPatch)));
  if (!atLeast) return false;
  if (range.startsWith("^"))
    return rMajor === 0 ? eMajor === 0 && eMinor === rMinor : eMajor === rMajor;
  if (range.startsWith("~")) return eMajor === rMajor && eMinor === rMinor;
  return range === exact;
}
