#!/usr/bin/env node
/**
 * Hold the PUBLISHED artifact against the source at the SAME version, BY CONTENT, and refuse when a version
 * already on the registry does not carry the bytes this repository says it ships.
 *
 * ⛔⛔ THE DEFECT, MEASURED RATHER THAN IMAGINED. `packages/agentic-terms/src/x402-envelope.ts` is tracked on
 * `main`, exported from that package's `index.ts`, and **absent from the published `0.17.0` tarball** — while
 * the source `package.json` also reads `0.17.0`. The work landed 2026-09-11T02:01Z; `0.17.0` published
 * 2026-09-10T21:26Z, four hours and thirty-five minutes EARLIER. Source and registry agree on the version
 * string and disagree on the bytes, so `check:dist` was green (dist/ was built from correct source),
 * `check:runtime` would be green (it packs THIS TREE, and a local pack cannot see a stale publish),
 * `reconcile-tags` was green (it asks whether published versions are TAGGED, not whether they are CURRENT)
 * — and a consumer running `npm install` got a package without the feature this repository says it has.
 *
 * ⭐ SAME VERSION MUST MEAN SAME CONTENT. A version number is a promise about bytes.
 *
 * ⛔⛔ AND CONTENT IS WHY THIS COMPARES HASHES RATHER THAN FILENAMES. A first draft compared the tarball's
 * FILE LIST against the tree's and called that parity. Measured against the real artifact, that draft saw
 * ONE of the four ways `0.17.0` is behind its source: `x402-envelope.ts` is absent, and `index.ts`,
 * `proposal.ts` and `proposal-universal.ts` are all PRESENT WITH DIFFERENT BYTES. ⇒ A filename check reports
 * three-quarters of a stale publish as clean, and the shape it misses — editing an existing file without a
 * bump — is the commoner one. A gate whose green says "matches the source it was cut from" must compare what
 * it claims to compare.
 *
 * ## WHY THIS IS NOT A SECOND COPY OF `check:currency`
 *
 * `check:currency` asks whether the protocol line we DECLARE is one npmjs still serves — a question about a
 * DEPENDENCY. This asks whether our OWN artifact matches our own source. Neither can answer the other's
 * question, and both must read the registry because no file in this tree knows what was published.
 *
 * ## ⛔ THE STATED LIMITS, ANNOUNCED RATHER THAN HIDDEN
 *
 * Only files under a declared SOURCE directory are compared. `dist/` is build output: comparing it would
 * require reproducing the exact toolchain of whatever machine published, and a mismatch there would be a
 * finding about build determinism rather than about drift. ⚠️ So a package shipping `dist` alone is reported
 * NOT COMPARABLE rather than silently passing — an unmeasured package must never read as clean.
 *
 * ⛔⛔ AND A SHRINKING SUBJECT SET IS THE FAILURE THIS GATE IS MOST LIKELY TO DIE OF, so it carries a FLOOR.
 * Without one, dropping `src` from a package's `files` — an ordinary "stop shipping source" cleanup — turns
 * the very package this gate exists for into a NOT COMPARABLE note, and a run comparing everything ELSE
 * exits 0 and prints that the published versions match. The subject leaves the set and the gate asserts
 * parity over its absence. `scripts/test-scripts.mjs` carries the same guard for the same reason.
 *
 * ⛔ AN UNREACHABLE REGISTRY IS A FAULT, never "in parity" — and A FAULT IS NOT DRIFT. Exit 3 says the
 * instrument failed; exit 1 says the artifact is behind. Filing the second over the first would assert a
 * defect nobody measured, which is the flattering error's mirror image and just as wrong.
 *
 * USAGE
 *   node scripts/check-published-parity.mjs
 *
 * ⚠️ `INTEGRA_PARITY_ROOT` and `INTEGRA_PARITY_ORIGIN` exist so the drive can run THIS FILE as a process
 * against a fixture tree and a local registry, and assert the exit CODES rather than the return values. An
 * earlier drive proved `verdict()` RETURNS 0/1/2 long before anything proved `main()` EXITS them, and the
 * exit code is the only thing the workflow reads — this estate's piped-exit defect, one layer up.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  lstatSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { argv, env, exit } from "node:process";

// ⛔ IMPORTED, NOT RE-DECLARED. `check-protocol-currency.mjs` already exports this exact literal, and
// `protocol-deps.mjs` exists in this repository precisely to stop one constant having two homes.
import { REGISTRY_ORIGIN } from "./check-protocol-currency.mjs";
import { readManifests } from "./protocol-deps.mjs";

/** Directories in `files[]` that hold TRACKED SOURCE, and are therefore comparable byte-for-byte. */
const SOURCE_DIRS = new Set(["src"]);

/**
 * ⛔ THE FLOOR: how many packages a healthy run COMPARES. Raise it as packages start publishing; ⛔ never
 * lower it to make a package that dropped out of the subject set pass. `M` 2026-09-14: `agentic-terms` and
 * `lcp-mcp-server` both publish and both ship `src`; `seller-mcp` has never published.
 */
export const COMPARABLE_FLOOR = 2;

/* ------------------------------------------------------------------ the subject set */

/**
 * Every package this repository declares publishable. ⛔ The predicate is the one a PUBLISH uses — `private`
 * absent or false AND `publishConfig.access` public — never a hand-kept list, which would be a second place
 * for the judgement to live and the place it would go stale.
 */
export function publishableManifests(manifests) {
  return manifests.filter(
    ({ pkg }) =>
      pkg.private !== true &&
      pkg.publishConfig?.access === "public" &&
      typeof pkg.name === "string" &&
      typeof pkg.version === "string",
  );
}

/**
 * npm accepts `src`, `src/` and `./src` for one directory. ⛔ A first draft normalised only for the
 * membership test and then interpolated the RAW spelling, so `"files": ["src/"]` produced `src//a.ts` and
 * reported every file in the package as missing, while `"./src"` fell out of `SOURCE_DIRS` entirely and took
 * the package out of the subject set — a false red and a false green from two legal spellings of one thing.
 */
const normaliseDir = (f) => f.replace(/^\.\//, "").replace(/\/+$/, "");

const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");

/** Walk, yielding one entry per file and one per unreadable path rather than abandoning the directory. */
function* walk(dir) {
  let names;
  try {
    names = readdirSync(dir);
  } catch (error) {
    yield { path: dir, error: error.code ?? String(error) };
    return;
  }
  for (const name of names) {
    const p = join(dir, name);
    let st;
    try {
      // `lstatSync`: a broken symlink becomes a fault to NAME, not an exception that loses its siblings.
      st = lstatSync(p);
    } catch (error) {
      yield { path: p, error: error.code ?? String(error) };
      continue;
    }
    if (st.isSymbolicLink()) {
      yield {
        path: p,
        error: "a symbolic link — not comparable byte-for-byte",
      };
      continue;
    }
    if (st.isDirectory()) yield* walk(p);
    else yield { path: p };
  }
}

/** The source a manifest declares it ships: `{ comparable, files: Map<relPath, sha256>, faults }`. */
export function declaredSourceFiles(packageDir, files) {
  const dirs = (files ?? [])
    .map(normaliseDir)
    .filter((f) => SOURCE_DIRS.has(f));
  const out = new Map();
  const faults = [];
  for (const d of dirs) {
    const abs = join(packageDir, d);
    for (const { path, error } of walk(abs)) {
      if (error) {
        // ⛔ NAMED, NEVER SWALLOWED. A first draft caught at the DIRECTORY level and continued, so one
        // broken symlink emptied the whole directory and the run then refused with "declares a source
        // directory and it holds no files" — a true refusal carrying a false diagnosis.
        faults.push(`${d}/${relative(abs, path)}: ${error}`);
        continue;
      }
      out.set(`${d}/${relative(abs, path)}`, sha256(readFileSync(path)));
    }
  }
  return { comparable: dirs.length > 0, files: out, faults };
}

/* ------------------------------------------------------------------ the registry seam */

/**
 * The real registry. ⭐ Exposed as a SEAM so the drive can exercise every verdict offline — and the drive
 * ALSO runs this implementation against a local HTTP server, because a seam whose real half is never
 * executed is a seam whose real half is unmeasured: replacing all of `NetworkRegistry` with stubs once broke
 * no test at all.
 */
export function NetworkRegistry({
  origin = env["INTEGRA_PARITY_ORIGIN"] ?? REGISTRY_ORIGIN,
  fetchImpl = fetch,
} = {}) {
  return {
    async metadata(name) {
      const res = await fetchImpl(`${origin}/${encodeURIComponent(name)}`, {
        headers: { accept: "application/json" },
      });
      if (res.status === 404) return { versions: {} };
      if (!res.ok)
        throw new Error(`registry answered ${res.status} for ${name}`);
      return await res.json();
    },
    /** `Map<pathWithoutPackagePrefix, sha256>` for every file in the published tarball. */
    async contents(name, version, tarballUrl) {
      if (typeof tarballUrl !== "string" || tarballUrl.length === 0)
        throw new Error(
          `${name}@${version} carries no dist.tarball in its registry metadata`,
        );
      const res = await fetchImpl(tarballUrl);
      if (!res.ok)
        throw new Error(
          `tarball for ${name}@${version} answered ${res.status}`,
        );
      const dir = mkdtempSync(join(tmpdir(), "parity-"));
      try {
        const file = join(dir, "p.tgz");
        writeFileSync(file, Buffer.from(await res.arrayBuffer()));
        execFileSync("tar", ["xzf", file, "-C", dir], { stdio: "pipe" });
        const base = join(dir, "package");
        const out = new Map();
        for (const { path, error } of walk(base)) {
          if (error) continue; // a link inside someone else's tarball is not our finding
          out.set(relative(base, path), sha256(readFileSync(path)));
        }
        return out;
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    },
  };
}

/* ------------------------------------------------------------------ the report */

/**
 * Compare each publishable package's source against the artifact published at the SAME version.
 *
 * `drift`  — the artifact is behind its own source. A product finding.
 * `faults` — the instrument could not measure. ⛔ NOT a product finding, and never reported as one.
 * `checked`— packages actually COMPARED, so a caller can refuse a run that measured less than the floor.
 */
export async function parityReport({ manifests, registry }) {
  const drift = [];
  const faults = [];
  const notes = [];
  let checked = 0;

  const subjects = publishableManifests(manifests);
  if (subjects.length === 0)
    return {
      drift,
      faults: [
        "no package in this repository declares itself publishable (`private` absent and " +
          "`publishConfig.access: public`). That is a subject set of zero, not a clean run — either the " +
          "predicate is wrong or this gate is pointed at the wrong tree.",
      ],
      notes,
      checked: 0,
    };

  for (const { name: dirName, path, pkg } of subjects) {
    const packageDir = join(path, "..");
    const label = `${pkg.name}@${pkg.version}`;

    let meta;
    try {
      meta = await registry.metadata(pkg.name);
    } catch (error) {
      faults.push(
        `${pkg.name} — the registry could not be read (${error.message}). ` +
          "⛔ An unreachable registry is NOT parity: nothing was compared.",
      );
      continue;
    }

    const versions = meta?.versions ?? {};
    if (Object.keys(versions).length === 0) {
      notes.push(
        `${pkg.name} — never published (\`${dirName}\` declares itself publishable). Nothing to compare; ` +
          "a first publish is not drift. ⚠️ A registry 404 reads the same way here, so a package that was " +
          "unpublished or renamed arrives as this note — which is what the floor exists to catch.",
      );
      continue;
    }

    const published = versions[pkg.version];
    if (published === undefined) {
      notes.push(
        `${label} — this version is not on the registry yet, so there is nothing to be out of parity with. ` +
          `Published: ${Object.keys(versions).sort().join(", ")}.`,
      );
      continue;
    }

    const {
      comparable,
      files: sourceFiles,
      faults: walkFaults,
    } = declaredSourceFiles(packageDir, pkg.files);

    if (walkFaults.length > 0) {
      faults.push(
        `${label} — ${walkFaults.length} source path(s) could not be read, so any comparison would be over ` +
          `a partial set:\n${walkFaults.map((f) => `        - ${f}`).join("\n")}`,
      );
      continue;
    }
    if (!comparable) {
      notes.push(
        `${label} — NOT COMPARABLE: it declares no source directory in \`files\` ` +
          `(${JSON.stringify(pkg.files ?? [])}). Build output is deliberately not compared. ` +
          "⚠️ Read this as unmeasured, never as clean.",
      );
      continue;
    }
    if (sourceFiles.size === 0) {
      faults.push(
        `${label} declares a source directory in \`files\` and that directory holds no files in this tree. ` +
          "A comparison against an empty source set would pass over nothing.",
      );
      continue;
    }

    let contents;
    try {
      contents = await registry.contents(
        pkg.name,
        pkg.version,
        published.dist?.tarball,
      );
    } catch (error) {
      faults.push(
        `${label} — the published tarball could not be read (${error.message}). Not compared.`,
      );
      continue;
    }

    if (contents.size === 0) {
      faults.push(
        `${label} — the published tarball yielded no files. The artifact is empty or its layout changed; ` +
          "either way nothing was compared.",
      );
      continue;
    }

    const missing = [];
    const differing = [];
    for (const [rel, hash] of sourceFiles) {
      const theirs = contents.get(rel);
      if (theirs === undefined) missing.push(rel);
      else if (theirs !== hash) differing.push(rel);
    }
    checked += 1;

    if (missing.length > 0 || differing.length > 0) {
      const lines = [
        ...missing.map((f) => `        - ABSENT    ${f}`),
        ...differing.map((f) => `        - DIFFERENT ${f}`),
      ];
      drift.push(
        `⛔ ${label} IS PUBLISHED AND IS BEHIND ITS OWN SOURCE — ${missing.length} file(s) absent, ` +
          `${differing.length} present with different bytes:\n${lines.join("\n")}\n\n` +
          `      The source tree and the registry both say \`${pkg.version}\`, so a version bump and a ` +
          "publish are what close this — republishing the same version is not possible and is not the " +
          `remedy. Control: ${contents.size} file(s) were read from that tarball and ${sourceFiles.size} ` +
          "from this tree, so both sides of the comparison were populated.",
      );
    }
  }

  return { drift, faults, notes, checked };
}

/**
 * ⛔⛔ FOUR ANSWERS, AND THREE OF THEM ARE NOT "PASS". Collapsing any pair would state something nobody
 * measured. This estate learned the distinction on the measured-run lock, where `--conflict-exit-code 75`
 * keeps "never got the box" separate from "below floor".
 *
 *   0  compared at least `floor` packages, and every one matched its source byte-for-byte
 *   1  DRIFT — a published artifact is behind its own source. A product finding.
 *   2  UNMEASURED — fewer than `floor` packages were comparable. No opinion is available.
 *   3  FAULT — the instrument failed. ⛔ Never reported as drift.
 */
export function verdict({ drift, faults, checked, floor = COMPARABLE_FLOOR }) {
  if (drift.length > 0) return { code: 1, kind: "drift" };
  if (faults.length > 0) return { code: 3, kind: "fault" };
  if (checked < floor)
    return {
      code: 2,
      kind: "unmeasured",
      message:
        `only ${checked} package(s) were compared, below the floor of ${floor}. Every other publishable ` +
        "package was ahead of the registry, never published, or not comparable on this axis. ⛔ A package " +
        "that LEAVES the comparable set takes its own coverage with it, and a run over what remains must " +
        "not print a tick. This is not a pass, it is not drift, and the instrument did not fail.",
    };
  return { code: 0, kind: "parity" };
}

/* ------------------------------------------------------------------ entry point */

async function main() {
  const root =
    env["INTEGRA_PARITY_ROOT"] ?? new URL("..", import.meta.url).pathname;
  const manifests = readManifests(root);
  const { drift, faults, notes, checked } = await parityReport({
    manifests,
    registry: NetworkRegistry(),
  });

  for (const n of notes) console.log(`  · ${n}\n`);

  const v = verdict({ drift, faults, checked });

  if (v.kind === "drift") {
    console.error("\n✕ check:published-parity — DRIFT\n");
    for (const d of drift) console.error(`  • ${d}\n`);
    exit(1);
  }
  if (v.kind === "fault") {
    console.error("\n✕ check:published-parity — THE INSTRUMENT FAILED\n");
    for (const f of faults) console.error(`  • ${f}\n`);
    exit(3);
  }
  if (v.kind === "unmeasured") {
    console.error(`\n⚠ check:published-parity — ${v.message}\n`);
    exit(2);
  }

  console.log(
    `✓ every published version matches the source it was cut from, byte for byte ` +
      `(${checked} package(s) compared, floor ${COMPARABLE_FLOOR}).`,
  );
}

// Importable for its drive; the registry read happens only when this file IS the entry point.
// ⛔ BOTH SIDES REALPATHED, for the reason `reconcile-tags.mjs` records: `import.meta.filename` is already
// resolved through symlinks and `argv[1]` is not, so the naive comparison makes the whole script a silent
// no-op for anyone whose checkout is reached through a symlinked directory.
if (
  argv[1] !== undefined &&
  realpathSync(resolve(argv[1])) === import.meta.filename
)
  await main();
