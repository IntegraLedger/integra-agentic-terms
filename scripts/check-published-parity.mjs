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
import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { argv, env, exit } from "node:process";
import { gunzipSync } from "node:zlib";

// ⛔ IMPORTED, NOT RE-DECLARED. `check-protocol-currency.mjs` already exports this exact literal, and
// `protocol-deps.mjs` exists in this repository precisely to stop one constant having two homes.
import { REGISTRY_ORIGIN } from "./check-protocol-currency.mjs";
import { readManifests } from "./protocol-deps.mjs";

/** Directories in `files[]` that hold TRACKED SOURCE, and are therefore comparable byte-for-byte. */
const SOURCE_DIRS = new Set(["src"]);

/**
 * ⛔ THE FLOOR: how many packages a healthy run COMPARES. ⛔ Never lower it to make a package that dropped
 * out of the subject set pass. `M` 2026-09-15: `agentic-terms`, `lcp-mcp-server` and `seller-mcp` all
 * publish and all ship `src`.
 *
 * ⛔⛔ AND IT IS HELD EQUAL TO THE COUNT, NOT MERELY BELOW IT — because "raise it as packages start
 * publishing" is an instruction to a human at the one moment they are thinking about something else, which
 * is a release. `M` 2026-09-15 this number was `2` while the gate compared `3`: `seller-mcp` was `E404`
 * when the floor was written and published `0.10.0` that night. Nothing said so, because a run comparing
 * MORE than the floor printed a tick. ⇒ A package leaving the set would then have dropped the count back to
 * `2`, met the stale floor, and exited 0 over its own absence — the floor's entire purpose, defeated by the
 * floor being one behind. See `verdict`'s fifth answer.
 */
export const COMPARABLE_FLOOR = 3;

/**
 * ⛔⛔ WHAT THE FLOOR IS HELD AGAINST — the TREE, and never `checked`.
 *
 * `M` 2026-09-15, argued by `sept-15-commerce` from the sibling repository and reproduced here before it
 * was believed: holding the number equal to `checked` reds the gate on a HEALTHY tree every time somebody
 * bumps a version, because `checked` legitimately drops between `changeset version` landing and the
 * publish that follows. Driven at `1a2dfbe` with `agentic-terms` bumped to an unpublished version:
 *
 *     floor 2 (before) -> "2 package(s) compared, floor 2."  exit 0
 *     floor 3 (after)  -> "below the floor of 3."            exit 2   ⛔ the release you are preparing
 *
 * ⭐ So the number answers what this repository DECLARES — publishable, and shipping source — which does
 * not move when a version moves, and is answerable with NO NETWORK. An unreachable registry is exactly
 * when a stale declaration would otherwise go another cycle unnoticed.
 */
export function declaredComparable(manifests) {
  return publishableManifests(manifests).filter(({ pkg }) =>
    (pkg.files ?? []).map(normaliseDir).some((d) => SOURCE_DIRS.has(d)),
  ).length;
}

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

/* ------------------------------------------------------------------ reading a tarball safely */

/**
 * \u26d4\u26d4 THE ARCHIVE IS NEVER EXTRACTED TO DISK, AND THAT IS A SECURITY PROPERTY RATHER THAN A STYLE CHOICE.
 *
 * A first draft wrote the downloaded tarball to a temp directory and shelled out to `tar xzf`. GitHub's
 * CodeQL flagged it on the pull request \u2014 *"network data written to file: write to file system depends on
 * untrusted data"* \u2014 and it was right. A registry tarball is externally controlled input, and extracting
 * one is a path-traversal and symlink-escape surface: an entry named `../../x`, an absolute path, or a
 * symlink followed by a later entry can place bytes outside the directory the caller chose. That modern GNU
 * tar strips most of those is a property of the tool that happened to be on the box, not of this code.
 *
 * \u2b50 So the tar is walked in memory and only REGULAR FILE entries are hashed. Nothing is written, nothing is
 * executed, and a hostile entry name can at worst appear as a key in a Map that is then compared against a
 * list of names this repository already declared. The traversal class is not mitigated; it is absent.
 *
 * The format is POSIX ustar: 512-byte header, `size` as octal at offset 124, content padded to 512.
 * Type `0` or NUL is a regular file; `x`/`g` are pax metadata and `L` is a GNU long name, whose payloads are
 * skipped along with everything else that is not a regular file.
 */
export function hashTarEntries(tar) {
  const out = new Map();
  const BLOCK = 512;
  for (let off = 0; off + BLOCK <= tar.length; ) {
    const header = tar.subarray(off, off + BLOCK);
    // Two consecutive NUL blocks end the archive; one is enough to stop reading names.
    if (header[0] === 0) break;

    const name = header.subarray(0, 100).toString("utf8").replace(/\0.*$/, "");
    const prefix = header
      .subarray(345, 500)
      .toString("utf8")
      .replace(/\0.*$/, "");
    const sizeField = header
      .subarray(124, 136)
      .toString("utf8")
      .replace(/\0.*$/, "")
      .trim();
    const size = Number.parseInt(sizeField, 8);
    if (!Number.isFinite(size) || size < 0)
      throw new Error(`tar entry '${name}' has an unreadable size field`);

    const type = String.fromCharCode(header[156]);
    const body = off + BLOCK;
    if ((type === "0" || type === "\0") && name.length > 0)
      out.set(
        prefix.length > 0 ? `${prefix}/${name}` : name,
        sha256(tar.subarray(body, body + size)),
      );

    off = body + Math.ceil(size / BLOCK) * BLOCK;
  }
  return out;
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
    /** `Map<pathWithoutPackagePrefix, sha256>` for every regular file in the published tarball. */
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
      const entries = hashTarEntries(
        gunzipSync(Buffer.from(await res.arrayBuffer())),
      );
      // \u26d4 npm wraps every tarball in a single `package/` directory, and the caller compares against
      // paths relative to the package root. Dropping the strip made every declared file read as ABSENT \u2014
      // 16 of 16 rather than the 4 real defects \u2014 which is a false RED, the cheap direction, and was
      // caught by the drive's assertion that the prefix is removed.
      const out = new Map();
      for (const [path, hash] of entries)
        if (path.startsWith("package/"))
          out.set(path.slice("package/".length), hash);
      return out;
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
  let ahead = 0;

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
      // ⛔ COUNTED, not merely noted. A source version ahead of the registry is the NORMAL state between a
      // version bump and the publish that follows, and it is the ONE reason `checked` may honestly fall
      // short of what the tree declares. Every other shortfall is a subject that LEFT.
      ahead += 1;
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

  return { drift, faults, notes, checked, ahead };
}

/**
 * ⛔⛔ FIVE ANSWERS, AND FOUR OF THEM ARE NOT "PASS". Collapsing any pair would state something nobody
 * measured. This estate learned the distinction on the measured-run lock, where `--conflict-exit-code 75`
 * keeps "never got the box" separate from "below floor".
 *
 *   0  compared EXACTLY `floor` packages, and every one matched its source byte-for-byte
 *   1  DRIFT — a published artifact is behind its own source. A product finding.
 *   2  UNMEASURED — fewer than `floor` packages were comparable. No opinion is available.
 *   3  FAULT — the instrument failed. ⛔ Never reported as drift.
 *   4  STALE FLOOR — MORE were comparable than the floor records. Nothing is wrong with the artifacts.
 *
 * ⭐⭐ WHY 4 IS NOT 0 WITH A WARNING. A warning is what produced the defect this answer exists for: the
 * floor sat at `2` against a comparable `3` from the night `seller-mcp` first published, and every run in
 * between printed a tick. ⇒ The run that FIRST sees a new package must fail, so the floor is raised in the
 * same change that publishes it rather than by somebody auditing months later.
 *
 * ⛔ AND IT IS NOT 2. `UNMEASURED` says no opinion is available; here a COMPLETE opinion is available and
 * it is positive. Reporting this as unmeasured would state something nobody measured, in the direction
 * this file's own head note calls the flattering error's mirror image.
 *
 * ⚠️ The floor is a RECORDED number the tree is held against, never derived from the tree — deriving it
 * would let a package dropping `src` lower the floor with it, and the gate would pass over its own
 * shrinking subject. That is the defect the floor exists for, so the count is compared to the record and
 * the record is edited by hand, deliberately, in the change that moves it.
 */
export function verdict({
  drift,
  faults,
  checked,
  ahead = 0,
  declared,
  floor = COMPARABLE_FLOOR,
}) {
  if (drift.length > 0) return { code: 1, kind: "drift" };
  // ⛔⛔ BEFORE `fault`, AND THAT ORDER IS THE POINT. Both `declared` and `floor` are TREE facts, so this
  // answers when nothing could be fetched — and an unreachable registry is precisely the run on which a
  // stale declaration would otherwise go unnoticed for another cycle. Only real drift outranks it, because
  // drift is a defect in what ships and this is a defect in the gate's own configuration.
  if (declared !== undefined && declared !== floor)
    return {
      code: 4,
      kind: "stale-floor",
      message:
        `this repository declares ${declared} publishable package(s) shipping source, and ` +
        `\`COMPARABLE_FLOOR\` records ${floor}. ⛔ Nothing is wrong with the artifacts — the DECLARATION ` +
        `is out of date. Set it to ${declared} in the same change that adds or removes the package. ` +
        "⚠️ A number left behind a package that JOINED lets the next package to LEAVE exit 0 over its own " +
        "absence, which is the whole of what it defends.",
    };
  if (faults.length > 0) return { code: 3, kind: "fault" };
  // ⛔⛔ ZERO COMPARED IS UNMEASURED, HOWEVER WELL ACCOUNTED FOR — and this arm is the one `- ahead`
  // makes necessary. `M` 2026-09-15, found by `sept-15-commerce` and driven here before it was believed:
  // `.changeset/config.json` carries a FIXED group, so `agentic-terms` and `lcp-mcp-server` move
  // together and a changeset touching `seller-mcp` as well moves all three. Then `checked` is 0,
  // `ahead` is 3, `floor` is 3, and `0 < 3 - 3` is false:
  //
  //     ✓ every published version matches the source it was cut from, byte for byte
  //       (0 of 3 declared compared, 3 awaiting publish).                              exit 0
  //
  // ⇒ A tick over a run that opened no tarball at all. That is the empty-subject-set defect wearing the
  // excuse's costume, in the gate whose entire purpose is refusing it — the same shape `parityReport`
  // already refuses when the SUBJECT set is zero, arriving instead through the accounting.
  // ⭐ `unmeasured` is exactly the right answer: not drift, not a fault, and not a pass.
  if (checked === 0)
    return {
      code: 2,
      kind: "unmeasured",
      message:
        `no package was compared. ${declared ?? floor} are declared and ${ahead} carry a version that is ` +
        "not on the registry yet, which is what a release in progress looks like. ⛔ Nothing was opened, " +
        "so there is no opinion to give — a tick here would be a statement about tarballs this run never " +
        "fetched. This is not drift and the instrument did not fail.",
    };
  // ⛔ `- ahead` is what keeps a release from being the red: a package whose source version is not yet on
  // the registry has honestly left the comparable set for the length of one publish, and that is not a
  // subject going missing.
  if (checked < floor - ahead)
    return {
      code: 2,
      kind: "unmeasured",
      message:
        `only ${checked} package(s) were compared; ${floor} are declared and ${ahead} await a publish. ` +
        "Every other publishable " +
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
  const declared = declaredComparable(manifests);
  const { drift, faults, notes, checked, ahead } = await parityReport({
    manifests,
    registry: NetworkRegistry(),
  });

  for (const n of notes) console.log(`  · ${n}\n`);

  const v = verdict({ drift, faults, checked, ahead, declared });

  // ⛔⛔ THE TICK IS REACHED ONLY BY `parity`, AND NEVER BY FALLING OFF THE END OF A LIST OF KINDS.
  // `M` 2026-09-15, measured by the plant that added the fifth verdict: this block tested three kinds and
  // let anything else reach the success line, so `verdict` returned `stale-floor` with code 4 and the
  // process printed a tick and exited 0. ⭐ Twenty-three green unit tests did not see it — they drive
  // `verdict`, which was correct; the defect was entirely in the process that reads it.
  // ⇒ The condition is now the POSITIVE one, so a verdict added later cannot fall through to a pass: it
  // exits its own code with its own message, and the worst a missing arm can do is print less detail.
  if (v.kind !== "parity") {
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
    console.error(`\n⚠ check:published-parity — ${v.message}\n`);
    exit(v.code);
  }

  console.log(
    `✓ every published version matches the source it was cut from, byte for byte ` +
      `(${checked} of ${declared} declared compared${ahead > 0 ? `, ${ahead} awaiting publish` : ""}).`,
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
