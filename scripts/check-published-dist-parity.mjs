/**
 * Hold the PUBLISHED `dist/` against a rebuild of the source it was cut from.
 *
 * ⛔⛔ WHY THIS EXISTS AND WHY `check:published-parity` DOES NOT COVER IT. That gate compares files under
 * `src/`, because `src/` is tracked and therefore has something in the tree to be compared against.
 * `dist/` is untracked, so it has none — and `dist/` is the whole consumed surface. Measured on
 * `@integraledger/agentic-terms@0.19.0`:
 *
 *     package/dist   64 files      <- everything `exports` resolves (`.` -> `./dist/index.js`)
 *     package/src    16 files      <- the only thing check:published-parity compares
 *     package root    5 files
 *     TOTAL          85            compared 16, not compared 69
 *
 * ⇒ 69 of 85 published files, including every file any consumer loads, were examined by nothing that
 * reads the registry. `check:runtime` does resolve the consumed surface, but it packs the TREE — a build
 * check, and this row exists because the failure it is about was invisible to a correct build.
 *
 * ⭐ WHAT IT CATCHES: a publish from a stale build directory. `src/` ships correct, `dist/` ships old, and
 * every other gate is green — `check:published-parity` compares the src that is fine, `check:runtime`
 * rebuilds dist fresh from the tree and never looks at what shipped.
 *
 * ⛔⛔ WHAT IT DOES NOT CATCH, MEASURED RATHER THAN ASSUMED. It would NOT have caught `0.17.0`, the artifact
 * the planning row behind this gate was filed about. That tarball was internally COHERENT — `x402-envelope` was
 * absent from src (0) and from dist (0) alike, because it was built from a tree predating the feature:
 *
 *     0.17.0 : src=15 dist=15  src-no-dist=[]  dist-no-src=[]
 *     0.19.0 : src=16 dist=16  src-no-dist=[]  dist-no-src=[]
 *
 * That failure is `check:published-parity`'s, and it catches it. ⇒ This gate is a SECOND subject set, not a
 * better instrument for the first one. Anyone tempted to merge the two should read those two lines first.
 *
 * ⭐ REBUILDING IS SOUND HERE, AND THAT WAS MEASURED BEFORE THIS WAS WRITTEN. Every publishable package in
 * this repository builds with a bare `tsc -p tsconfig.build.json` — no bundler, no timestamps. Rebuilt at
 * the published version and compared byte for byte: agentic-terms 64/64 identical, lcp-mcp-server 64/64,
 * seller-mcp 12/12. ⚠️ Determinism holds AT THE PINNED COMPILER. A TypeScript bump changes output
 * legitimately, so a red here after a toolchain change is this gate telling the truth about a `dist` that
 * no longer corresponds to its source — republish, do not weaken the gate.
 *
 * ⛔ SOURCE PARITY IS CHECKED FIRST AND REPORTED SEPARATELY. If the published `src` differs from the tree,
 * the rebuild would be of the wrong source and any dist verdict would be noise. That case is reported as
 * `skipped` naming `check:published-parity`, never as dist drift and never as a pass.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import {
  NetworkRegistry,
  publishableManifests,
} from "./check-published-parity.mjs";

/**
 * ⛔ THE FLOOR: how many packages a healthy run REBUILDS AND COMPARES. Held EQUAL to the count, never
 * merely below it, for the reason the sibling gate states: "raise it as packages start shipping" is a
 * number that only ever moves in the flattering direction, and a package that silently LEFT the set would
 * keep a green behind it.
 *
 * `M` 2026-09-16: 4, when `connector-conformance` joined the publishable set.
 *
 * ⛔⛔ AND RAISING IT EXPOSED A DEFECT IN `verdict` THAT HAD TO BE FIXED IN THE SAME CHANGE, because until
 * it was, this gate could not carry a package that had not been published yet — which every new package is.
 * `M` 2026-09-16, driven rather than reasoned:
 *
 *     {skipped: [], compared: 3, floor: 3}       -> parity        exit 0
 *     {skipped: ["new"], compared: 3, floor: 3}  -> stale-floor   exit 4
 *     {skipped: ["new"], compared: 3, floor: 4}  -> unmeasured    exit 2
 *     {skipped: ["a"],   compared: 2, floor: 3}  -> unmeasured    exit 2   <- an ORDINARY release window
 *
 * ⇒ The last line is what makes it a defect rather than a cost of the new package. From `changeset version`
 * landing until the publish, EVERY release window read `unmeasured` here — while this file's own `notes`
 * said of exactly that state that "a release in progress is not a lost subject, and this gate gives no
 * opinion on it". The note and the verdict disagreed, and the verdict is what the workflow reads.
 *
 * ⭐ It was caught by the LIVE control in the drive, not by a fixture: `assert.equal(verdict(r).kind,
 * "parity")` against the real registry answered `unmeasured` the moment a fourth package was declared.
 *
 * ⇒ `ahead` is now counted SEPARATELY from `skipped`, and the shortfall arm subtracts it. The two are not
 * one bucket: `ahead` is "not on the registry yet", which is a subject that has honestly left for the
 * length of one publish; `skipped` is "published source disagrees with the tree", which is the sibling
 * gate's finding and a state this gate deliberately gives no dist verdict on. Merging them is what let the
 * equality arm pass and the shortfall arm refuse.
 *
 * ⛔⛔ AND THE FIRST CUT OF THAT FIX SHIPPED A FALSE GREEN, WHICH IS WHY THERE ARE **THREE** ACCOUNTINGS
 * AND NOT TWO. This docblock said "exactly as the sibling gate counts it" and that sentence was FALSE.
 * `NetworkRegistry.metadata` renders a NAME-level 404 as `{versions: {}}`, so a package npmjs has NEVER
 * heard of — never published, **unpublished, or renamed** — arrived here as `v === undefined` and was
 * counted as `ahead`, and `ahead` is the one bucket the shortfall arm forgives. Driven with a stub
 * registry, at the commit that introduced it:
 *
 *     the new package answers a NAME 404, the other three are faithful
 *       -> compared 3, ahead 1, skipped 0   -> parity      exit 0     ⛔ THE FALSE GREEN
 *     the same tree, before the `ahead` fix -> unmeasured  exit 2
 *     the sibling gate, same tree           -> unmeasured  exit 2
 *
 * ⇒ `npm unpublish` or a rename would have left the dist axis GREEN INDEFINITELY, while the src axis
 * correctly opened its NOTHING-MEASURED issue for the identical state. ⭐ The sibling does not have this
 * defect because it tests `Object.keys(versions).length === 0` FIRST and does not count that as `ahead` —
 * its note says in as many words that a 404 "is what the floor exists to catch".
 *
 * ⇒ So a name npmjs has never served is `skipped`: accounted for, named, and NOT forgiven. Only "the name
 * exists and this version is not on it yet" is `ahead`.
 */
export const DIST_FLOOR = 4;

const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");

/**
 * Every regular file under `dir`, as `Map<relPath, sha256>`. Returns an empty map when `dir` is absent.
 *
 * ⛔⛔ `withFileTypes` RATHER THAN A `statSync` PER ENTRY, FOR TWO REASONS AND THE SECOND IS A DEFECT THIS
 * FUNCTION SHIPPED WITH. `statSync` FOLLOWS symlinks, so the `st.isSymbolicLink()` guard written here first
 * could never once be true — a link under the tree was followed and hashed as though it were a regular
 * file, and the guard that was supposed to stop it read as present. A `Dirent` reports the entry itself,
 * so the test now means what it says.
 *
 * ⚠️ And CodeQL named the other half: `js/file-system-race`, high — stat-then-read is a check whose answer
 * may be stale by the time the file is opened. One directory read plus a guarded open removes both.
 */
export function hashTree(dir) {
  const out = new Map();
  const walk = (d) => {
    let entries;
    try {
      entries = readdirSync(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const p = join(d, e.name);
      // ⛔ A symlink is skipped, never followed: a link out of the tree would hash a file this artifact
      // does not ship, and a link INTO it would hash one file twice under two names.
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) {
        walk(p);
        continue;
      }
      if (!e.isFile()) continue;
      // ⛔ Read and let the read decide, rather than asking first and trusting the answer.
      let buf;
      try {
        buf = readFileSync(p);
      } catch {
        continue;
      }
      out.set(relative(dir, p), sha256(buf));
    }
  };
  walk(dir);
  return out;
}

/** The `dist/` half of a published tarball's entries, rekeyed without the `dist/` prefix. */
export function publishedDist(entries) {
  const out = new Map();
  for (const [path, hash] of entries)
    if (path.startsWith("dist/")) out.set(path.slice("dist/".length), hash);
  return out;
}

/** The `src/` half, likewise — used only to decide whether a rebuild would be of the right source. */
export function publishedSrc(entries) {
  const out = new Map();
  for (const [path, hash] of entries)
    if (path.startsWith("src/")) out.set(path.slice("src/".length), hash);
  return out;
}

/**
 * Compare two `Map<path, sha256>` in BOTH directions. ⛔ Three findings reported as three, never as one
 * count: a filename check cannot see the third, and a count cannot be acted on.
 */
export function compare(published, rebuilt) {
  // ⛔⛔ NAMED FOR THE SIDE THEY ARE ON, NOT "absent"/"extra". A first draft called these `absent` and
  // `extra` and then wrote the two drift sentences the other way round: a file present in the tarball and
  // NOT emitted by the source was reported as "published dist is MISSING". Both messages existed, both
  // fired, and the diagnosis was confidently inverted — a shape a count-only assertion cannot see. The
  // plant that caught it is `DRIFT, EXTRA` in the drive.
  const onlyPublished = [...published.keys()]
    .filter((k) => !rebuilt.has(k))
    .sort();
  const onlyRebuilt = [...rebuilt.keys()]
    .filter((k) => !published.has(k))
    .sort();
  const different = [...published.keys()]
    .filter((k) => rebuilt.has(k) && published.get(k) !== rebuilt.get(k))
    .sort();
  return { onlyPublished, onlyRebuilt, different };
}

export const buildPackage = (dir) =>
  execFileSync("pnpm", ["build"], {
    cwd: dir,
    stdio: "pipe",
    encoding: "utf8",
  });

/**
 * ⛔ `faults` are the INSTRUMENT failing and are never reported as a product finding. `skipped` is a
 * package this gate deliberately did not judge and must not be counted as compared.
 */
export async function distParityReport({
  manifests,
  registry,
  build = buildPackage,
}) {
  const drift = [];
  const faults = [];
  const skipped = [];
  const notes = [];
  let compared = 0;
  // ⛔ NOT `skipped`. See the floor's docblock: a version that is not on the registry yet is a different
  // state from one this gate declined to judge, and counting them in one bucket is what made an ordinary
  // release window read as a subject going missing.
  let ahead = 0;

  for (const { dir, pkg } of publishableManifests(manifests)) {
    const { name, version } = pkg;
    let entries;
    try {
      const meta = await registry.metadata(name);
      const versions = meta.versions ?? {};
      // ⛔⛔ THE NAME FIRST, AND THE VERSION SECOND. `NetworkRegistry` renders a NAME-level 404 as an empty
      // `versions`, so asking only about the version cannot tell "we have not published this one yet"
      // from "npmjs has never heard of this package" — and the second is a subject that LEFT, which is
      // exactly what the floor is for. See the docblock on DIST_FLOOR: conflating them shipped a false
      // green on this gate.
      if (Object.keys(versions).length === 0) {
        notes.push(
          `${name} — never published, so there is no dist/ to compare. ⚠️ A registry 404 for the NAME ` +
            "reads the same way here, so a package that was unpublished or renamed arrives as this note " +
            "— which is what the floor exists to catch. This is not forgiven and never prints a tick.",
        );
        skipped.push(name);
        continue;
      }
      const v = versions[version];
      if (v === undefined) {
        notes.push(
          `${name}@${version} is not published — a release in progress is not a lost subject, and this gate gives no opinion on it.`,
        );
        ahead += 1;
        continue;
      }
      entries = await registry.contents(name, version, v.dist?.tarball);
    } catch (err) {
      faults.push(`${name}@${version} — ${err.message}`);
      continue;
    }

    const pubDist = publishedDist(entries);
    if (pubDist.size === 0) {
      faults.push(
        `${name}@${version} published NO dist/ entries. This gate compares the consumed surface; there is nothing here to compare and a tick would be a statement about an artifact it never opened.`,
      );
      continue;
    }

    // ⛔ The rebuild is only meaningful if the published src is the src we hold.
    const srcDiff = compare(publishedSrc(entries), hashTree(join(dir, "src")));
    if (
      srcDiff.onlyPublished.length +
        srcDiff.onlyRebuilt.length +
        srcDiff.different.length >
      0
    ) {
      skipped.push(name);
      notes.push(
        `${name}@${version} — published src differs from the tree, so a rebuild would be of the wrong source. That is \`check:published-parity\`'s finding, not this gate's; this gate gives no dist verdict here.`,
      );
      continue;
    }

    try {
      build(dir);
    } catch (err) {
      faults.push(
        `${name}@${version} — rebuild failed: ${String(err.message).slice(0, 300)}`,
      );
      continue;
    }

    const rebuilt = hashTree(join(dir, "dist"));
    if (rebuilt.size === 0) {
      faults.push(
        `${name}@${version} — the rebuild emitted no dist/, so nothing was compared.`,
      );
      continue;
    }

    const d = compare(pubDist, rebuilt);
    compared += 1;
    if (d.onlyRebuilt.length > 0)
      drift.push(
        `${name}@${version} — published dist/ is MISSING ${d.onlyRebuilt.length} file(s) the source emits: ${d.onlyRebuilt.slice(0, 8).join(", ")}`,
      );
    if (d.onlyPublished.length > 0)
      drift.push(
        `${name}@${version} — published dist/ carries ${d.onlyPublished.length} file(s) this source does not emit: ${d.onlyPublished.slice(0, 8).join(", ")}`,
      );
    if (d.different.length > 0)
      drift.push(
        `${name}@${version} — ${d.different.length} published dist/ file(s) DIFFER in content from the rebuild: ${d.different.slice(0, 8).join(", ")}`,
      );
  }

  return { drift, faults, skipped, notes, compared, ahead };
}

/**
 * ⛔⛔ ZERO COMPARED IS UNMEASURED, HOWEVER WELL ACCOUNTED FOR. A run that skipped every package because a
 * release is in flight has no opinion to give, and a tick there is the empty-subject-set defect.
 */
export function verdict({
  drift,
  faults,
  skipped,
  compared,
  ahead = 0,
  floor = DIST_FLOOR,
}) {
  if (drift.length > 0) return { code: 1, kind: "drift" };
  if (faults.length > 0) return { code: 3, kind: "fault" };
  if (compared === 0) return { code: 2, kind: "unmeasured" };
  // ⛔ EVERY DECLARED PACKAGE IS ACCOUNTED FOR, in one of three ways — compared, awaiting a publish, or
  // deliberately not judged. A total that does not reach the floor means one of them is not there at all.
  if (compared + skipped.length + ahead !== floor)
    return { code: 4, kind: "stale-floor" };
  // ⛔ `- ahead` is what keeps a release from being the red, and what lets a package that has landed but
  // never published be carried at all. A package that has LEFT the set still lands here, because leaving
  // does not increment `ahead`.
  if (compared < floor - ahead) return { code: 2, kind: "unmeasured" };
  return { code: 0, kind: "parity" };
}

/* ------------------------------------------------------------------ the process */

/**
 * The subject set, read with a guard.
 *
 * ⛔⛔ AN UNCAUGHT THROW HERE EXITS **1**, AND THE WORKFLOW MAPS 1 TO DRIFT. A stray file under `packages/`,
 * or a directory with no manifest, would have ended the process with the code that files *"the published
 * `dist/` is not what this source emits"* — a product finding, named against artifacts the run never opened.
 * `M` 2026-09-17: the read was `readdirSync(root).map(...)` with no filter and no `try`.
 *
 *   · an entry that is not a DIRECTORY cannot be a package and is skipped: a stray file is not a finding
 *     about any artifact;
 *   · a DIRECTORY whose `package.json` cannot be read or parsed is a FAULT, named, and never a silent skip —
 *     the floor would otherwise absorb it and the run would report over a subject set one package smaller,
 *     which is this gate's own defect arrived at from the manifest side.
 *
 * ⚠️ The sibling gate makes the same choice one level down: its `walk` yields a fault per unreadable path
 * rather than abandoning the directory (`check-published-parity.mjs`).
 */
export function readManifests(root) {
  const manifests = [];
  const unreadable = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const dir = join(root, entry.name);
    try {
      manifests.push({
        dir,
        pkg: JSON.parse(readFileSync(join(dir, "package.json"), "utf8")),
      });
    } catch (error) {
      unreadable.push(
        `${entry.name}/package.json — ${error.code ?? error.message}`,
      );
    }
  }
  return { manifests, unreadable };
}

/**
 * ⛔ THE WORKFLOW READS THE EXIT CODE, not a return value, so `main` is driven as a process by the drive's
 * sibling gate convention. ⭐ A refused run prints NO success line, whatever its kind — a tick beside a
 * refusal is the shape a reader greps for and believes.
 */
export async function main({
  root = new URL("../packages", import.meta.url).pathname,
  registry = NetworkRegistry({}),
} = {}) {
  const { manifests, unreadable } = readManifests(root);
  if (unreadable.length > 0) {
    console.error(
      "\n✕ check:published-dist-parity — THE SUBJECT SET COULD NOT BE READ\n",
    );
    for (const u of unreadable) console.error(`   • ${u}`);
    console.error(
      "\n⛔ Nothing here is a claim about any published artifact: the instrument could not decide what to " +
        "compare. This is a fault, and the floor is deliberately not consulted — a package whose manifest " +
        "cannot be read must not be absorbed as one that left.\n",
    );
    return 3;
  }
  const report = await distParityReport({ manifests, registry });
  const v = verdict(report);

  for (const n of report.notes) console.log(`  · ${n}\n`);

  if (v.kind === "drift") {
    console.error("\n✕ check:published-dist-parity — DRIFT\n");
    for (const d of report.drift) console.error(`   • ${d}`);
    console.error(
      "\n⛔ The artifact a consumer loads is not what this source emits. Republish; do not adjust the gate.\n",
    );
    return v.code;
  }
  if (v.kind === "fault") {
    console.error("\n✕ check:published-dist-parity — THE INSTRUMENT FAILED\n");
    for (const f of report.faults) console.error(`   • ${f}`);
    console.error(
      "\n⛔ This is NOT a product finding and must not be reported as one.\n",
    );
    return v.code;
  }
  if (v.kind === "stale-floor") {
    console.error(
      `\n✕ check:published-dist-parity — the floor is ${DIST_FLOOR} and this run accounted for ` +
        `${report.compared + report.skipped.length + report.ahead} (${report.compared} compared, ` +
        `${report.ahead} awaiting a publish, ${report.skipped.length} not judged). ` +
        "⛔ Raise DIST_FLOOR when a package joins; never lower it to make a package that left go quiet.\n",
    );
    return v.code;
  }
  if (v.kind === "unmeasured") {
    console.error(
      `\n⚠ check:published-dist-parity — UNMEASURED: ${report.compared} package(s) compared. ` +
        "A run that opened no published dist has no opinion to give, and a tick here would be a statement about artifacts it never read.\n",
    );
    return v.code;
  }

  console.log(
    `✓ check:published-dist-parity — ${report.compared} published dist/ tree(s) rebuilt from their own source ` +
      `and matched byte for byte, of ${DIST_FLOOR} declared (${report.ahead} awaiting a publish, ` +
      `${report.skipped.length} not judged here).`,
  );
  return 0;
}

if (process.argv[1] === new URL(import.meta.url).pathname)
  process.exit(await main());
