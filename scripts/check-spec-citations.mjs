#!/usr/bin/env node
/**
 * ⛔⛔ SHIPPED PROSE CITES THE PUBLISHED SPECIFICATION, AND NEVER AN INTERNAL REVISION.
 *
 * WHY THIS EXISTS. `v1.36`, `v1.37` and `v1.38` are Integra's internal working drafts. They are published
 * nowhere a reader of these packages can reach, so a citation of one is not a stale stamp to be refreshed:
 * it is a reference that CANNOT BE FOLLOWED, shipped inside an npm tarball, and it also discloses the
 * existence and numbering of an unpublished document. Both of those are permanent once a version is on the
 * registry — an already-published tarball cannot be recalled, only succeeded.
 *
 * THE RULE. Shipped prose may cite `LCP §N`. The section numbering is identical between the internal and
 * the published editions, so the bare section is what a reader can actually go and follow. The published
 * edition is `LCP_SPEC_VERSION`, exported by `@integraledger/lcp-kernel`, and it is the only version string
 * this repository has any business naming.
 *
 * ⚠️ WHAT THIS CANNOT CATCH, said plainly. It does not know whether a citation is ACCURATE. Nothing
 * mechanical does. What it guarantees is narrower and worth having: no shipped sentence points a reader at
 * a document that does not exist for them.
 *
 * ★ WHY THE SUBJECT SET IS "WHAT NPM PACKS", AND WHY THAT IS NOT `src` ALONE. The audit that opened this
 * scanned `packages/*​/src/**` and found five citations. The real number in the tarball was seven: npm packs
 * `README.md` whatever the `files` field says, and `packages/lcp-mcp-server/README.md` carried the same
 * sentence as `src/server.ts`. A pathspec that cannot see a surface reports it clean forever, which is the
 * defect this gate exists to prevent, arrived at from the measuring side. So the set is derived from each
 * publishable manifest's own `files`, plus the two names npm always adds.
 *
 * ★★ AND "SHIPPED" IS TWO SURFACES, NOT ONE. This repository publishes to npm AND to
 * `agenticterms.integraledger.com`, which is built out of `website/` in this same tree. `M` 2026-09-14 the
 * deployed site served THREE citations of an internal draft — one of them rendered at `/mcp/boundary`, all
 * three in `/llms-full.txt`, the file written to be ingested wholesale by agents — while this gate reported
 * `44 packed file(s) … none spells an internal LCP revision` and was CORRECT: no manifest lists `website/`
 * in its `files`, so the site was outside the subject set by construction. ⇒ The sentence above about a
 * pathspec that cannot see a surface was true one level up, about the tarball versus the estate. The
 * subject set is now WHAT THIS REPOSITORY PUBLISHES. planning register #204.
 *
 * ⚠️ `dist/` IS IN THE TARBALL AND IS DELIBERATELY NOT WALKED. It is gitignored `tsc` output whose
 * docblocks are copied verbatim out of `src` — measured: every `dist` hit in the opening audit was the same
 * sentence as its `src` original, and there were no others. Walking it would make this gate's subject set
 * depend on whether anyone had run a build, which is the one property a gate must not have; `check:dist`
 * already refuses a `dist` file whose `src` original is gone. `src` is where the sentence is written and
 * where it gets fixed.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

/**
 * ⚠️ The drive hands in a fixture through `INTEGRA_GATE_ROOT`, the same spelling `check:hermetic-tests`
 * uses in this directory. ⭐ Unlike that gate this one needs no trailing-separator normalisation: every
 * path here is built with `join()`, which normalises either spelling, and `join` is the only way `ROOT`
 * is ever consumed. Said rather than relied on — the sibling gate paid for that difference once.
 *
 * USAGE
 *   node scripts/check-spec-citations.mjs
 *   INTEGRA_GATE_ROOT=<dir> node scripts/check-spec-citations.mjs   # a fixture (the drive uses this)
 */
const ROOT =
  process.env["INTEGRA_GATE_ROOT"] ?? new URL("..", import.meta.url).pathname;

/**
 * An INTERNAL LCP revision spelled in prose: `v1.37`, `v0.1.38`, `v1.36`.
 *
 * ⛔ THE TWO-DIGIT PATCH IS THE DISCRIMINATOR AND IT IS LOAD-BEARING. Ported unchanged from
 * `integra-protocol`, where it is documented at length: `v1.0` is the PUBLISHED edition and also appears in
 * shipped prose for W3C Bitstring Status List, so a looser `vN.N` would refuse legitimate text and a gate
 * that refuses legitimate text gets weakened rather than obeyed. Integra's internal series has always been
 * `1.3x`, and two digits is what separates it from every other `vN.N` anyone writes.
 */
const ANY_REVISION = /v(?:0\.)?1\.\d{2}\b/g;

/**
 * The prose halves of a published surface. Everything else is bytes, not sentences.
 *
 * `.mdx` and `.tsx` are here for the site: the documentation pages are MDX and the routes that frame them
 * are TSX. Neither appears anywhere under `packages/`, so adding them widens the site walk and leaves the
 * packed walk at exactly the files it had — measured, not assumed.
 */
const TEXT_EXT = new Set([
  ".ts",
  ".tsx",
  ".mts",
  ".cts",
  ".js",
  ".mjs",
  ".cjs",
  ".md",
  ".mdx",
  ".json",
]);

/**
 * npm packs these whatever `files` says, and forgetting it is exactly how the README leak survived the
 * audit that found everything else. `package.json` is here because `description` and `keywords` are prose
 * a stranger reads on the registry page before they read anything else.
 */
const ALWAYS_PACKED = ["README.md", "package.json"];

/** Built output: in the tarball, derived from `src`, and gitignored. See the docblock. */
const NOT_WALKED = new Set(["dist"]);

/**
 * ⛔ Raise as packages and surfaces are added; never lower it to make a deletion pass. 44 files today
 * across three publishable packages, cross-checked against `npm pack --dry-run --json` for each of them.
 * The floor's job is the walk collapsing — losing either large package drops the count to 25.
 */
const FILE_FLOOR = 30;

/**
 * ⛔⛔ THE SECOND SURFACE: the pages `agenticterms.integraledger.com` serves.
 *
 * `website/content` is the MDX a reader loads; `website/src` is the routes and components that frame it,
 * including `llms.txt` and `llms-full.txt`. ⚠️ Deliberately NOT the whole of `website/`: a lockfile, a
 * `tsconfig` and a `wrangler.toml` emit no sentence to any reader, and walking them would widen the
 * subject set without widening the SURFACE — which is the failure this gate exists to refuse, pointed the
 * other way. `M` 2026-09-14 all ten `LCP §` citations and all three internal revisions under `website/`
 * were in `website/content`; `website/src` held zero of each and is here because a route that renders
 * prose is one commit away from carrying some.
 */
const SITE_ROOTS = ["website/content", "website/src"];

/**
 * ⛔ Same job as `FILE_FLOOR`, for the site. 51 files today — 28 under `content`, 23 under `src` — so a
 * floor of 40 goes red if EITHER root drops out, which is the collapse this is for. Never lower it to
 * make a deletion pass.
 */
const SITE_FLOOR = 40;

/**
 * ⛔ DIRECTORY-OR-NOT COMES FROM THE SAME DIRECTORY READ, not from a second syscall. A `statSync` between
 * `readdirSync` and `readFileSync` is a time-of-check/time-of-use window; `withFileTypes` closes it by
 * answering from the entry already in hand.
 */
function walkInto(out, dir, rel) {
  for (const ent of readdirSync(dir, { withFileTypes: true })) {
    const name = ent.name;
    const p = join(dir, name);
    if (ent.isDirectory()) walkInto(out, p, `${rel}/${name}`);
    else if (TEXT_EXT.has(name.slice(name.lastIndexOf("."))))
      out.push({ where: `${rel}/${name}`, text: readFileSync(p, "utf8") });
  }
}

/** One piece of shipped prose: where it came from, and what it says. */
function shippedProse() {
  const out = [];
  const walk = (dir, rel) => walkInto(out, dir, rel);

  const packages = [];
  for (const pkg of readdirSync(join(ROOT, "packages"))) {
    const dir = join(ROOT, "packages", pkg);
    if (!statSync(dir).isDirectory()) continue;
    const manifestPath = join(dir, "package.json");
    // ⛔ THE READ IS THE CHECK. `existsSync` then `readFileSync` is the same time-of-check/time-of-use
    // window as the two above, and a package directory with no manifest is not an error worth a
    // separate syscall to discover.
    let manifest;
    try {
      manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    } catch {
      continue;
    }
    if (manifest.private === true) continue;

    const before = out.length;
    const entries = [
      ...new Set([
        ...(Array.isArray(manifest.files) ? manifest.files : []),
        ...ALWAYS_PACKED,
      ]),
    ];
    for (const entry of entries) {
      if (NOT_WALKED.has(entry)) continue;
      const p = join(dir, entry);
      // ⛔ NO existsSync BEFORE THE READ — that is the check-then-use CodeQL flags. A missing
      // entry is answered by the read failing, which is the same answer one syscall later.
      // ⛔ NO STAT AT ALL. Even inside a try/catch, a `statSync` before a `readFileSync` is a
      // time-of-check/time-of-use window — the stat answers about one moment and the read happens at
      // another. ⇒ ATTEMPT THE READ AND LET IT ANSWER: a directory throws `EISDIR`, a missing entry
      // throws `ENOENT`, and both are answered without a second syscall to disagree with.
      if (TEXT_EXT.has(entry.slice(entry.lastIndexOf(".")))) {
        let text;
        try {
          text = readFileSync(p, "utf8");
        } catch {
          continue;
        }
        out.push({ where: `packages/${pkg}/${entry}`, text });
      } else {
        try {
          walk(p, `packages/${pkg}/${entry}`);
        } catch {}
      }
    }
    packages.push({ pkg, files: out.length - before });
  }
  return { prose: out, packages };
}

/**
 * The prose the documentation site serves, one root at a time so a root that contributes nothing is
 * reportable by name rather than hidden inside a total.
 *
 * ⛔ A MISSING ROOT IS A REFUSAL, NOT A SKIP. `readdirSync` is allowed to throw here: if `website/content`
 * has been moved or renamed, this gate must go red and say so, because the alternative is reporting clean
 * over a surface it stopped reading. That is the whole defect.
 */
function siteProse() {
  const out = [];
  const roots = [];
  for (const root of SITE_ROOTS) {
    const before = out.length;
    walkInto(out, join(ROOT, root), root);
    roots.push({ root, files: out.length - before });
  }
  return { prose: out, roots };
}

// ---- canaries: prove the pattern still discriminates before trusting a clean result ----
//
// ⛔ THE SECOND HALF IS NOT DECORATION. A gate that refused `LCP §C.1` as well as `LCP v1.38 §C.1` would be
// refusing the CITATION rather than the REVISION, and the fix it demanded — deleting the reference — would
// destroy the load-bearing half of every sentence it touched. The published edition `v1.0` is in the same
// list for the same reason: it is the one version string this prose is allowed to name.
const CANARIES = [
  [
    "LCP v1.38 §C.9 shows a different vocabulary",
    true,
    "the current internal draft",
  ],
  ["cited against v1.37 before the rename", true, "an earlier internal draft"],
  [
    "v1.36 is where the rule first appeared",
    true,
    "the earliest internal draft",
  ],
  [
    "the kernel constant is v0.1.38",
    true,
    "the leading-zero spelling of the same draft",
  ],
  [
    "LCP §C.9 illustrates a different vocabulary",
    false,
    "a bare section citation — the FIX",
  ],
  [
    "verify before sign (LCP §5.3)",
    false,
    "a bare section citation in a README table",
  ],
  ["the published edition is v1.0", false, "the PUBLISHED edition"],
  [
    "W3C Bitstring Status List v1.0",
    false,
    "a standard that shares the published edition's shape",
  ],
  ["MCP v2.1 annotations", false, "an unrelated one-digit version"],
];
for (const [sample, shouldFlag, what] of CANARIES) {
  ANY_REVISION.lastIndex = 0;
  if (ANY_REVISION.test(sample) !== shouldFlag)
    throw new Error(
      `check:spec-citations canary FAILED: "${sample}" (${what}) should ${shouldFlag ? "" : "NOT "}be flagged. ` +
        "The pattern is not discriminating and a clean result would mean nothing.",
    );
}

// ---- the scan ----
const { prose: packed, packages } = shippedProse();
const { prose: site, roots } = siteProse();

// ⛔⛔ THE TWO SURFACES ARE COUNTED SEPARATELY AND FLOORED SEPARATELY, ON PURPOSE. One combined total under
// one floor is a total in which losing the entire site walk is masked by the packed files still being
// there — 44 of 95 clears any floor a 95-file tree would set. Two counts, two floors: each surface has to
// be present on its own.
const prose = [...packed, ...site];

// ⛔ THE BLIND-GATE GUARDS. A walker that finds nothing reports clean forever, and so does one that quietly
// stops descending into a package or drops a surface. Each of these is a way that has actually happened
// somewhere in this workspace, asserted before any result is believed.
for (const [surface, n, floor] of [
  ["the packed set", packed.length, FILE_FLOOR],
  ["the documentation site", site.length, SITE_FLOOR],
]) {
  if (n === 0) {
    console.error(
      `⛔ check:spec-citations walked ZERO files of ${surface}. The walk is broken. Refusing to report clean.`,
    );
    process.exit(1);
  }
  if (n < floor) {
    console.error(
      `⛔ check:spec-citations walked ${n} file(s) of ${surface}, floor is ${floor}.\n\n` +
        "   A walk that collapsed is indistinguishable from a clean tree. If surfaces were removed on\n" +
        "   purpose, lower the floor in this file deliberately and say why.\n",
    );
    process.exit(1);
  }
}
const emptyRoots = roots.filter((r) => r.files === 0);
if (emptyRoots.length > 0) {
  console.error(
    `⛔ check:spec-citations walked no prose at all under: ${emptyRoots.map((r) => r.root).join(", ")}.\n` +
      "   A site root contributing nothing means the walk lost it, and the site is deployed from this\n" +
      "   tree. Refusing to report clean over a surface that a reader can load.\n",
  );
  process.exit(1);
}
const empty = packages.filter((p) => p.files === 0);
if (empty.length > 0) {
  console.error(
    `⛔ check:spec-citations walked no prose at all in: ${empty.map((p) => p.pkg).join(", ")}.\n` +
      "   A publishable package contributing nothing means the walk lost it. Refusing to report clean.\n",
  );
  process.exit(1);
}
// The specific blindness this gate was written after: the README is packed, was not in the audit's
// pathspec, and carried a citation. If it ever falls out of the subject set again, that must be red.
const missingReadme = packages
  .map((p) => p.pkg)
  .filter((pkg) => !prose.some((f) => f.where === `packages/${pkg}/README.md`));
if (missingReadme.length > 0) {
  console.error(
    `⛔ check:spec-citations did not walk the README of: ${missingReadme.join(", ")}.\n` +
      "   npm packs README.md whatever `files` says, and a README leak is what this gate was written\n" +
      "   after. Refusing to report clean over a surface that ships.\n",
  );
  process.exit(1);
}

const offenders = [];
for (const { where, text } of prose) {
  text.split("\n").forEach((line, i) => {
    ANY_REVISION.lastIndex = 0;
    const cited = [
      ...new Set([...line.matchAll(ANY_REVISION)].map((m) => m[0])),
    ];
    if (cited.length > 0)
      offenders.push({ where, line: i + 1, cites: cited.sort().join(", ") });
  });
}

if (offenders.length > 0) {
  console.error(
    `\nRefusing to verify: ${offenders.length} published line(s) spell an internal LCP revision, ` +
      `across ${prose.length} file(s) this repository publishes — ${packed.length} that npm packs and ` +
      `${site.length} that the documentation site serves:\n`,
  );
  for (const o of offenders)
    console.error(`  ${o.where}:${o.line} — cites ${o.cites}`);
  console.error(
    "\nCite `LCP §N` instead. The section numbering is identical between the internal and the published\n" +
      "editions, so the section is the half a reader can follow — the revision is the half that names a\n" +
      "document they cannot obtain. If a sentence genuinely depends on what an internal draft said and the\n" +
      "published text says otherwise, say so about the PUBLISHED text rather than quoting the draft.\n",
  );
  process.exit(1);
}

// ⭐ THE GREEN STATES ITS OWN SUBJECT SET, both halves of it. A reader of this line should be able to
// tell what a pass does NOT cover without opening the file: it covers what npm packs and what the site
// serves, and nothing else in this tree.
console.log(
  `check:spec-citations — ${prose.length} published file(s): ${packed.length} packed across ` +
    `${packages.length} publishable package(s) (${packages.map((p) => `${p.pkg} ${p.files}`).join(", ")}), ` +
    `and ${site.length} served by the documentation site ` +
    `(${roots.map((r) => `${r.root} ${r.files}`).join(", ")}). None spells an internal LCP revision, ` +
    `${CANARIES.length}/${CANARIES.length} pattern canaries.`,
);
