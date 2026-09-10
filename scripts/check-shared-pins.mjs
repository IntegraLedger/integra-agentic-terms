#!/usr/bin/env node
/**
 * `check:shared-pins` — **the dependency surface this workspace shares with the published protocol line
 * must agree with it, and every pin that carries that obligation must say so.**
 *
 * ⛔⛔ **THIS REPOSITORY IS THE MIDDLE OF A THREE-REPOSITORY CHAIN AND WAS THE ONLY LINK WITH NO GATE.**
 * The protocol repository publishes the line; this repository consumes it and PUBLISHES AGAIN; a
 * downstream consumer then installs both. So a dependency this package declares lands in that tree
 * beside the protocol's own copy, and until this gate existed nothing here compared the two.
 *
 * Measured 2026-09-10, and it is why this file exists. The protocol catalogue moved `zod` 4.4.3 -> 4.5.4
 * and published; `@integraledger/agentic-terms@0.16.0` was already on the registry declaring `zod: 4.4.3`,
 * immutably. Commerce then had the line at two versions of `zod` at once:
 *
 *   4.5.4  @integraledger/lcp-discovery
 *   4.4.3  @integraledger/agentic-terms@0.16.0     <- published from here
 *
 * ⇒ That consumer's cross-repository job went red **with no commit landing in it to explain the failure**,
 * and the only place that could see the split was the one furthest from the cause. This gate moves
 * that discovery to the repository that creates it, BEFORE the publish that makes it immutable.
 *
 * ⭐ **AND TWO COPIES OF `zod` IS NOT A BOOKKEEPING COMPLAINT.** `zod` is absent from this package's
 * public `.d.ts` surface — measured, zero mentions — so the compiler will not catch it. What breaks is
 * runtime: a schema built by one copy fails `instanceof` against the other, and every branch that asks
 * "is this one of mine" silently answers no. A type-checker cannot see it and a test only sees it if the
 * two copies actually meet.
 *
 * ## ⭐ THE COMPARISON WITH TWO ANSWERS, AND WHY THIS ONE IS RIGHT
 *
 * There are two things "the protocol repo's pin" can mean, and they differ for exactly as long as it
 * matters:
 *
 *   THE CATALOG STRING at the protocol repo's `main` — unreadable from here, and WRONG even if it were
 *     readable. This workspace does not compile against the protocol repo's working tree. Between a bump
 *     there and a release, that string names a version nothing here consumes, so a gate reading it would
 *     go red on a divergence that does not exist and green on one that does.
 *
 *   THE VERSION THE PUBLISHED LINE DECLARES — what `@integraledger/lcp-discovery@0.18.1` actually names
 *     in its own `dependencies`, read out of `node_modules`. That is the copy that lands in this tree
 *     beside ours, and a disagreement between the two is precisely the split described above. It needs no
 *     cross-repo read at all: the published tarball carries the protocol repo's catalog decision,
 *     expanded, and it is already on this disk.
 *
 * ⇒ So the cross-repo obligation is enforced ENTIRELY from this side, against the artifact rather than
 * against the other repository's source. Read the INSTALLED line, not the declared one.
 *
 * ## WHAT IT ASSERTS — three directions, and the last two are what keep the class closed
 *
 *   ONE   A name declared by BOTH the published line and this workspace must carry the SAME version.
 *         This is the split above.
 *
 *   TWO   A pin whose comment CLAIMS parity that the published line cannot witness is red. An
 *         unwitnessable claim reads as covered and is not.
 *
 *   THREE A pin the published line DOES declare, but whose comment claims nothing, is red. Direction ONE
 *         alone would leave the obligation invisible to the next reader, and a hand-written marker that
 *         nobody is required to write is a marker that silently stops being written. This direction is
 *         what makes the subject set self-maintaining: add a shared dependency and the gate makes you
 *         document it the same day.
 *
 * ⛔ **THE SUBJECT SET IS DERIVED FROM THE TREE ON BOTH SIDES.** The published side comes from walking the
 * real `node_modules` link graph; this side from `pnpm-workspace.yaml`'s catalog AND from every
 * `packages/*` manifest. Neither is a list maintained in this file. Today exactly one name is shared
 * (`zod`) — and that number is derived on every run, so the day a second one arrives it is in scope
 * without anyone remembering to add it.
 *
 * ⚠️ **THE PUBLISHED SIDE IS `dependencies` ONLY, WHICH IS NARROWER THAN IT FIRST LOOKS.** A published
 * package's devDependencies are never installed for a consumer, so they cannot put a second copy in this
 * tree and there is nothing here for direction ONE to compare. Scanning them would manufacture
 * constraints that no tree can violate, which is a different way of lying about coverage.
 *
 * ⛔ **THE LINK GRAPH, NEVER THE `.pnpm` DIRECTORY LISTING.** pnpm does not prune the store when a
 * dependency moves, so `ls node_modules/.pnpm` reports versions nothing links to. A resolved link is the
 * tree; a directory is sediment. Workspace packages are excluded by the same walk: their realpath is under
 * `packages/`, not under the store.
 *
 * ⛔ **AN EMPTY SUBJECT SET IS REFUSED.** A tree with no installed protocol packages is a broken install,
 * not a clean one — a gate that compares against nothing and says so in green is the failure this
 * repository has been bitten by more than any other.
 *
 * ⚠️ Ported from the downstream consumer, whose copy is the original. The mechanism is identical and
 * deliberately so: two consumers of one line should not disagree about what parity means. Every inline
 * comment below records a failure measured there — the quoting forms, the comment-at-any-indentation
 * dedent, pushing the store entry rather than the package — and each one applies here unchanged.
 *
 * USAGE
 *   node scripts/check-shared-pins.mjs
 */
import { existsSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import { join, sep } from "node:path";

// ⛔ Normalised to a trailing separator, so a derived root and one handed in by a drive behave alike.
const ROOT_RAW =
  process.env["INTEGRA_GATE_ROOT"] ?? new URL("..", import.meta.url).pathname;
const ROOT = ROOT_RAW.endsWith("/") ? ROOT_RAW : `${ROOT_RAW}/`;

const fail = [];

/**
 * A WIRING error — the gate cannot run, as distinct from the tree being wrong.
 *
 * ⛔ It reports everything found so far BEFORE exiting. A fix pushed onto a deferred fail list that an
 * earlier throw preempts is inert: one in this repository printed zero times while a changeset claimed the
 * class closed. Anything accumulated is a real finding and must survive the wiring fault that follows it.
 */
const die = (message) => {
  console.error("\n✕ shared-pins check failed\n");
  for (const f of fail) console.error(`  • ${f}\n`);
  console.error(`  • ${message}\n`);
  process.exit(1);
};

/**
 * The sentence a catalog comment uses to take on the cross-repo obligation.
 *
 * ⚠️ This is the ONE hand-written string here, and it is a fact about the prose rather than a subject set:
 * the subjects are derived, and direction THREE makes the tree refuse a shared pin that has not written
 * this sentence. So the marker cannot silently lose coverage the way a maintained list does — a pin that
 * stops matching it does not vanish from the gate, it goes red.
 */
const CLAIM_MARKER = "protocol repo's catalog";

/* ---------- this side: the catalog, with the comment that owns each entry ---------- */

const WORKSPACE_FILE = join(ROOT, "pnpm-workspace.yaml");
if (!existsSync(WORKSPACE_FILE))
  die(
    `no pnpm-workspace.yaml at ${WORKSPACE_FILE} — the catalog is half this gate's subject set`,
  );

/**
 * Reads `catalog:` as entries carrying their documentation: the comment block immediately above an entry
 * plus any trailing comment on its own line. Both are where the parity sentence is actually written, and
 * a parser that kept only the key/value would make direction TWO and THREE unimplementable.
 */
function readCatalog(text) {
  const lines = text.split("\n");
  const start = lines.findIndex((l) => l.trimEnd() === "catalog:");
  if (start === -1) return null;
  const entries = new Map();
  const unparseable = [];
  let block = [];
  for (let i = start + 1; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim() === "") {
      block = [];
      continue;
    }
    // ⛔ A comment at ANY indentation is documentation, never a dedent. The first version tested for a
    // column-0 line BEFORE testing for a comment, so a single divider comment at column 0 ended the scan
    // and every entry below it left the subject set — measured, with a live viem split going green behind
    // it. Only a NON-COMMENT line at column 0 leaves `catalog:`.
    const comment = line.match(/^\s*#\s?(.*)$/);
    if (comment) {
      block.push(comment[1]);
      continue;
    }
    if (/^\S/.test(line)) break;
    // ⛔⛔ THREE QUOTING FORMS, AND AN UNPARSEABLE LINE IS REFUSED RATHER THAN SKIPPED. The first version
    // required a DOUBLE-quoted value and `continue`d on anything else, so `zod: '4.4.2'` or a bare
    // `viem: 2.55.19` silently vanished from the subject set — and a vanished entry cannot fail any of the
    // three directions. This file already writes single quotes in-house (`'@swc/core': false`), so that was
    // the house style, not an exotic input. Skipping is what made it invisible; refusing is the fix.
    const entry = line.match(
      /^\s+(?:"([^"]+)"|'([^']+)'|([^\s:#]+))\s*:\s*(?:"([^"]*)"|'([^']*)'|([^\s#]+))\s*(?:#\s?(.*))?$/,
    );
    if (!entry) {
      unparseable.push(`line ${i + 1}: ${line.trim()}`);
      block = [];
      continue;
    }
    const name = entry[1] ?? entry[2] ?? entry[3];
    const version = entry[4] ?? entry[5] ?? entry[6];
    entries.set(name, { version, doc: [...block, entry[7] ?? ""].join(" ") });
    block = [];
  }
  return { entries, unparseable };
}

const parsed = readCatalog(readFileSync(WORKSPACE_FILE, "utf8"));
if (parsed === null)
  die("pnpm-workspace.yaml declares no `catalog:` — nothing to compare");
if (parsed.unparseable.length > 0)
  die(
    "these `catalog:` lines could not be read, and a line this gate cannot read is a pin it is not " +
      "checking:\n      " +
      parsed.unparseable.join("\n      "),
  );
const catalog = parsed.entries;
if (catalog.size === 0)
  die("`catalog:` parsed to zero entries — the parser and the file disagree");

/* ---------- this side: direct pins in packages/*, which the catalog does not cover ---------- */

const PACKAGES = join(ROOT, "packages");
if (!existsSync(PACKAGES)) die(`no packages/ at ${PACKAGES}`);

/** name -> [{ spec, pkg }] for third-party deps a manifest pins itself rather than via `catalog:`. */
const direct = new Map();
for (const dir of readdirSync(PACKAGES)) {
  const manifest = join(PACKAGES, dir, "package.json");
  if (!existsSync(manifest)) continue;
  const pkg = JSON.parse(readFileSync(manifest, "utf8"));
  for (const section of ["dependencies", "devDependencies"]) {
    for (const [name, spec] of Object.entries(pkg[section] ?? {})) {
      if (name.startsWith("@integraledger/")) continue;
      if (
        spec === "catalog:" ||
        spec.startsWith("catalog:") ||
        spec.startsWith("workspace:")
      )
        continue;
      if (!direct.has(name)) direct.set(name, []);
      direct.get(name).push({ spec, pkg: pkg.name ?? dir });
    }
  }
}

/* ---------- the other side: what the INSTALLED published line declares ---------- */

const STORE = join(ROOT, "node_modules", ".pnpm") + sep;

/**
 * Every `@integraledger/*` package reachable by following real links from this workspace, keeping only
 * those resolved into the pnpm store.
 *
 * ⛔ Registry-installed packages are the published line; workspace packages are ours. They are
 * indistinguishable by name and by manifest — only the realpath separates them.
 */
function readPublishedLine() {
  const seen = new Map();
  const queue = [
    ROOT.slice(0, -1),
    ...readdirSync(PACKAGES).map((d) => join(PACKAGES, d)),
  ];
  while (queue.length > 0) {
    const scope = join(queue.shift(), "node_modules", "@integraledger");
    if (!existsSync(scope)) continue;
    for (const name of readdirSync(scope)) {
      let real;
      try {
        real = realpathSync(join(scope, name));
      } catch {
        continue;
      }
      if (seen.has(real)) continue;
      const manifest = join(real, "package.json");
      if (!existsSync(manifest)) continue;
      seen.set(real, JSON.parse(readFileSync(manifest, "utf8")));
      // ⛔⛔ PUSH THE STORE ENTRY, NOT THE PACKAGE. pnpm lays a package's own dependencies out as SIBLINGS
      // inside the same store entry — `.pnpm/<id>/node_modules/@integraledger/<dep>` — never nested under
      // the package directory. Pushing `real` looked like a descent and was a no-op past depth one: the
      // path it then probed, `<real>/node_modules/@integraledger`, does not exist in a pnpm tree at all.
      // Measured on a pnpm-shaped fixture: a transitive protocol package declaring a DIVERGENT viem was
      // never read, and the gate reported the tree clean. It happens that every store name in the current
      // install is reachable at depth one, so the coverage was resting on a coincidence of this install
      // rather than on the walk.
      queue.push(join(real, "..", "..", ".."));
    }
  }
  return [...seen.entries()]
    .filter(([real]) => real.startsWith(STORE))
    .map(([, pkg]) => pkg);
}

const published = readPublishedLine();
if (published.length === 0)
  die(
    "no @integraledger package resolves into the pnpm store from this workspace — the published line is " +
      "absent, so this gate would compare against nothing and say so in green. Run `pnpm install`.",
  );

/** name -> Map(spec -> [declarer]) across the published line. */
const declared = new Map();
for (const pkg of published) {
  for (const [name, spec] of Object.entries(pkg.dependencies ?? {})) {
    if (name.startsWith("@integraledger/")) continue;
    if (!declared.has(name)) declared.set(name, new Map());
    const bySpec = declared.get(name);
    if (!bySpec.has(spec)) bySpec.set(spec, []);
    bySpec.get(spec).push(`${pkg.name}@${pkg.version}`);
  }
}
if (declared.size === 0)
  die(
    "the published line declares no third-party runtime dependency — that has never been true of it",
  );

/* ---------- the three directions ---------- */

const EXACT = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

let compared = 0;
let notDeclaredHere = 0;

for (const [name, bySpec] of [...declared.entries()].sort()) {
  // The published line disagreeing with ITSELF is a split already shipped, and no comparison against this
  // workspace is meaningful until it is resolved.
  if (bySpec.size > 1) {
    const shown = [...bySpec.entries()]
      .map(([s, who]) => `${s} (${who.join(", ")})`)
      .join(" vs ");
    fail.push(
      `${name}: the published line declares it at more than one version — ${shown}. Two copies are ` +
        `already in this tree; the protocol repo has to converge before this workspace can match it.`,
    );
    continue;
  }
  const [spec, declarers] = [...bySpec.entries()][0];

  // Ours, from either place a version can be written.
  const here = [];
  if (catalog.has(name))
    here.push({ spec: catalog.get(name).version, where: "catalog" });
  for (const d of direct.get(name) ?? [])
    here.push({ spec: d.spec, where: `packages/ — ${d.pkg}` });
  if (here.length === 0) {
    notDeclaredHere++;
    continue;
  }

  // ⛔ Equality is defined against an exact version. A range would need a rule about which member of it
  // counts as "equal", and inventing one here would be this gate deciding something the comments did not.
  if (!EXACT.test(spec)) {
    fail.push(
      `${name}: the published line declares the range \`${spec}\` (${declarers.join(", ")}), not an exact ` +
        `version. This gate compares for equality and has no rule for a range — decide what parity means ` +
        `for a range before this can pass.`,
    );
    continue;
  }

  compared++;

  // DIRECTION ONE — the versions must agree.
  for (const mine of here) {
    if (mine.spec !== spec) {
      fail.push(
        `${name}: this workspace pins \`${mine.spec}\` (${mine.where}); the published line it compiles ` +
          `against declares \`${spec}\` (${declarers.join(", ")}). Two copies land in one tree and a type ` +
          `built from one is unassignable to a parameter typed against the other.`,
      );
    }
  }

  // DIRECTION THREE — a shared pin must say that it is shared.
  const doc = catalog.get(name)?.doc ?? "";
  if (!doc.includes(CLAIM_MARKER)) {
    if (catalog.has(name)) {
      fail.push(
        `${name}: the published line declares it (${declarers.join(", ")}), so this pin carries the ` +
          `cross-repo obligation — and its catalog comment does not say so. Direction ONE is checking it ` +
          `and the next reader cannot tell. State the parity, mentioning "${CLAIM_MARKER}".`,
      );
    } else {
      fail.push(
        `${name}: pinned directly in ${here.map((h) => h.where).join(", ")} and also declared by the ` +
          `published line (${declarers.join(", ")}) — a shared dependency outside the catalog, which is ` +
          `the surface a catalog sweep walks past. Move it into \`catalog:\`, where the parity claim has ` +
          `somewhere to live.`,
      );
    }
  }
}

// DIRECTION TWO — a claim the published line cannot witness.
let claimed = 0;
for (const [name, { doc }] of [...catalog.entries()].sort()) {
  if (!doc.includes(CLAIM_MARKER)) continue;
  claimed++;
  if (declared.has(name)) continue;
  fail.push(
    `${name}: its catalog comment claims parity with the protocol repo's catalog, and no package in the ` +
      `published line declares it — so nothing in either repository can witness that claim. It reads as ` +
      `checked and is not. Either the dependency is genuinely shared and the published line should say ` +
      `so, or the comment is describing a local decision and must stop calling it cross-repo parity.`,
  );
}

if (fail.length > 0) {
  console.error("\n✕ shared-pins check failed\n");
  for (const f of fail) console.error(`  • ${f}\n`);
  process.exit(1);
}

console.log(
  `✓ shared pins agree with the published protocol line — ${compared} shared ` +
    `${compared === 1 ? "dependency" : "dependencies"} compared across ${published.length} installed ` +
    `@integraledger packages, ${claimed} parity ${claimed === 1 ? "claim" : "claims"} witnessed, ` +
    `${notDeclaredHere} declared by the published line and not by this workspace`,
);
