#!/usr/bin/env node
/**
 * Reconcile git tags against what is actually published, independently of HOW a release was approved.
 *
 * ⛔⛔ THE DEFECT THIS EXISTS FOR. Tagging used to live only inside `approve-staged.mjs`, so it happened
 * only when a maintainer approved a release by running that script. Approving in the **npm web UI** is
 * the same 2FA proof-of-presence and is a perfectly reasonable thing to do — and it leaves the repository
 * untagged, silently. `0.11.0` went out that way and produced no tags at all. The sibling protocol
 * repository lost **five consecutive releases** (0.12.0 → 0.13.0, 155 tags) to the same cause, which for
 * a long time looked like a bug in the tagging code and was not: the code was simply never reached.
 *
 * ⭐ A step that only runs on one of several legitimate paths is not a step, it is a coincidence. This
 * script derives the answer from the two sources that are true regardless of path — the registry, and
 * each version's own SLSA provenance — so it is correct after a script approval, a web approval, or a
 * publish nobody remembers.
 *
 *   node scripts/reconcile-tags.mjs            report; exit 1 if any published version is untagged
 *   node scripts/reconcile-tags.mjs --write    additionally create and push the missing tags
 *
 * ⚠️ NEEDS NO NPM AUTH. Provenance and the packument are public reads. `--write` needs push rights for
 * tags and nothing else, which is why the workflow that runs it grants `contents: write` on that job
 * alone rather than at the top level.
 *
 * ⚠️ NO FALLBACK TO HEAD, ever. A version whose provenance cannot be read is REPORTED, never guessed at.
 * An untagged release is visibly missing; a mis-tagged one is a wrong answer that reads as a right one.
 */
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { argv, exit } from "node:process";

const WRITE = argv.includes("--write");
const root = new URL("..", import.meta.url).pathname;
const run = (cmd, args) =>
  execFileSync(cmd, args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });

/** Publishable package names, derived from `private` rather than a name pattern. */
function publishable() {
  const names = [];
  for (const dir of readdirSync(`${root}/packages`)) {
    const manifest = `${root}/packages/${dir}/package.json`;
    if (!existsSync(manifest)) continue;
    const pkg = JSON.parse(readFileSync(manifest, "utf8"));
    if (pkg.private !== true && typeof pkg.name === "string")
      names.push(pkg.name);
  }
  return names.sort();
}

async function publishedVersions(name) {
  const res = await fetch(
    `https://registry.npmjs.org/${encodeURIComponent(name)}`,
  );
  if (!res.ok) return null;
  return Object.keys((await res.json()).versions ?? {});
}

/** The commit a published version was built from, per its own SLSA provenance. */
async function provenanceCommit(name, version) {
  const url = `https://registry.npmjs.org/-/npm/v1/attestations/${encodeURIComponent(name)}@${version}`;
  const res = await fetch(url);
  if (!res.ok) return null;
  for (const att of (await res.json()).attestations ?? []) {
    if (!/slsa/i.test(att.predicateType ?? "")) continue;
    const payload = att.bundle?.dsseEnvelope?.payload;
    if (!payload) continue;
    const stmt = JSON.parse(Buffer.from(payload, "base64").toString());
    const deps = stmt.predicate?.buildDefinition?.resolvedDependencies ?? [];
    const sha = deps.find((d) => /git/i.test(d.uri ?? ""))?.digest?.gitCommit;
    if (sha) return sha;
  }
  return null;
}

/** Remote tags mapped to the COMMIT each resolves to. The `^{}` deref line is the commit; comparing tag
 *  OBJECTS instead reports a false mismatch whenever a message or tagger differs. */
function remoteTagCommits() {
  const map = new Map();
  for (const line of run("git", ["ls-remote", "--tags", "origin"]).split(
    "\n",
  )) {
    const [sha, ref] = line.split("\t");
    if (!ref) continue;
    const deref = ref.endsWith("^{}");
    const name = ref.replace(/^refs\/tags\//, "").replace(/\^\{\}$/, "");
    if (deref || !map.has(name)) map.set(name, sha);
  }
  return map;
}

const names = publishable();
const remote = remoteTagCommits();
const missing = [];
const unresolvable = [];
let checked = 0;

for (const name of names) {
  const versions = await publishedVersions(name);
  if (versions === null) {
    // Never published at all is not a defect — a package can exist in the tree before its first release.
    console.log(`  ${name}: not on the registry yet`);
    continue;
  }
  for (const version of versions) {
    checked++;
    const tag = `${name}@${version}`;
    if (remote.has(tag)) continue;
    const sha = await provenanceCommit(name, version);
    if (sha === null) {
      unresolvable.push(
        `${tag} — published, untagged, and its provenance is unreadable`,
      );
      continue;
    }
    missing.push({ tag, sha });
  }
}

console.log(
  `reconcile-tags — ${names.length} publishable package(s), ${checked} published version(s), ` +
    `${missing.length + unresolvable.length} untagged.`,
);

if (missing.length === 0 && unresolvable.length === 0) exit(0);

for (const m of missing)
  console.log(`  UNTAGGED ${m.tag} -> ${m.sha.slice(0, 8)}`);
for (const u of unresolvable) console.log(`  UNTAGGED ${u}`);

if (!WRITE) {
  console.error(
    "\n⛔ Published versions with no tag. This happens when a release is approved outside\n" +
      "`approve-staged.mjs` — the npm web UI, for instance — which never reaches its tagging step.\n" +
      "Re-run with `--write`, or dispatch the `tags` workflow, to write them from provenance.\n",
  );
  exit(1);
}

const wrote = [];
for (const { tag, sha } of missing) {
  try {
    run("git", ["cat-file", "-e", `${sha}^{commit}`]);
  } catch {
    unresolvable.push(
      `${tag} — provenance names ${sha.slice(0, 8)}, absent from this clone`,
    );
    continue;
  }
  // ⛔ MISSING FROM THE REMOTE DOES NOT MEAN MISSING LOCALLY, and the two diverge for ordinary reasons:
  // a push that failed after the tag was written, a tag deleted from the remote, a clone that has tags an
  // earlier run created. `git tag -a` on an existing name throws, and letting that escape would abort the
  // whole reconciliation over a tag that is merely un-pushed. Found by deleting one remote tag and
  // watching this script die on the local copy that remained.
  let local = null;
  try {
    local = run("git", ["rev-list", "-n", "1", `refs/tags/${tag}`]).trim();
  } catch {
    // no local tag — the ordinary case
  }
  if (local !== null && local !== sha) {
    unresolvable.push(
      `${tag} — local tag is at ${local.slice(0, 8)}, provenance says ${sha.slice(0, 8)}; left alone`,
    );
    continue;
  }
  if (local === null)
    run("git", [
      "tag",
      "-a",
      tag,
      sha,
      "-m",
      tag,
      "-m",
      `Published from ${sha.slice(0, 8)}. Commit taken from this version's own SLSA provenance on the\n` +
        "registry, not from HEAD. Written by reconcile-tags, which does not depend on how the release\n" +
        "was approved.",
    ]);
  wrote.push(tag);
}
if (wrote.length > 0) {
  try {
    run("git", ["push", "origin", ...wrote.map((t) => `refs/tags/${t}`)]);
  } catch (cause) {
    // Reported, not thrown: the versions are already published, so the list of what is untagged is worth
    // more to an operator than a stack trace.
    unresolvable.push(
      `push failed for ${wrote.length} tag(s): ${
        String(cause.stderr ?? cause.message)
          .trim()
          .split("\n")[0]
      }`,
    );
  }
}

// The remote is the only witness: `push` exiting 0 means the transport worked, not that refs landed.
const after = remoteTagCommits();
const stillMissing = missing.filter(({ tag, sha }) => after.get(tag) !== sha);
console.log(
  `\nwrote and confirmed ${missing.length - stillMissing.length} of ${missing.length} tag(s).`,
);
if (stillMissing.length > 0 || unresolvable.length > 0) {
  console.error(
    "\n⛔ still untagged:\n" +
      [
        ...stillMissing.map((m) => `  - ${m.tag}`),
        ...unresolvable.map((u) => `  - ${u}`),
      ].join("\n") +
      "\n",
  );
  exit(1);
}
