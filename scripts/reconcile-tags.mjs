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
 *
 * ⛔⛔ A PACKAGE NAME OUTLIVES THE REPOSITORY IT WAS PUBLISHED FROM, and reading provenance as a commit
 * alone cannot see that. `@integraledger/lcp-mcp-server` 0.9.0 → 0.12.1 were built somewhere this line no
 * longer lives, before it moved here at 0.13.0. Those six commits are not reachable from this
 * `origin/main` and never will be, so every run reported six permanently untagged versions and exited 1 —
 * a gate that is always red carries no information, and a real untagged release would have arrived in
 * exactly the same colour.
 *
 * ⭐ SO THE CLASSIFIER READS THE REPOSITORY, NOT ONLY THE COMMIT. Provenance names both, in the same
 * `resolvedDependencies` entry; a bare SHA cannot say which history it belongs to. A version built
 * outside this repository is not this repository's tag to write, and saying so is the whole fix.
 *
 * ⛔⛔ IT MUST STAY A PURE REGISTRY READ. The obvious stronger check — confirm the tag really exists on
 * the repository the provenance names — was written, passed locally, and would have failed in CI: that
 * remote answers 401 anonymously, and the workflow's `GITHUB_TOKEN` is scoped to THIS repository, so the
 * job would have gone red on authentication while reporting it as an untagged release. Measured, not
 * assumed. What is pinned below instead is each pre-move version's provenance commit, which every
 * consumer can read without any credential at all.
 *
 * ⚠️ NOT A SILENT EXEMPTION. A pre-move version passes only when the provenance commit still matches the
 * pin; a version built anywhere but here that is NOT pinned fails loudly; and a pin the registry no
 * longer serves fails too, so the table cannot outlive what it describes.
 */
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import { resolve } from "node:path";
import { argv, exit } from "node:process";
import { fileURLToPath } from "node:url";

const WRITE = argv.includes("--write");
// `.pathname` keeps percent-encoding, so a clone under a path with a space fails at `readdirSync`.
const root = fileURLToPath(new URL("..", import.meta.url));
const run = (cmd, args) =>
  execFileSync(cmd, args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });

/**
 * Versions of this line that were built BEFORE it moved to this repository, pinned to the commit each
 * one's own SLSA provenance names. Every value here is a public registry read — the attestation endpoint
 * needs no credential — so the pin can be re-derived by anyone, including from a fork.
 *
 * An entry is a claim that this repository is not the one that should carry the version's tag. It is
 * checked, never trusted: the provenance commit must still equal the pin, and the registry must still
 * serve the version. Delete an entry when either stops being true rather than leaving it as decoration.
 */
export const BUILT_BEFORE_THE_MOVE = Object.freeze({
  "@integraledger/lcp-mcp-server@0.9.0":
    "2a58b806c6bcef61910558ea5ce8c451b94f82db",
  "@integraledger/lcp-mcp-server@0.10.0":
    "0bb54d1d3bacecd2254f17bcbc911fba7972c6b1",
  "@integraledger/lcp-mcp-server@0.10.1":
    "30bfe69e82ad1aa8317caa58f6dd2d8bd01f2055",
  "@integraledger/lcp-mcp-server@0.11.0":
    "466d1750bfe8fb50d06ac2753614f05fea591021",
  "@integraledger/lcp-mcp-server@0.12.0":
    "93248318f75069fd5bb11516ef2633044ebd6026",
  "@integraledger/lcp-mcp-server@0.12.1":
    "6917a3dc1c92c642cde5bbef2241e135fbf785e5",
});

/**
 * `owner/name` out of any GitHub URL this tree encounters — an npm `repository.url`
 * (`git+https://github.com/O/R.git`) or a provenance dependency URI
 * (`git+https://github.com/O/R@refs/heads/main`). Null for anything else, which the caller treats as
 * unclassifiable rather than as a match.
 *
 * ⛔ THE HOST IS CHECKED, NOT SEARCHED FOR. This was `url.indexOf("github.com/")`, a substring test that
 * accepted `https://mygithub.com/owner/repo` and `https://evil-github.com/O/R` and returned a slug for
 * them — a wrong answer where the whole point is to refuse. Parsing properly also drops query strings,
 * fragments and stray whitespace, each of which the hand-rolled version carried into the slug.
 */
export function parseRepositorySlug(url) {
  if (typeof url !== "string") return null;
  let parsed;
  try {
    // npm and provenance both prefix the transport: `git+https://…`, `git+ssh://…`.
    parsed = new URL(url.trim().replace(/^git\+/, ""));
  } catch {
    return null;
  }
  if (parsed.host !== "github.com" && parsed.host !== "www.github.com")
    return null;
  // The ref suffix comes AFTER the repository name; `git@github.com` is a username the URL parser has
  // already taken off, so cutting at `@` here can only be the ref.
  const segments = parsed.pathname
    .split("@")[0]
    .replace(/\.git$/, "")
    .split("/")
    .filter((segment) => segment !== "");
  if (segments.length !== 2) return null;
  return `${segments[0]}/${segments[1]}`;
}

/**
 * GitHub owners and repository names are case-insensitive, and the comparison this gate turns on is an
 * equality test — a manifest written `integraledger/…` against provenance minted `IntegraLedger/…` would
 * classify every version of this repository as foreign and reproduce the always-red condition exactly.
 */
export function sameRepository(a, b) {
  return (
    typeof a === "string" &&
    typeof b === "string" &&
    a.toLowerCase() === b.toLowerCase()
  );
}

/** Publishable package manifests, derived from `private` rather than a name pattern. */
function publishableManifests() {
  const manifests = [];
  for (const dir of readdirSync(`${root}/packages`)) {
    const path = `${root}/packages/${dir}/package.json`;
    if (!existsSync(path)) continue;
    const pkg = JSON.parse(readFileSync(path, "utf8"));
    if (pkg.private !== true && typeof pkg.name === "string")
      manifests.push(pkg);
  }
  return manifests.sort((a, b) => a.name.localeCompare(b.name));
}

/**
 * Which repository THIS tree is, taken from `repository.url` because that is the same field the registry
 * publishes, so it is directly comparable to what provenance names. (It is NOT a defence against a clone
 * pointed elsewhere — `remoteTagCommits` reads `origin` and `--write` pushes to `origin`, so such a clone
 * is already wrong in ways this cannot see.) Disagreement between packages is a defect in its own right,
 * so it throws rather than picking one.
 */
export function repositoryIdentity(manifests) {
  const slugs = new Set();
  for (const pkg of manifests) {
    const slug = parseRepositorySlug(pkg.repository?.url);
    if (slug === null)
      throw new Error(
        `${pkg.name} declares no usable \`repository.url\` — this script cannot tell which repository a version was published from without one.`,
      );
    slugs.add(slug);
  }
  if (slugs.size === 0)
    throw new Error(
      "no publishable packages — reconciling tags over an empty set would report a green over nothing.",
    );
  if (slugs.size > 1)
    throw new Error(
      `publishable packages disagree about their repository: ${[...slugs].sort().join(", ")}`,
    );
  return [...slugs][0];
}

async function publishedVersions(name) {
  const res = await fetch(
    `https://registry.npmjs.org/${encodeURIComponent(name)}`,
  );
  // ⛔⛔ ONLY 404 MEANS "NEVER PUBLISHED". Collapsing every non-200 into that made a 429 or a 5xx look
  // like an unpublished package, and the pin-staleness check below then read the silence as proof the
  // pins were stale — a red daily job whose stated remedy was to DELETE six correct entries. A registry
  // that cannot answer is a reason to stop, not a fact about the registry's contents.
  if (res.status === 404) return null;
  if (!res.ok)
    throw new Error(
      `the registry answered ${res.status} for ${name}; nothing can be concluded about what is published, so this run stops rather than guessing.`,
    );
  return Object.keys((await res.json()).versions ?? {});
}

/**
 * The commit AND the repository a published version was built from, per its own SLSA provenance. The
 * two come from the same `resolvedDependencies` entry, so the commit is read in the only context that
 * makes it meaningful — a bare SHA cannot say which history it belongs to.
 */
async function provenanceOrigin(name, version) {
  const url = `https://registry.npmjs.org/-/npm/v1/attestations/${encodeURIComponent(name)}@${version}`;
  const res = await fetch(url);
  if (!res.ok) return null;
  for (const att of (await res.json()).attestations ?? []) {
    if (!/slsa/i.test(att.predicateType ?? "")) continue;
    const payload = att.bundle?.dsseEnvelope?.payload;
    if (!payload) continue;
    const stmt = JSON.parse(Buffer.from(payload, "base64").toString());
    const deps = stmt.predicate?.buildDefinition?.resolvedDependencies ?? [];
    const dep = deps.find((d) => /git/i.test(d.uri ?? ""));
    const sha = dep?.digest?.gitCommit;
    if (sha) return { sha, repository: parseRepositorySlug(dep.uri) };
  }
  return null;
}

/**
 * What to do with ONE published version whose tag is absent from this repository — the whole decision the
 * daily job turns on, kept pure so it can be driven without a registry or a git remote.
 *
 * Returns `{ kind: "tag-here" }` when this repository owes the tag, `{ kind: "pre-move" }` when the
 * version was built before the line moved here and its provenance commit still matches the pin, and
 * `{ kind: "refuse", reason }` otherwise. There is no fourth answer and no silent pass.
 */
export function classifyVersion({ tag, sha, repository, self }) {
  if (sameRepository(repository, self)) return { kind: "tag-here", tag, sha };
  const built = repository ?? "a repository this script cannot parse";
  const pinned = Object.hasOwn(BUILT_BEFORE_THE_MOVE, tag)
    ? BUILT_BEFORE_THE_MOVE[tag]
    : undefined;
  if (pinned === undefined)
    return {
      kind: "refuse",
      reason: `${tag} — built in ${built}, not ${self}, and not declared as predating the move`,
    };
  if (pinned !== sha)
    // ⛔ FULL SHAs, not the abbreviations used everywhere else. Found by flipping a pin's LAST character:
    // the refusal fired correctly and read `declared at 2a58b806, provenance says 2a58b806`, which tells
    // an operator that something differs and nothing about what.
    return {
      kind: "refuse",
      reason: `${tag} — declared at ${pinned}, provenance says ${sha} in ${built}`,
    };
  return {
    kind: "pre-move",
    note: `${tag} — built in ${built} at ${sha.slice(0, 8)}, before the move`,
  };
}

/**
 * Pins the registry no longer serves. ⛔ A DECLARATION THAT MATCHES NOTHING IS THE SUBJECT SET EMPTYING:
 * once a pinned version stops being published the entry exempts nothing, and an entry that exempts
 * nothing hides the next mistake.
 */
export function staleDeclarations(published) {
  return Object.keys(BUILT_BEFORE_THE_MOVE)
    .filter((tag) => !published.has(tag))
    .map(
      (tag) =>
        `${tag} is declared as predating the move but the registry does not serve it — delete the entry`,
    );
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

async function main() {
  const manifests = publishableManifests();
  const self = repositoryIdentity(manifests);
  const remote = remoteTagCommits();
  const published = new Set();
  const missing = [];
  const unresolvable = [];
  const elsewhere = [];
  let checked = 0;

  for (const { name } of manifests) {
    const versions = await publishedVersions(name);
    if (versions === null) {
      // Never published at all is not a defect — a package can exist in the tree before its first release.
      console.log(`  ${name}: not on the registry yet`);
      continue;
    }
    for (const version of versions) {
      checked++;
      const tag = `${name}@${version}`;
      published.add(tag);
      if (remote.has(tag)) continue;
      const origin = await provenanceOrigin(name, version);
      if (origin === null) {
        unresolvable.push(
          `${tag} — published, untagged, and its provenance is unreadable`,
        );
        continue;
      }
      const { sha, repository } = origin;
      const decided = classifyVersion({ tag, sha, repository, self });
      if (decided.kind === "tag-here") missing.push({ tag, sha });
      else if (decided.kind === "pre-move") elsewhere.push(decided.note);
      else unresolvable.push(decided.reason);
    }
  }

  unresolvable.push(...staleDeclarations(published));

  console.log(
    `reconcile-tags — ${manifests.length} publishable package(s) in ${self}, ${checked} published version(s), ` +
      `${missing.length + unresolvable.length} untagged, ${elsewhere.length} built before the move.`,
  );

  for (const e of elsewhere) console.log(`  PRE-MOVE ${e}`);
  if (missing.length === 0 && unresolvable.length === 0) exit(0);

  for (const m of missing)
    console.log(`  UNTAGGED ${m.tag} -> ${m.sha.slice(0, 8)}`);
  for (const u of unresolvable) console.log(`  UNTAGGED ${u}`);

  if (!WRITE) {
    // ⛔ THE ADVICE IS SPLIT BECAUSE THE CAUSES ARE. `--write` can only close the first list; telling an
    // operator to re-run with it over a mismatched pin or a stale declaration contradicts the very lines
    // printed above, which ask them to edit the table instead.
    console.error(
      missing.length > 0
        ? "\n⛔ Published versions this repository owes a tag. This happens when a release is approved\n" +
            "outside `approve-staged.mjs` — the npm web UI, for instance — which never reaches its tagging\n" +
            "step. Re-run with `--write`, or dispatch the `tags` workflow, to write them from provenance.\n"
        : "\n⛔ Nothing here is a missing tag `--write` can create — read each line above and fix what it\n" +
            "names: a version built elsewhere that no pin covers, a pin that no longer matches provenance,\n" +
            "or a declaration the registry no longer serves.\n",
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
}

// Importable for its drive; the reconciliation itself runs only when this file IS the entry point.
// ⛔ BOTH SIDES REALPATHED. `import.meta.filename` is already resolved through symlinks and `argv[1]` is
// not, so comparing `resolve(argv[1])` to it made the whole script a silent no-op — exit 0, no output,
// nothing reconciled — for anyone whose checkout is reached through a symlinked directory. The CI path
// has no symlink component, so this would have stayed invisible there and misfired on a laptop.
if (
  argv[1] !== undefined &&
  realpathSync(resolve(argv[1])) === import.meta.filename
)
  await main();
