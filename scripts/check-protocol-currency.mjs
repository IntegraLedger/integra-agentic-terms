#!/usr/bin/env node
/**
 * Compare the protocol line this repository DECLARES against the line npmjs actually serves, and refuse
 * when the declaration cannot admit what a consumer installing today resolves.
 *
 * ⛔⛔ THE DEFECT, WHICH HAS NOW LANDED THREE TIMES. `agentic-terms` peers `@integraledger/lcp-*` at
 * `^X.Y.0`, and on a `0.x` version a caret is MINOR-LOCKED — `^0.16.0` excludes `0.17.0` outright. When the
 * protocol released a new minor, a consumer holding this package and the new protocol together got **no
 * error**: pnpm resolved a SECOND protocol line beside the first, thirteen packages deep, every one of them
 * reachable. Two copies of `lcp-binding-core` break `instanceof CarrierError`, and nothing in that
 * consumer's own build says so. The same shape shipped at 0.14.0 → 0.15.0, at 0.15.0 → 0.16.0 and again at
 * 0.16.0 → 0.17.0; each time it surfaced only when a downstream repository's wire gate refused an install,
 * which is far too late. A defect that recurs on every repin is not a slip, it is a missing gate.
 *
 * ⭐ WHY `check:wire` CANNOT CLOSE IT, AND WHY THIS IS NOT A SECOND COPY OF IT. `check:wire` is a
 * COHERENCE gate: it holds the peer range, the exercised dev pin, the shipped runtime caret and the
 * published install docs equal to one another. Every one of those rules passed on the day the defect
 * shipped, because the repository was internally consistent — on a line the protocol had already moved
 * past. Nothing in this tree knows what the protocol published; that fact lives on the registry. This gate
 * asks the one question no file here can answer, and asks nothing `check:wire` already asks.
 *
 * ⚠️ WHAT `protocol-latest.yml` ALREADY DOES, STATED HONESTLY SO NOBODY BUILDS THIS TWICE. That workflow
 * moves the dev pins to `latest` and runs the whole of `verify`, so `check:wire`'s peer rule DOES go red
 * once the published line passes the declared caret. It is not nothing, and this gate does not replace it.
 * Three things separate them, each measured:
 *
 *   LATENCY.      `protocol-latest` samples once per weekday at 06:17 UTC. `@integraledger/lcp-kernel`
 *                 0.17.0 was published 2026-09-10T16:01Z; that day's run had already gone green at 06:40Z,
 *                 so the earliest it could have spoken was ~14 hours later — and for a Friday-evening
 *                 publish, ~62. The whole window is one in which consumers install.
 *   ATTRIBUTION.  Its red arrives as `verify` failing, over a job that also runs `audit` — non-hermetic by
 *                 its own docblock — plus build, lint, typecheck and every test. "The caret range does not
 *                 hold against latest" is a conclusion a reader has to reconstruct. This gate makes one
 *                 comparison and names both versions.
 *   SILENCE.      Its whole signal depends on `pnpm up --dev` having actually moved something, and `pnpm
 *                 up` exits 0 when it moves nothing. A glob that stopped matching, or a registry that
 *                 answered badly, leaves that job green having verified the tree against its own lockfile.
 *                 Here an unreachable registry is a refusal with its own message, never a green.
 *
 * ⛔ NOT IN `pnpm verify`, AND THAT IS THE POINT. `verify` is this repository's offline definition of
 * "does this tree pass". A network read inside it would turn every protocol release — an event in another
 * repository, on someone else's schedule — into a red build for whoever happened to be editing a README.
 * The drive beside this file IS in `verify` (via `test:scripts`) because it is hermetic; the check itself
 * runs on the schedule in `.github/workflows/protocol-currency.yml`, which files an issue rather than
 * failing a branch. Nothing in this repository changed; the world did.
 *
 * ⛔ THE PACKUMENT, NOT `-/package/<pkg>/dist-tags`, AND THE REASON IS A MEASUREMENT. The dist-tags
 * endpoint is nineteen bytes and looks like the obvious choice. Measured 2026-09-10 against a scoped name
 * that does not exist, it answers **401 Unauthorized** — a package that was never published and a
 * credential problem arrive in the same status, and this gate would have to guess which. The abbreviated
 * packument (`Accept: application/vnd.npm.install-v1+json`) answers a clean **404**, carries `dist-tags`,
 * and costs 11.7 KB against the full document's 45.6 KB. `reconcile-tags.mjs` already reads the packument
 * and already carries the lesson that ONLY 404 means "never published"; there is now one story about that
 * in this repository rather than two.
 *
 * ⛔ THE SUBJECT IS THE LINE, NEVER THE PATCH — and refusing on a patch would CONTRADICT `check:wire`.
 * That gate requires every protocol range to be `^X.Y.0` and refuses a raised floor outright, because on a
 * `0.x` line the patch is the only part of a caret that moves and raising it strands consumers on earlier
 * patches of the same line. So a gate that went red because npmjs serves `0.17.3` against a declared
 * `^0.17.0` would be demanding a change its sibling refuses to accept. A patch delta is REPORTED here and
 * exits 0; only a line the declaration cannot admit is a refusal.
 *
 * ⭐ THE SUBJECT SET IS DERIVED, NEVER LISTED. Every name comes from `declaredProtocolDeps`, which reads
 * the manifests — so a protocol package added to the tree is checked the day it is added, and the root's
 * `@integraledger/lcp-conformance`, which sits in no package's list and is the pin the last repin walked
 * past, is in the set for the same reason as the rest. An EMPTY subject set is a refusal, not a pass: a
 * gate that read no manifests reports exactly the green of one that read all of them.
 *
 *     node scripts/check-protocol-currency.mjs
 */
import { realpathSync } from "node:fs";
import { resolve } from "node:path";
import { argv, exit } from "node:process";
import { fileURLToPath } from "node:url";
import {
  declaredProtocolDeps,
  isExact,
  readManifests,
  satisfies,
  workspaceNames,
} from "./protocol-deps.mjs";

/** The public registry these packages are published to, and the one `reconcile-tags.mjs` reads. */
export const REGISTRY_ORIGIN = "https://registry.npmjs.org";

/**
 * A version this gate can reason about: `X.Y.Z` and nothing else. `satisfies` parses exactly this shape,
 * so admitting a prerelease or a build suffix here would hand it a string whose precedence it does not
 * implement and take the `false` as a drift finding.
 */
const RELEASE = /^\d+\.\d+\.\d+$/;

/** A declaration this gate can derive a line from: an exact release, or a caret/tilde over one. */
const DECLARABLE = /^[\^~]?\d+\.\d+\.\d+$/;

/**
 * THE PORT. A `RegistryPort` is `(name) => Promise<RegistryAnswer>`, and a `RegistryAnswer` is exactly one
 * of three things:
 *
 *   `{ kind: "packument", body }`    the bytes the registry served, UNPARSED
 *   `{ kind: "absent" }`             a 404, and only ever a 404
 *   `{ kind: "unreachable", detail }` anything else at all — a 5xx, a 429, a 401, DNS, a timeout
 *
 * ⭐ THE PORT RETURNS BYTES AND NEVER PARSES THEM. That is what keeps malformed-response handling inside
 * the pure decision below, where the drive can exercise it with a real implementation of this same
 * interface instead of a network. A port that returned a parsed object would have to decide what a
 * truncated body means, and that decision would then exist only on the path no test can reach.
 *
 * ⛔ AND ONLY A 404 EVER BECOMES "absent". `reconcile-tags.mjs` records what the alternative costs: a 429 or
 * a 5xx read as "never published", and the caller then treated the silence as evidence about the
 * registry's CONTENTS. A registry that cannot answer is a reason to stop, not a fact.
 *
 * @typedef {{ kind: "packument", body: string }
 *         | { kind: "absent" }
 *         | { kind: "unreachable", detail: string }} RegistryAnswer
 * @typedef {(name: string) => Promise<RegistryAnswer>} RegistryPort
 */

/**
 * A transport failure described by its whole cause chain, not by its outermost message.
 *
 * ⛔ `fetch` REPORTS EVERY NETWORK FAILURE AS `TypeError: fetch failed`. Measured 2026-09-10 by pointing
 * the real port at a host that does not resolve: eleven packages, eleven lines reading "fetch failed", and
 * nothing to say whether that was DNS, TLS, a refused connection or a proxy. This job's output is an issue
 * body somebody has to triage, and `cause.cause` is where undici puts the answer — `getaddrinfo
 * ENOTFOUND`, `ECONNREFUSED`, `unable to verify the first certificate`. Walking the chain is the whole
 * difference between a report and a shrug.
 */
export function describeFailure(error) {
  const seen = [];
  for (let e = error, depth = 0; e != null && depth < 8; e = e.cause, depth++) {
    const message = typeof e === "string" ? e : e.message;
    if (
      typeof message === "string" &&
      message !== "" &&
      !seen.includes(message)
    )
      seen.push(message);
  }
  return seen.length > 0 ? seen.join(": ") : String(error);
}

/**
 * The REAL implementation of `RegistryPort`: an HTTPS read of the abbreviated packument.
 *
 * ⚠️ The timeout is not decoration. Without one a hung connection leaves the scheduled job sitting until
 * the runner's own limit, which reads as a stuck job rather than as the unreachable registry it is.
 *
 * @param {{ origin?: string, timeoutMs?: number }} [options]
 * @returns {RegistryPort}
 */
export function NetworkRegistry({
  origin = REGISTRY_ORIGIN,
  timeoutMs = 15_000,
} = {}) {
  return async (name) => {
    let res;
    try {
      res = await fetch(`${origin}/${encodeURIComponent(name)}`, {
        headers: { accept: "application/vnd.npm.install-v1+json" },
        // A redirect off npmjs is not something to follow silently while asking what npmjs publishes.
        redirect: "error",
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (cause) {
      return { kind: "unreachable", detail: describeFailure(cause) };
    }
    if (res.status === 404) return { kind: "absent" };
    if (!res.ok) return { kind: "unreachable", detail: `HTTP ${res.status}` };
    try {
      return { kind: "packument", body: await res.text() };
    } catch (cause) {
      // A body that dies mid-stream is a transport failure, not a malformed document.
      return { kind: "unreachable", detail: describeFailure(cause) };
    }
  };
}

/** `"0.17.3"` → `{ major: 0, minor: 17 }`. The unit this gate compares; the patch is deliberately dropped. */
function lineOf(version) {
  const [major, minor] = version.split(".").map(Number);
  return { major, minor };
}

/** `-1` when `a` is an earlier line than `b`, `1` when later, `0` when the same line. */
function compareLines(a, b) {
  if (a.major !== b.major) return a.major < b.major ? -1 : 1;
  if (a.minor !== b.minor) return a.minor < b.minor ? -1 : 1;
  return 0;
}

/** How a declaration reads, spelled out so the refusal says WHY it cannot admit the published version. */
function rangeShape(spec) {
  if (spec.startsWith("^"))
    return spec.startsWith("^0.")
      ? "a caret on a `0.x` version pins the MINOR, not the major"
      : "a caret pins the major";
  if (spec.startsWith("~")) return "a tilde pins the minor";
  return "an exact pin admits only itself";
}

/**
 * `dist-tags.latest` out of a packument body, or a description of what made it unusable.
 *
 * ⛔ FOUR SEPARATE WAYS TO BE UNREADABLE, AND EACH SAYS WHICH. Collapsing them into one "bad response"
 * would leave an operator unable to tell a truncated body from a package that publishes only prereleases —
 * two completely different things to do about it.
 */
function latestFrom(body) {
  let doc;
  try {
    doc = JSON.parse(body);
  } catch (cause) {
    return { bad: `the body is not JSON (${cause.message})` };
  }
  const tags = doc?.["dist-tags"];
  if (tags === null || typeof tags !== "object")
    return { bad: "it carries no `dist-tags` object" };
  const latest = tags.latest;
  if (typeof latest !== "string")
    return {
      bad: `\`dist-tags.latest\` is ${JSON.stringify(latest)}, not a string`,
    };
  if (!RELEASE.test(latest))
    return {
      bad: `\`dist-tags.latest\` is "${latest}", not an \`X.Y.Z\` release version — this gate compares release lines and will not guess at prerelease precedence`,
    };
  return { latest };
}

/**
 * Every declared protocol spec, grouped by package and then by the spec string, so one wrong line yields
 * one refusal naming every site rather than nine that repeat themselves.
 *
 * @returns {Map<string, Map<string, string[]>>} dep → spec → ["where → field", …]
 */
export function declarationsByPackage(manifests, workspace) {
  const byDep = new Map();
  for (const { where, field, dep, spec } of declaredProtocolDeps(
    manifests,
    workspace,
  )) {
    if (!byDep.has(dep)) byDep.set(dep, new Map());
    const bySpec = byDep.get(dep);
    if (!bySpec.has(spec)) bySpec.set(spec, []);
    bySpec.get(spec).push(`${where} → ${field}`);
  }
  return byDep;
}

/** A line as `"0.17"` — the key drift is grouped under, so one repin's worth of drift is ONE finding. */
const lineKey = ({ major, minor }) => `${major}.${minor}`;

/**
 * How many DECLARATIONS a group covers, which is the number of manifest sites and not the number of rows.
 * ⛔ Written as `entries.length` first, and the drive caught it: one package declaring `^0.16.0` as both a
 * peer and a shipped dependency and `0.16.0` as the dev pin is THREE declarations printed on two rows, and
 * the finding claimed two. A count beside an evidence list is there to prove the list is complete; one
 * that counts the wrong thing invites a reader to believe a site was missed.
 */
const countSites = (entries) => entries.reduce((n, e) => n + e.sites.length, 0);

/**
 * The evidence rows under a grouped finding: the package, what it declares, what npmjs serves, and where.
 * Sorted by package so two runs over the same tree produce the same bytes.
 */
function evidence(entries) {
  const width = Math.max(...entries.map((e) => e.dep.length));
  const specWidth = Math.max(...entries.map((e) => e.spec.length + 2));
  return entries
    .slice()
    .sort((a, b) => a.dep.localeCompare(b.dep) || a.spec.localeCompare(b.spec))
    .map(
      (e) =>
        `      ${e.dep.padEnd(width)}  ${`"${e.spec}"`.padEnd(specWidth)}  vs npmjs ${e.latest}   ${e.sites.join(", ")}`,
    )
    .join("\n");
}

/**
 * ⛔⛔ DRIFT IS GROUPED BY LINE, NEVER REPEATED PER DECLARATION. Measured on the plant that reproduces the
 * 0.16.0 → 0.17.0 defect exactly: ungrouped, ONE fact — the whole tree sits a minor behind — printed as
 * TWENTY near-identical paragraphs, one per declaration, each restating the `instanceof CarrierError`
 * consequence in full. This job's output is an issue body, and an issue body nobody reads to the bottom of
 * is the same as no issue. The finding is "this tree declares the 0.16 line and npmjs serves 0.17"; the
 * packages and specs are its evidence and belong in a list beneath it.
 *
 * ⭐ The "why it cannot admit" sentence is DERIVED from the shapes actually present, not written here. A
 * group of exact dev pins and a group of carets fail for different reasons, and a fixed sentence would be
 * wrong for one of them.
 */
function renderBehind({ declared, published, entries }) {
  const shapes = [...new Set(entries.map((e) => rangeShape(e.spec)))];
  return (
    `BEHIND THE PUBLISHED LINE — this tree declares the ${lineKey(declared)} line; npmjs serves ` +
    `${lineKey(published)} under \`latest\`.\n` +
    `    ${new Set(entries.map((e) => e.dep)).size} package(s), ${countSites(entries)} declaration(s):\n` +
    `${evidence(entries)}\n` +
    `    Not one of those can admit what the registry serves — ${shapes.join("; ")}.\n` +
    `    ⛔ A consumer that installs this package alongside the ${lineKey(published)} protocol gets NO\n` +
    "    error. pnpm resolves a SECOND copy of the protocol line beside this one, thirteen packages deep,\n" +
    "    and two copies of `lcp-binding-core` break `instanceof CarrierError`. Repin the line with a\n" +
    "    changeset — `check:wire` will refuse every wrong shape on the way through."
  );
}

/**
 * The mirror case, and NOT a symmetric one: nothing in this repository is stale. `npm publish` moves the
 * `latest` dist-tag to whatever was just published unless `--tag` says otherwise, so a hotfix cut on an
 * older line drags `latest` backwards — and then the install instructions this repository publishes name a
 * range that a consumer resolving `latest` cannot satisfy. That is a live consumer-facing break, which is
 * why it is a refusal and not a note.
 */
function renderAhead({ declared, published, entries }) {
  return (
    `AHEAD OF THE PUBLISHED LINE — this tree declares the ${lineKey(declared)} line, but npmjs serves the\n` +
    `    EARLIER ${lineKey(published)} line under \`latest\`.\n` +
    `    ${new Set(entries.map((e) => e.dep)).size} package(s), ${countSites(entries)} declaration(s):\n` +
    `${evidence(entries)}\n` +
    "    This is not staleness here. Either an older line was published without `--tag`, or the `latest`\n" +
    "    dist-tag was moved back. Either way a consumer installing these packages today resolves a version\n" +
    "    this repository's declared range refuses, so the install its documents advertise does not work."
  );
}

/**
 * The whole decision, pure but for the injected port: what this tree declares, against what npmjs serves.
 *
 * Returns `{ refusals, notes, checked }`. `refusals` non-empty means exit 1 — there is no other outcome
 * that exits 1, and no refusal that is silently downgraded to a note.
 *
 * @param {{ manifests: object[], workspace: Set<string>, registry: RegistryPort }} input
 */
export async function currencyReport({ manifests, workspace, registry }) {
  const refusals = [];
  const notes = [];
  const byDep = declarationsByPackage(manifests, workspace);

  if (byDep.size === 0) {
    refusals.push(
      "the tree declares no `@integraledger/lcp-*` dependency at all, so this gate compared nothing\n" +
        "    against the registry. An empty subject set is a REFUSAL here, never a pass: a run that read no\n" +
        "    manifests reports exactly the green of one that read all of them, and the manifests are the only\n" +
        "    place the declared line lives.",
    );
    return { refusals, notes, checked: 0 };
  }

  /** One outage is ONE finding, for the same reason one repin's drift is. */
  const unreachable = [];
  const behind = new Map();
  const ahead = new Map();

  let checked = 0;
  for (const dep of [...byDep.keys()].sort()) {
    const bySpec = byDep.get(dep);
    const answer = await registry(dep);

    if (answer.kind === "unreachable") {
      unreachable.push(`      ${dep} — ${answer.detail}`);
      continue;
    }
    if (answer.kind === "absent") {
      refusals.push(
        `${dep} — THE REGISTRY ANSWERS 404: this tree declares a dependency on a package npmjs does not\n` +
          `    serve (declared at ${[...bySpec.values()].flat().join(", ")}).\n` +
          '    This is not "no newer version"; it is no version at all, and a consumer\'s install of it\n' +
          "    cannot succeed. Either the name is wrong here or the package was never published.",
      );
      continue;
    }

    const read = latestFrom(answer.body);
    if (read.bad !== undefined) {
      refusals.push(
        `${dep} — THE REGISTRY ANSWERED 200 BUT ${read.bad}.\n` +
          "    A response this gate cannot read is a refusal, not a pass: reading `latest` out of it would\n" +
          "    compare the declared line against `undefined` and find no drift.",
      );
      continue;
    }

    const { latest } = read;
    const published = lineOf(latest);
    checked++;

    for (const [spec, sites] of bySpec) {
      if (!DECLARABLE.test(spec)) {
        refusals.push(
          `${dep} — ${sites.join(", ")} declares "${spec}", which is neither an exact \`X.Y.Z\` nor a\n` +
            "    `^`/`~` range over one. This gate cannot derive a line from that string, so it refuses\n" +
            "    rather than waving the declaration through unchecked.",
        );
        continue;
      }
      if (satisfies(spec, latest)) continue;

      const declared = lineOf(spec.replace(/^[\^~]/, ""));
      const direction = compareLines(declared, published);

      if (direction === 0) {
        // Same line, and the spec still does not admit it. For the exercised exact pin that is ordinary
        // patch drift and `protocol-latest` is what moves it; for a RANGE it is a floor above what npmjs
        // serves, which `check:wire` refuses on its own terms.
        if (isExact(spec))
          notes.push(
            `${dep} — the exercised pin is ${spec}; npmjs serves ${latest} on the same ${lineKey(declared)} line.\n` +
              "    Not a refusal: the peer floor must stay at the minor's zero patch, and `protocol-latest` is\n" +
              "    what moves the exercised pin.",
          );
        else
          refusals.push(
            `${dep} — ${sites.join(", ")} declares "${spec}", whose floor is ABOVE the "${latest}" npmjs\n` +
              "    serves under `latest`. A raised floor on a `0.x` line strands consumers on earlier patches\n" +
              "    of the same line; `check:wire` refuses this shape too, and it is refused here because a\n" +
              `    consumer installing ${dep} today cannot satisfy it.`,
          );
        continue;
      }

      const bucket = direction < 0 ? behind : ahead;
      const key = `${lineKey(declared)}→${lineKey(published)}`;
      if (!bucket.has(key))
        bucket.set(key, { declared, published, entries: [] });
      bucket.get(key).entries.push({ dep, spec, sites, latest });
    }
  }

  if (unreachable.length > 0)
    refusals.push(
      `THE REGISTRY COULD NOT BE READ for ${unreachable.length} of ${byDep.size} declared package(s):\n` +
        `${unreachable.join("\n")}\n` +
        "    Nothing can be concluded about what is published, so this run refuses rather than reporting the\n" +
        "    declared line as current. An unreachable registry and an up-to-date one are the same silence,\n" +
        "    and a zero is not an absence.",
    );
  for (const key of [...behind.keys()].sort())
    refusals.push(renderBehind(behind.get(key)));
  for (const key of [...ahead.keys()].sort())
    refusals.push(renderAhead(ahead.get(key)));

  return { refusals, notes, checked };
}

async function main() {
  const root = fileURLToPath(new URL("..", import.meta.url));
  const manifests = readManifests(root);
  const workspace = workspaceNames(manifests);
  const { refusals, notes, checked } = await currencyReport({
    manifests,
    workspace,
    registry: NetworkRegistry(),
  });

  for (const n of notes) console.log(`  · ${n}\n`);

  if (refusals.length > 0) {
    console.error("\n✕ protocol-currency check failed\n");
    for (const r of refusals) console.error(`  • ${r}\n`);
    exit(1);
  }

  console.log(
    `✓ every declared protocol package is on a line npmjs still serves under \`latest\` (${checked} package(s) read).`,
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
