/**
 * Drive for `check-protocol-currency.mjs` — the decision it makes once the registry has answered, and the
 * four different ways an answer can mean "stop".
 *
 * ⛔⛔ THE DRIVE IS HERMETIC BY CONSTRUCTION, NOT BY LUCK. `FixedRegistry` below is a REAL implementation
 * of the same `RegistryPort` interface the network one implements — it just serves from a table instead of
 * a socket. Nothing here reads `node_modules`, resolves a package, or symlinks any part of the real tree.
 * That last one is not a hypothetical: a fixture in a sibling repository symlinked `node_modules` into
 * itself, inherited whatever the ambient install happened to be, and asserted one refusal message right up
 * until the day the install changed underneath it. A fixture that borrows anything real is hermetic only
 * until someone else runs `pnpm install`.
 *
 * ⛔ AND `FixedRegistry` THROWS ON A NAME IT WAS NOT GIVEN. A table miss must be loud: if it returned
 * `unreachable` for an unknown name, every test below that asserts the unreachable message would pass for a
 * typo in its own table, and the one path this gate exists to get right would have no coverage at all.
 *
 * ⛔ NO ASSERTION HERE IS BUILT OUT OF A VALUE THE SCRIPT EXPORTS. The messages are spelled out as literal
 * strings. `check-protocol-currency.mjs` deliberately exports no message constant, so the tautological
 * `assert.match(out, new RegExp(SOME_MESSAGE))` — which cannot fail — is not available to write.
 */
import assert from "node:assert/strict";
import test from "node:test";
import {
  currencyReport,
  declarationsByPackage,
  describeFailure,
  NetworkRegistry,
  REGISTRY_ORIGIN,
} from "./check-protocol-currency.mjs";
import { workspaceNames } from "./protocol-deps.mjs";

const KERNEL = "@integraledger/lcp-kernel";
const CONFORMANCE = "@integraledger/lcp-conformance";
const SIBLING = "@integraledger/lcp-mcp-server";

/**
 * A real `RegistryPort` over an in-memory table. `answers` maps a package name to the exact
 * `RegistryAnswer` to serve; `asked` records every name it was given, so a test can prove the subject set
 * was DERIVED rather than assert over whatever the port happened to be asked for.
 */
function FixedRegistry(answers) {
  const asked = [];
  const port = async (name) => {
    asked.push(name);
    if (!Object.hasOwn(answers, name))
      throw new Error(
        `FixedRegistry has no answer for ${name} — the table and the manifests disagree, and serving a plausible answer here would let a typo pass as a finding.`,
      );
    return answers[name];
  };
  port.asked = asked;
  return port;
}

/** A packument body carrying one `dist-tags.latest`, in the shape the abbreviated packument really has. */
const packument = (name, latest) => ({
  kind: "packument",
  body: JSON.stringify({
    name,
    "dist-tags": { latest },
    versions: { [latest]: { name, version: latest } },
    modified: "2026-09-10T16:01:53.459Z",
  }),
});

/**
 * A workspace shaped like the real one: a root that pins `lcp-conformance` in `devDependencies` — the pin
 * that sits in no package's list and that the last repin walked past — and one package carrying the peer
 * range, the exercised dev pin and a `workspace:*` sibling.
 */
function tree({ peer = "^0.17.0", dev = "0.17.0", conformance = "0.17.0" }) {
  return [
    {
      name: "<root>",
      path: "/w/package.json",
      pkg: {
        name: "@integraledger/agentic-terms-root",
        devDependencies: {
          [CONFORMANCE]: conformance,
          [SIBLING]: "workspace:*",
          typescript: "7.0.2",
        },
      },
    },
    {
      name: "agentic-terms",
      path: "/w/packages/agentic-terms/package.json",
      pkg: {
        name: "@integraledger/agentic-terms",
        peerDependencies: { [KERNEL]: peer },
        devDependencies: { [KERNEL]: dev },
      },
    },
    {
      name: "lcp-mcp-server",
      path: "/w/packages/lcp-mcp-server/package.json",
      pkg: { name: SIBLING, dependencies: { [KERNEL]: peer } },
    },
  ];
}

const run = (manifests, answers) => {
  const registry = FixedRegistry(answers);
  return currencyReport({
    manifests,
    workspace: workspaceNames(manifests),
    registry,
  }).then((report) => ({ ...report, asked: registry.asked }));
};

const current = {
  [KERNEL]: packument(KERNEL, "0.17.0"),
  [CONFORMANCE]: packument(CONFORMANCE, "0.17.0"),
};

const has = (haystack, needle) =>
  assert.ok(
    haystack.includes(needle),
    `expected to find:\n    ${needle}\n  in:\n    ${haystack}`,
  );

const only = (refusals) => {
  assert.equal(
    refusals.length,
    1,
    `expected exactly one refusal, got ${refusals.length}:\n${refusals.join("\n---\n")}`,
  );
  return refusals[0];
};

test("a tree on the published line refuses nothing, and reads every declared package", async () => {
  const { refusals, notes, checked, asked } = await run(tree({}), current);
  assert.deepEqual(refusals, []);
  assert.deepEqual(notes, []);
  assert.equal(checked, 2);
  // ⛔ THE SUBJECT SET IS DERIVED. Two distinct protocol packages are declared across three manifests and
  // seven declarations; the port is asked for each name once, and never for the `workspace:*` sibling.
  assert.deepEqual([...asked].sort(), [CONFORMANCE, KERNEL]);
});

test("⛔⛔ THE DEFECT — a tree a minor behind the published line is refused, and the refusal names both lines", async () => {
  const { refusals } = await run(tree({ peer: "^0.16.0", dev: "0.16.0" }), {
    ...current,
  });
  const out = only(refusals);
  has(
    out,
    "BEHIND THE PUBLISHED LINE — this tree declares the 0.16 line; npmjs serves 0.17 under `latest`.",
  );
  // ⛔ ONE FINDING, THREE DECLARATIONS. The peer, the shipped runtime caret and the exercised exact pin
  // are the same drift; the count is what proves the evidence list is complete rather than truncated.
  has(out, "1 package(s), 3 declaration(s):");
  has(
    out,
    "vs npmjs 0.17.0   agentic-terms → peerDependencies, lcp-mcp-server → dependencies",
  );
  has(out, "agentic-terms → devDependencies");
  // Both shapes present, and both reasons given — a fixed sentence would be wrong for one of them.
  has(
    out,
    "Not one of those can admit what the registry serves — an exact pin admits only itself; a caret on a `0.x` version pins the MINOR, not the major.",
  );
  has(
    out,
    "and two copies of `lcp-binding-core` break `instanceof CarrierError`. Repin the line with a",
  );
});

test("⛔ a caret behind on the MAJOR is refused too, and says why THAT caret cannot admit it", async () => {
  const { refusals } = await run(tree({ peer: "^1.2.0", dev: "1.2.0" }), {
    [KERNEL]: packument(KERNEL, "2.0.0"),
    [CONFORMANCE]: packument(CONFORMANCE, "0.17.0"),
  });
  const out = only(refusals);
  has(
    out,
    "BEHIND THE PUBLISHED LINE — this tree declares the 1.2 line; npmjs serves 2.0 under `latest`.",
  );
  has(out, "a caret pins the major");
});

test("⛔ two packages behind by DIFFERENT amounts are two findings — collapsing them would state one wrong line", async () => {
  const { refusals } = await run(
    tree({ peer: "^0.16.0", dev: "0.16.0", conformance: "0.15.0" }),
    current,
  );
  assert.equal(refusals.length, 2);
  assert.ok(
    refusals.some((r) =>
      r.includes("declares the 0.15 line; npmjs serves 0.17"),
    ),
  );
  assert.ok(
    refusals.some((r) =>
      r.includes("declares the 0.16 line; npmjs serves 0.17"),
    ),
  );
});

test("⛔⛔ AN UNREACHABLE REGISTRY IS ITS OWN REFUSAL — never `up to date`", async () => {
  const { refusals, checked } = await run(tree({}), {
    ...current,
    [KERNEL]: { kind: "unreachable", detail: "HTTP 503" },
  });
  const out = only(refusals);
  has(out, "THE REGISTRY COULD NOT BE READ for 1 of 2 declared package(s):");
  has(out, "@integraledger/lcp-kernel — HTTP 503");
  has(
    out,
    "An unreachable registry and an up-to-date one are the same silence,",
  );
  // ⛔ AND IT IS NOT COUNTED AS READ. `checked` is what the success line reports, so a package the gate
  // could not read must not inflate it — otherwise a total outage prints a confident count.
  assert.equal(checked, 1);
});

test("⛔ A 404 IS A DIFFERENT REFUSAL FROM AN UNREACHABLE REGISTRY, and says the package is not served at all", async () => {
  const { refusals } = await run(tree({}), {
    ...current,
    [KERNEL]: { kind: "absent" },
  });
  const out = only(refusals);
  has(
    out,
    "@integraledger/lcp-kernel — THE REGISTRY ANSWERS 404: this tree declares a dependency on a package npmjs does not",
  );
  has(out, 'This is not "no newer version"; it is no version at all');
  // It names where the dependency is declared, or an operator cannot find what to delete.
  has(out, "agentic-terms → peerDependencies");
});

test("⛔ A BODY THAT IS NOT JSON IS A REFUSAL, not a package with no newer version", async () => {
  const { refusals } = await run(tree({}), {
    ...current,
    [KERNEL]: { kind: "packument", body: "<html>502 Bad Gateway</html>" },
  });
  const out = only(refusals);
  has(
    out,
    "@integraledger/lcp-kernel — THE REGISTRY ANSWERED 200 BUT the body is not JSON (",
  );
  has(out, "compare the declared line against `undefined` and find no drift.");
});

test("⛔ A 200 WITH NO `dist-tags` IS A REFUSAL — the field this gate exists to read is the one that is missing", async () => {
  const { refusals } = await run(tree({}), {
    ...current,
    [KERNEL]: {
      kind: "packument",
      body: JSON.stringify({ name: KERNEL, versions: {} }),
    },
  });
  has(
    only(refusals),
    "@integraledger/lcp-kernel — THE REGISTRY ANSWERED 200 BUT it carries no `dist-tags` object.",
  );
});

test("⛔ `dist-tags.latest` that is not a string is a refusal, and the refusal prints what it actually was", async () => {
  const { refusals } = await run(tree({}), {
    ...current,
    [KERNEL]: {
      kind: "packument",
      body: JSON.stringify({ name: KERNEL, "dist-tags": { latest: 17 } }),
    },
  });
  has(
    only(refusals),
    "THE REGISTRY ANSWERED 200 BUT `dist-tags.latest` is 17, not a string.",
  );
});

test("⛔ a prerelease under `latest` is refused rather than guessed at — `satisfies` implements no prerelease precedence", async () => {
  const { refusals } = await run(tree({}), {
    ...current,
    [KERNEL]: packument(KERNEL, "0.18.0-rc.1"),
  });
  has(
    only(refusals),
    '`dist-tags.latest` is "0.18.0-rc.1", not an `X.Y.Z` release version',
  );
});

test("⛔⛔ THE FOUR REFUSALS ARE FOUR DIFFERENT SENTENCES — a positive control on the one property the brief turns on", async () => {
  const cases = {
    behind: packument(KERNEL, "0.18.0"),
    unreachable: { kind: "unreachable", detail: "getaddrinfo ENOTFOUND" },
    absent: { kind: "absent" },
    malformed: { kind: "packument", body: "not json at all" },
  };
  const seen = new Map();
  for (const [label, answer] of Object.entries(cases)) {
    const { refusals } = await run(tree({}), { ...current, [KERNEL]: answer });
    assert.ok(refusals.length > 0, `${label} produced no refusal`);
    seen.set(label, refusals.join("\n"));
  }
  const texts = [...seen.values()];
  assert.equal(
    new Set(texts).size,
    4,
    `the four conditions must not share a message:\n${[...seen].map(([k, v]) => `${k}: ${v.split("\n")[0]}`).join("\n")}`,
  );
  // And none of them is the success sentence.
  for (const [label, text] of seen)
    assert.ok(
      !text.includes("is on a line npmjs still serves"),
      `${label} read as a pass`,
    );
});

test("⛔⛔ AN EMPTY SUBJECT SET IS A REFUSAL — a gate that read nothing is the same green as one that read everything", async () => {
  const empty = [
    {
      name: "<root>",
      path: "/w/package.json",
      pkg: { name: "@x/root", devDependencies: { typescript: "7.0.2" } },
    },
  ];
  const registry = FixedRegistry({});
  const { refusals, checked } = await currencyReport({
    manifests: empty,
    workspace: workspaceNames(empty),
    registry,
  });
  has(
    only(refusals),
    "the tree declares no `@integraledger/lcp-*` dependency at all, so this gate compared nothing",
  );
  assert.equal(checked, 0);
  assert.deepEqual(registry.asked, []);
});

test("⛔ a spec this gate cannot derive a line from is refused, never waved through", async () => {
  const manifests = tree({});
  manifests[1].pkg.peerDependencies[KERNEL] = ">=0.17.0 <1";
  const { refusals } = await run(manifests, current);
  has(
    only(refusals),
    '@integraledger/lcp-kernel — agentic-terms → peerDependencies declares ">=0.17.0 <1", which is neither an exact `X.Y.Z` nor a',
  );
});

test("a newer PATCH on the declared line is a note and not a refusal — refusing it would demand what `check:wire` forbids", async () => {
  const { refusals, notes } = await run(tree({}), {
    ...current,
    [KERNEL]: packument(KERNEL, "0.17.3"),
  });
  assert.deepEqual(refusals, []);
  assert.equal(notes.length, 1);
  has(
    notes[0],
    "@integraledger/lcp-kernel — the exercised pin is 0.17.0; npmjs serves 0.17.3 on the same 0.17 line.",
  );
});

test("⛔ a range whose FLOOR is above what npmjs serves is a refusal, distinct from being behind", async () => {
  const manifests = tree({});
  manifests[1].pkg.peerDependencies[KERNEL] = "^0.17.5";
  const { refusals } = await run(manifests, current);
  const out = only(refusals);
  has(
    out,
    '@integraledger/lcp-kernel — agentic-terms → peerDependencies declares "^0.17.5", whose floor is ABOVE the "0.17.0" npmjs',
  );
  assert.ok(
    !out.includes("BEHIND THE PUBLISHED LINE"),
    "a raised floor is not the same finding as a stale line",
  );
});

test("⛔ declaring a line NEWER than `latest` is refused — a consumer resolving `latest` cannot satisfy it", async () => {
  const { refusals } = await run(tree({ peer: "^0.18.0", dev: "0.18.0" }), {
    ...current,
  });
  const out = only(refusals);
  has(
    out,
    "AHEAD OF THE PUBLISHED LINE — this tree declares the 0.18 line, but npmjs serves the",
  );
  has(out, "EARLIER 0.17 line under `latest`.");
  has(out, "an older line was published without `--tag`");
});

test("⛔ the ROOT's protocol pin is a subject — it sits in no package's list and is the one a repin walks past", async () => {
  const { refusals } = await run(tree({ conformance: "0.16.0" }), current);
  const out = only(refusals);
  has(
    out,
    "BEHIND THE PUBLISHED LINE — this tree declares the 0.16 line; npmjs serves 0.17 under `latest`.",
  );
  has(out, "1 package(s), 1 declaration(s):");
  has(out, "@integraledger/lcp-conformance");
  has(out, "<root> → devDependencies");
});

test("⛔ a `workspace:*` sibling on the `lcp-` prefix is never a subject — the prefix cannot tell it from the protocol line", async () => {
  const manifests = tree({});
  const byDep = declarationsByPackage(manifests, workspaceNames(manifests));
  assert.deepEqual([...byDep.keys()].sort(), [CONFORMANCE, KERNEL]);
  assert.ok(!byDep.has(SIBLING));
});

test("⛔ FixedRegistry throws on a name it has no answer for — a table miss must never read as a finding", async () => {
  await assert.rejects(
    () => run(tree({}), { [KERNEL]: packument(KERNEL, "0.17.0") }),
    /FixedRegistry has no answer for @integraledger\/lcp-conformance/,
  );
});

test("the real port is built against npmjs and is a function of one argument, so the drive and the job share an interface", () => {
  assert.equal(REGISTRY_ORIGIN, "https://registry.npmjs.org");
  assert.equal(typeof NetworkRegistry(), "function");
  assert.equal(NetworkRegistry().length, 1);
});

test("⛔⛔ a transport failure is described by its whole cause chain — `fetch failed` alone says nothing", () => {
  // Exactly the shape undici throws: a flat outer message with the real answer one level down. Measured
  // against a host that does not resolve, the outer message is all eleven lines used to say.
  const undici = new TypeError("fetch failed", {
    cause: new Error("getaddrinfo ENOTFOUND registry.example.invalid"),
  });
  assert.equal(
    describeFailure(undici),
    "fetch failed: getaddrinfo ENOTFOUND registry.example.invalid",
  );
});

test("⛔ a repeated message is not printed twice, and a cycle terminates", () => {
  const inner = new Error("ECONNREFUSED");
  const outer = new Error("ECONNREFUSED", { cause: inner });
  assert.equal(describeFailure(outer), "ECONNREFUSED");
  // A self-referential cause is a real shape in wrapped-error libraries; the walk must not hang.
  const loop = new Error("boom");
  loop.cause = loop;
  assert.equal(describeFailure(loop), "boom");
});

test("⛔ a timeout has no `cause`, and must still describe itself rather than reading as empty", () => {
  // `AbortSignal.timeout` rejects with a DOMException carrying no cause at all.
  assert.equal(
    describeFailure(
      new DOMException(
        "The operation was aborted due to timeout",
        "TimeoutError",
      ),
    ),
    "The operation was aborted due to timeout",
  );
  // And a thrown non-Error still yields something an operator can read.
  assert.equal(describeFailure("socket hang up"), "socket hang up");
  assert.equal(describeFailure(null), "null");
});
