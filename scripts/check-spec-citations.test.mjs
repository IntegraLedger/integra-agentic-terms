/**
 * The drive for `check:spec-citations`.
 *
 * ⛔⛔ **A GATE THAT HAS NEVER BEEN RED HAS NEVER BEEN SHOWN TO BE A GATE.** Every case below plants a
 * defect into a temporary tree and asserts the refusal NAMES it — and the first case is the null plant,
 * over the same fixture shape, because a red that a clean tree also produces is measuring the fixture
 * rather than the plant.
 *
 * ⭐⭐ **WHY THIS FILE EXISTS NOW.** The gate's in-file canaries prove the PATTERN discriminates. Nothing
 * proved the SUBJECT SET did. `M` 2026-09-14 the deployed documentation site served three citations of an
 * internal draft while the gate reported `44 packed file(s) … none spells an internal LCP revision` and was
 * correct: the site was outside the set by construction. A pattern canary cannot catch that. Only a case
 * that plants into a surface can. planning register #204.
 *
 * ⚠️ **The fixtures carry filler.** Both floors are real numbers — 30 packed files and 40 site files — so a
 * fixture below them is refused by the floor before any plant is read. The filler is how a case gets to
 * assert the thing it is about; two cases assert the floors themselves.
 *
 * ⭐ Nothing in a fixture is executed: the gate READS files. A revision planted here is never published.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const GATE = fileURLToPath(
  new URL("./check-spec-citations.mjs", import.meta.url),
);

/**
 * ⭐ THE PLANTED REVISION. `v1.37` rather than `v1.38`, so a case asserting the refusal names it cannot
 * pass on a stray `v1.38` that some fixture header happens to carry.
 */
const PLANT = "v1.37";

/** How many filler files each surface gets: comfortably over its floor, so the plant is what moves. */
const PACKED_FILLER = 34;
const SITE_FILLER = 24; // per root — 48 total, over the 40 floor

/**
 * A fixture tree: one publishable package and the two site roots, each with enough files to clear its own
 * floor, plus whatever the case plants.
 *
 * ⚠️ `counts` exists for the two cases that are ABOUT the floors. Everything else takes the default,
 * which is a tree the gate has no structural complaint about.
 */
const tree = ({ files = {}, counts = {} } = {}) => {
  const packedN = counts.packed ?? PACKED_FILLER;
  const contentN = counts.content ?? SITE_FILLER;
  const srcN = counts.src ?? SITE_FILLER;

  const root = mkdtempSync(join(tmpdir(), "spec-citations-drive-"));
  const all = {
    // ⛔ `README.md` is not filler: the gate refuses a publishable package whose README it did not walk,
    // because a README leak is the miss it was written after.
    "packages/p/package.json": JSON.stringify({
      name: "@integraledger/p",
      version: "0.0.0",
      files: ["src"],
    }),
    "packages/p/README.md":
      "# p\n\nCites LCP §C.9, which is the allowed form.\n",
  };
  for (let i = 0; i < packedN; i++)
    all[`packages/p/src/filler-${i}.ts`] = `export const filler${i} = ${i};\n`;
  for (let i = 0; i < contentN; i++)
    all[`website/content/docs/filler-${i}.mdx`] = `# Filler ${i}\n\nProse.\n`;
  for (let i = 0; i < srcN; i++)
    all[`website/src/app/filler-${i}.tsx`] =
      `export const Filler${i} = () => null;\n`;

  for (const [path, body] of Object.entries({ ...all, ...files })) {
    const full = join(root, path);
    mkdirSync(join(full, ".."), { recursive: true });
    writeFileSync(full, body);
  }
  return root;
};

const run = (root) => {
  const r = spawnSync(process.execPath, [GATE], {
    env: { ...process.env, INTEGRA_GATE_ROOT: root },
    encoding: "utf8",
  });
  return { status: r.status, out: `${r.stdout}${r.stderr}` };
};

/**
 * Does the refusal name this FILE as a finding, on its own line?
 *
 * ⭐ The gate prints `  <path>:<line> — cites <revision>`, so the assertion is that a line of the output
 * starts with the path and a colon. ⛔ Not `out.includes(path)`: that would also pass on the path
 * appearing inside the remedy sentence, or as a PREFIX of some longer path in a different finding.
 */
const namesFile = (out, path) =>
  out.split("\n").some((line) => line.trim().startsWith(`${path}:`));

const drive = (name, options, expect) =>
  test(name, () => {
    const root = tree(options);
    try {
      expect(run(root));
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

// ⭐⭐ THE NULL PLANT, FIRST. Every case below differs from this one by exactly the planted defect, so a
// red below is caused by the plant. Without this the suite could be measuring a malformed fixture.
drive(
  "⭐ the null plant — a clean fixture is GREEN, so every red below is the plant",
  {},
  (r) => {
    assert.equal(r.status, 0, r.out);
    // ⛔ And the green states its subject set. A pass that does not say what it walked is a pass nobody
    // can check against the surface it claims to cover.
    assert.match(r.out, /packed across/, r.out);
    assert.match(r.out, /served by the documentation site/, r.out);
  },
);

drive(
  "⛔ a revision in a PACKED source file is refused, naming the file",
  {
    files: {
      "packages/p/src/leak.ts": `// Cites LCP ${PLANT} §C.9.\nexport const x = 1;\n`,
    },
  },
  (r) => {
    assert.equal(r.status, 1, r.out);
    assert.ok(namesFile(r.out, "packages/p/src/leak.ts"), r.out);
  },
);

// ⛔⛔ THE CASE THIS FILE WAS WRITTEN FOR. Before #204 this fixture was GREEN: the page is served to every
// reader of the documentation site and was in no manifest's `files`, so the gate never opened it.
drive(
  "⛔⛔ a revision in a page the SITE SERVES is refused, naming the page",
  {
    files: {
      "website/content/docs/leak.mdx": `# Leak\n\nLCP ${PLANT} §C.9's illustrative table lists five tools.\n`,
    },
  },
  (r) => {
    assert.equal(
      r.status,
      1,
      `a page the site serves is inside the subject set:\n${r.out}`,
    );
    assert.ok(namesFile(r.out, "website/content/docs/leak.mdx"), r.out);
  },
);

// ⭐ …and the SECOND site root, because `SITE_ROOTS` has two entries and one of them being walked is not
// evidence about the other.
drive(
  "⛔ a revision in a site ROUTE (the second root) is refused, naming the route",
  {
    files: {
      "website/src/app/leak.tsx": `export const Leak = () => "LCP ${PLANT} §C.4";\n`,
    },
  },
  (r) => {
    assert.equal(r.status, 1, r.out);
    assert.ok(namesFile(r.out, "website/src/app/leak.tsx"), r.out);
  },
);

// ⚠️⚠️ THE BOUNDARY, STATED SO A GREEN IS NOT READ AS MORE THAN IT IS. The subject set is what this
// repository PUBLISHES — what npm packs and what the site serves. A file in neither is not examined, and
// that is intended: this gate's claim is about references a stranger can follow, and nobody follows a
// citation out of a test fixture.
// ⛔ If you are here because you want the whole tree swept: that is planning register #204 clause 3 and it is Fisher's,
// because it needs an exemption mechanism for this gate's own canaries and for CONTRIBUTING.md — and an
// exemption list is the poisoned-declaration shape this estate has already been bitten by.
drive(
  "⚠️ KNOWN AND INTENDED: a revision OUTSIDE both published surfaces is not examined",
  {
    files: {
      "packages/p/test/notes.test.ts": `// LCP ${PLANT} §C.9 said otherwise.\n`,
      "docs-internal/notes.md": `LCP ${PLANT} §C.9 said otherwise.\n`,
    },
  },
  (r) => {
    assert.equal(
      r.status,
      0,
      `the boundary is that neither of these is in the subject set:\n${r.out}`,
    );
  },
);

// ⭐ CONTROL for the case above: the SAME sentence, moved onto a published surface, IS refused. Without
// this the boundary case would also pass if the gate had stopped reading anything at all.
drive(
  "⭐ CONTROL: the same sentence on a PUBLISHED surface is refused — so the case above is a boundary, not blindness",
  {
    files: {
      "website/content/docs/notes.mdx": `LCP ${PLANT} §C.9 said otherwise.\n`,
    },
  },
  (r) => {
    assert.equal(r.status, 1, r.out);
    assert.ok(namesFile(r.out, "website/content/docs/notes.mdx"), r.out);
  },
);

// ⛔⛔ THE COLLAPSE. Two surfaces are floored SEPARATELY because one combined total hides the loss of the
// smaller: 34 packed files clear any floor a 58-file tree would set, while every page has gone.
drive(
  "⛔⛔ a site walk that COLLAPSED is refused by its own floor, not masked by the packed count",
  { counts: { content: 4, src: 4 } },
  (r) => {
    assert.equal(r.status, 1, r.out);
    assert.match(r.out, /documentation site, floor is 40/, r.out);
  },
);

drive(
  "⛔ a site root that contributes NOTHING is named, not averaged away",
  { counts: { content: 0 } },
  (r) => {
    assert.equal(r.status, 1, r.out);
    assert.match(r.out, /website\/content/, r.out);
  },
);

// ⭐ The remedy the refusal prescribes has to actually pass, or the gate is telling people to do something
// it refuses. The bare section is the fix, on both surfaces.
drive(
  "⭐ the prescribed FIX — a bare `LCP §N` — is accepted on both surfaces",
  {
    files: {
      "packages/p/src/ok.ts": "// Cites LCP §C.9.\nexport const x = 1;\n",
      "website/content/docs/ok.mdx": "# OK\n\nLCP §C.9's illustrative table.\n",
    },
  },
  (r) => {
    assert.equal(r.status, 0, r.out);
  },
);
