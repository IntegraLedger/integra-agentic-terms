#!/usr/bin/env node --test
import assert from "node:assert/strict";
/**
 * `check:shared-pins`' own drive.
 *
 * ⛔⛔ **THE GATE IS THE ONLY THING IN EITHER REPOSITORY THAT READS A COMMENT SPANNING BOTH**, so a green
 * from it is load-bearing in a way most greens here are not: nothing else would disagree if it were
 * wrong. Every direction is re-planted below, and so is each refusal that distinguishes "the tree is
 * fine" from "the gate could not look".
 *
 * ⭐ The fixture builds a REAL pnpm layout — a store directory under `node_modules/.pnpm` and symlinks
 * into it — because the gate deliberately separates the published line from our own packages by RESOLVED
 * PATH and by nothing else. A fixture that wrote plain directories would pass while testing the opposite
 * of what ships: it was measuring workspace manifests as "the published line" that made `pg` look like a
 * protocol dependency the first time this was measured by hand.
 */
import { execFileSync } from "node:child_process";
import { mkdirSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { test } from "node:test";
import { scratchDir } from "./scratch-dir.mjs";

const SCRIPT = new URL("./check-shared-pins.mjs", import.meta.url).pathname;

/**
 * @param {object} opts
 * @param {string} [opts.catalog]   raw `catalog:` body, comments included — the parity claims live there
 * @param {object} [opts.packages]  name -> manifest, written under `packages/`
 * @param {object} [opts.installed] name -> { version, dependencies }, written into the store AND linked
 * @param {boolean} [opts.omitWorkspaceFile]
 */
function fixture({
  catalog,
  packages = {},
  installed = {},
  siblings = {},
  omitWorkspaceFile = false,
} = {}) {
  // ⛔ realpath: on macOS the temp root is itself a symlink, and the gate compares resolved paths against
  // a store path built from ROOT. An unresolved root makes every installed package look like ours.
  const root = realpathSync(scratchDir("shared-pins-drive-"));

  if (!omitWorkspaceFile) {
    writeFileSync(
      join(root, "pnpm-workspace.yaml"),
      `packages:\n  - "packages/*"\n${catalog === undefined ? "" : `catalog:\n${catalog}`}`,
    );
  }

  mkdirSync(join(root, "packages"), { recursive: true });
  for (const [dir, manifest] of Object.entries(packages)) {
    mkdirSync(join(root, "packages", dir), { recursive: true });
    writeFileSync(
      join(root, "packages", dir, "package.json"),
      JSON.stringify(manifest, null, 2),
    );
  }

  for (const [name, spec] of Object.entries(installed)) {
    const short = name.replace("@integraledger/", "");
    const real = join(
      root,
      "node_modules",
      ".pnpm",
      `${short}@${spec.version}`,
      "node_modules",
      name,
    );
    mkdirSync(real, { recursive: true });
    writeFileSync(
      join(real, "package.json"),
      JSON.stringify(
        { name, version: spec.version, dependencies: spec.dependencies ?? {} },
        null,
        2,
      ),
    );
    const link = join(root, "node_modules", name);
    mkdirSync(dirname(link), { recursive: true });
    symlinkSync(relative(dirname(link), real), link);
  }

  // A package reachable ONLY as a store sibling of its host — which is how pnpm lays out every
  // transitive dependency. No root link, deliberately.
  for (const [name, spec] of Object.entries(siblings)) {
    const host = spec.hostDir;
    const dir = join(root, "node_modules", ".pnpm", host, "node_modules", name);
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      join(dir, "package.json"),
      JSON.stringify(
        { name, version: spec.version, dependencies: spec.dependencies ?? {} },
        null,
        2,
      ),
    );
  }

  return root;
}

function run(root) {
  try {
    return {
      status: 0,
      output: execFileSync("node", [SCRIPT], {
        encoding: "utf8",
        env: { ...process.env, INTEGRA_GATE_ROOT: root },
        stdio: "pipe",
      }),
    };
  } catch (error) {
    return {
      status: error.status ?? 1,
      output: `${error.stdout ?? ""}${error.stderr ?? ""}`,
    };
  }
}

/** The shape that passes: one shared pin, equal on both sides, and its comment says it is shared. */
const AGREEING = {
  catalog: `  # MUST equal the protocol repo's catalog pin.\n  viem: "2.55.19"\n`,
  installed: {
    "@integraledger/lcp-binding-evm-common": {
      version: "0.14.0",
      dependencies: { viem: "2.55.19" },
    },
  },
};

test("agreeing pins pass, and the report carries the counts it proved", () => {
  const { status, output } = run(fixture(AGREEING));
  assert.equal(status, 0, `an agreeing tree must pass:\n${output}`);
  assert.match(
    output,
    /1 shared dependency compared/,
    `the count must be visible:\n${output}`,
  );
  assert.match(
    output,
    /1 parity claim witnessed/,
    `the claim count must be visible:\n${output}`,
  );
});

test("DIRECTION ONE — a catalog pin behind the published line is red, naming both versions", () => {
  // The measured case: the protocol repo bumped viem and published; this side kept the older pin.
  const { status, output } = run(
    fixture({
      ...AGREEING,
      catalog: `  # MUST equal the protocol repo's catalog pin.\n  viem: "2.55.18"\n`,
    }),
  );
  assert.equal(
    status,
    1,
    `a stale catalog pin PASSED — this is the split the comments warn about:\n${output}`,
  );
  assert.match(
    output,
    /2\.55\.18/,
    `red, but not naming what we pin:\n${output}`,
  );
  assert.match(
    output,
    /2\.55\.19/,
    `red, but not naming what the published line declares:\n${output}`,
  );
});

test("DIRECTION ONE — a stale pin declared DIRECTLY in a package is caught too", () => {
  // The surface a catalog-driven sweep walks past: `ripple-binary-codec` and `ripple-keypairs` were
  // pinned in seller-settlement, outside the catalog, and the 0.14.0 re-pin missed them in silence.
  const { status, output } = run(
    fixture({
      catalog: `  zod: "4.4.3"\n`,
      packages: {
        settlement: {
          name: "@x/settlement",
          dependencies: { viem: "2.55.18" },
        },
      },
      installed: {
        "@integraledger/lcp-binding-evm-common": {
          version: "0.14.0",
          dependencies: { viem: "2.55.19" },
        },
      },
    }),
  );
  assert.equal(
    status,
    1,
    `a stale DIRECT pin PASSED — the catalog is not the whole subject set:\n${output}`,
  );
  assert.match(
    output,
    /@x\/settlement/,
    `red, but not naming the manifest that pins it:\n${output}`,
  );
  assert.match(
    output,
    /2\.55\.18/,
    `red, but not naming the stale version:\n${output}`,
  );
});

test("DIRECTION TWO — a parity claim the published line cannot witness is red", () => {
  const { status, output } = run(
    fixture({
      catalog:
        `  # MUST equal the protocol repo's catalog pin.\n  viem: "2.55.19"\n` +
        `  # Pinned equal to the protocol repo's catalog.\n  "@types/json-schema": "7.0.15"\n`,
      installed: {
        "@integraledger/lcp-binding-evm-common": {
          version: "0.14.0",
          dependencies: { viem: "2.55.19" },
        },
      },
    }),
  );
  assert.equal(
    status,
    1,
    `an unwitnessable parity claim PASSED — it reads as checked and is not:\n${output}`,
  );
  assert.match(
    output,
    /@types\/json-schema/,
    `red, but not naming the unwitnessable claim:\n${output}`,
  );
});

test("DIRECTION THREE — a shared pin whose comment claims nothing is red", () => {
  const { status, output } = run(
    fixture({
      catalog: `  # trust boundaries only — never the kernel\n  zod: "4.4.3"\n`,
      installed: {
        "@integraledger/lcp-discovery": {
          version: "0.14.0",
          dependencies: { zod: "4.4.3" },
        },
      },
    }),
  );
  assert.equal(
    status,
    1,
    `a silently-shared pin PASSED — the obligation would be invisible:\n${output}`,
  );
  assert.match(output, /zod/, `red, but not naming the pin:\n${output}`);
  assert.match(
    output,
    /protocol repo's catalog/,
    `red, but not saying what to write:\n${output}`,
  );
});

test("DIRECTION THREE — a shared pin outside the catalog is told to move into it", () => {
  const { status, output } = run(
    fixture({
      catalog: `  zod: "4.4.3"\n`,
      packages: {
        settlement: {
          name: "@x/settlement",
          dependencies: { viem: "2.55.19" },
        },
      },
      installed: {
        "@integraledger/lcp-binding-evm-common": {
          version: "0.14.0",
          dependencies: { viem: "2.55.19" },
        },
      },
    }),
  );
  assert.equal(
    status,
    1,
    `an AGREEING direct pin passed — agreement today is not the claim:\n${output}`,
  );
  assert.match(output, /catalog/, `red, but not naming the remedy:\n${output}`);
});

test("the published line disagreeing with ITSELF is red, not compared against", () => {
  const { status, output } = run(
    fixture({
      catalog: `  # MUST equal the protocol repo's catalog pin.\n  viem: "2.55.19"\n`,
      installed: {
        "@integraledger/lcp-binding-evm-common": {
          version: "0.14.0",
          dependencies: { viem: "2.55.19" },
        },
        "@integraledger/lcp-binding-evm-x402": {
          version: "0.14.0",
          dependencies: { viem: "2.55.18" },
        },
      },
    }),
  );
  assert.equal(status, 1, `a split ALREADY IN THE TREE passed:\n${output}`);
  assert.match(
    output,
    /more than one version/,
    `red, but not saying the published line is split:\n${output}`,
  );
});

test("a range on the published side is REFUSED, never guessed at", () => {
  const { status, output } = run(
    fixture({
      catalog: `  # MUST equal the protocol repo's catalog pin.\n  viem: "2.55.19"\n`,
      installed: {
        "@integraledger/lcp-binding-evm-common": {
          version: "0.14.0",
          dependencies: { viem: "^2.55.19" },
        },
      },
    }),
  );
  assert.equal(
    status,
    1,
    `a range was silently treated as equal to a version:\n${output}`,
  );
  assert.match(
    output,
    /range/,
    `red, but not saying why it cannot decide:\n${output}`,
  );
});

test("a tree with no installed protocol packages is REFUSED, not called clean", () => {
  // check:versions spent its whole life examining an empty set and printing a sentence true of nothing.
  const { status, output } = run(
    fixture({
      catalog: `  # MUST equal the protocol repo's catalog pin.\n  viem: "2.55.19"\n`,
    }),
  );
  assert.equal(
    status,
    1,
    `an empty published line PASSED — the gate compared against nothing:\n${output}`,
  );
  assert.match(
    output,
    /pnpm install/,
    `red, but not saying what is wrong:\n${output}`,
  );
});

test("a missing pnpm-workspace.yaml is a wiring refusal", () => {
  const { status, output } = run(
    fixture({ ...AGREEING, omitWorkspaceFile: true }),
  );
  assert.equal(status, 1, `a missing workspace file PASSED:\n${output}`);
  assert.match(
    output,
    /pnpm-workspace\.yaml/,
    `red, but not naming the missing file:\n${output}`,
  );
});

test("a workspace file with no catalog: is a wiring refusal", () => {
  const { status, output } = run(fixture({ ...AGREEING, catalog: undefined }));
  assert.equal(status, 1, `a workspace with no catalog PASSED:\n${output}`);
  assert.match(
    output,
    /catalog/,
    `red, but not naming what is absent:\n${output}`,
  );
});

/* ── The catalog parser, and the three ways it used to lose an entry in silence ─────────────────────── */

test("a SINGLE-quoted pin is read, and its divergence is red", () => {
  // ⛔⛔ MEASURED GREEN before the fix: the parser required a double-quoted value and `continue`d on
  // anything else, so the entry left the subject set and no direction could fire. This file already writes
  // single quotes in-house (`'@swc/core': false`), so it is the house style, not an exotic input.
  const { status, output } = run(
    fixture({
      catalog:
        "  # MUST equal the protocol repo's catalog pin.\n  viem: '2.55.18'\n",
      installed: {
        "@integraledger/lcp-binding-evm-common": {
          version: "0.14.0",
          dependencies: { viem: "2.55.19" },
        },
      },
    }),
  );
  assert.equal(status, 1, `a single-quoted divergence PASSED:\n${output}`);
  assert.match(
    output,
    /2\.55\.18/,
    `red, but not naming the stale pin:\n${output}`,
  );
});

test("a BARE pin is read, and its divergence is red", () => {
  const { status, output } = run(
    fixture({
      catalog:
        "  # MUST equal the protocol repo's catalog pin.\n  viem: 2.55.18\n",
      installed: {
        "@integraledger/lcp-binding-evm-common": {
          version: "0.14.0",
          dependencies: { viem: "2.55.19" },
        },
      },
    }),
  );
  assert.equal(status, 1, `an unquoted divergence PASSED:\n${output}`);
  assert.match(
    output,
    /2\.55\.18/,
    `red, but not naming the stale pin:\n${output}`,
  );
});

test("a catalog line the parser cannot read is REFUSED, never skipped", () => {
  const { status, output } = run(
    fixture({
      catalog:
        '  # MUST equal the protocol repo\'s catalog pin.\n  viem: "2.55.19"\n  this line is not a pin\n',
      installed: {
        "@integraledger/lcp-binding-evm-common": {
          version: "0.14.0",
          dependencies: { viem: "2.55.19" },
        },
      },
    }),
  );
  assert.equal(
    status,
    1,
    `an unreadable catalog line was skipped and the gate PASSED:\n${output}`,
  );
  assert.match(
    output,
    /could not be read/,
    `red, but not saying what it could not read:\n${output}`,
  );
});

test("a comment at the left margin does not truncate the catalog", () => {
  // ⛔⛔ MEASURED: one divider comment at column 0 ended the scan, taking 8 comparisons to 1 and a live
  // viem split to green. A comment is documentation at any indentation; only a non-comment dedents.
  const { status, output } = run(
    fixture({
      catalog:
        '  # MUST equal the protocol repo\'s catalog pin.\n  zod: "4.4.3"\n# a divider\n' +
        '  # MUST equal the protocol repo\'s catalog pin.\n  viem: "2.55.18"\n',
      installed: {
        "@integraledger/lcp-discovery": {
          version: "0.14.0",
          dependencies: { zod: "4.4.3" },
        },
        "@integraledger/lcp-binding-evm-common": {
          version: "0.14.0",
          dependencies: { viem: "2.55.19" },
        },
      },
    }),
  );
  assert.equal(
    status,
    1,
    `an entry below a column-0 comment left the subject set:\n${output}`,
  );
  assert.match(
    output,
    /viem/,
    `red, but not on the entry below the comment:\n${output}`,
  );
});

test("⭐ a package reachable only as a STORE SIBLING is read — the walk, not a coincidence of the install", () => {
  // pnpm lays a package's own dependencies out as siblings inside the same store entry, never nested under
  // it. Pushing the package directory looked like a descent and was a no-op past depth one.
  const { status, output } = run(
    fixture({
      catalog:
        '  # MUST equal the protocol repo\'s catalog pin.\n  viem: "2.55.18"\n',
      installed: {
        "@integraledger/agentic-terms": { version: "0.13.0", dependencies: {} },
      },
      siblings: {
        "@integraledger/lcp-binding-evm-common": {
          hostDir: "agentic-terms@0.13.0",
          version: "0.14.0",
          dependencies: { viem: "2.55.19" },
        },
      },
    }),
  );
  assert.equal(
    status,
    1,
    `a transitive protocol package was never read, and the split PASSED:\n${output}`,
  );
  assert.match(
    output,
    /2\.55\.19/,
    `red, but not naming what the transitive package declares:\n${output}`,
  );
});
