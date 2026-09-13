#!/usr/bin/env node
/**
 * The drive for `check:runner-patch` — **every defect it exists to catch, PLANTED, with the gate going
 * red for the right reason.**
 *
 * ⛔⛔ A GATE IS NOT FINISHED WHEN IT IS GREEN. The defect this one names is invisible by construction:
 * vitest skips every test whose name a pattern does not match and exits 0, so Stryker records those
 * mutants as SURVIVED and the score collapses toward the static-mutants-only floor — or, where a ratchet
 * sits below that, stays GREEN over a suite that ran nothing. There is no loud failure to notice, which is
 * exactly why the plants below are the evidence and the passing line is not.
 *
 * ⭐ The three plants correspond to the three ways the pairing can break, measured on real trees on
 * 2026-09-13 before this file existed: the patch DROPPED under catalog 5; vitest DOWNGRADED to 4 under a
 * patch that stayed; and the STALE INSTALL — catalog 5 against a `node_modules` holding 4 — which was live
 * in a shared clone of the protocol repository that day.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  assess,
  canaryRefusals,
  catalogVitest,
} from "./check-runner-patch.mjs";

const GATE = fileURLToPath(new URL("check-runner-patch.mjs", import.meta.url));
const ROOT = fileURLToPath(new URL("..", import.meta.url));

const PATCHED = "return nameParts.join(' > ').trim();";
const UNPATCHED = "return nameParts.join(' ').trim();";
const both = (src) => ({ "stryker-setup.js": src, "test-helpers.js": src });

// ─── the correct pairings, both directions ─────────────────────────────────────────────────────────────

test("⭐ vitest 5 beside a patched runner passes, and says which spelling it saw", () => {
  const { refusals, want, seen } = assess({
    catalogVersion: "5.0.0",
    installedVitest: "5.0.0",
    sites: both(PATCHED),
  });
  assert.deepEqual(refusals, [], refusals.join("\n"));
  assert.equal(want, "join(' > ')");
  assert.equal(seen.length, 2, seen.join(", "));
});

test("⭐⭐ vitest 4 beside an UNPATCHED runner also passes — the gate demands consistency, not the patch", () => {
  // This is what makes it the mechanical form of the atomicity rule rather than a preference: a tree that
  // has not bumped yet is correct, and stays correct, until the bump and the patch move together.
  const { refusals, want } = assess({
    catalogVersion: "4.1.11",
    installedVitest: "4.1.11",
    sites: both(UNPATCHED),
  });
  assert.deepEqual(refusals, [], refusals.join("\n"));
  assert.equal(want, "join(' ')");
});

// ─── the three plants ──────────────────────────────────────────────────────────────────────────────────

test("⛔ PLANT: the patch DROPPED while the catalog still says 5 — both sites named", () => {
  const { refusals } = assess({
    catalogVersion: "5.0.0",
    installedVitest: "5.0.0",
    sites: both(UNPATCHED),
  });
  assert.equal(refusals.length, 2, refusals.join("\n"));
  for (const r of refusals)
    assert.match(
      r,
      /does not spell `join\(' > '\)` — it spells `join\(' '\)`/,
      r,
    );
});

test("⛔ PLANT: vitest DOWNGRADED to 4 under a patch that stayed — the mirror image", () => {
  const { refusals } = assess({
    catalogVersion: "4.1.11",
    installedVitest: "4.1.11",
    sites: both(PATCHED),
  });
  assert.equal(refusals.length, 2, refusals.join("\n"));
  for (const r of refusals)
    assert.match(
      r,
      /does not spell `join\(' '\)` — it spells `join\(' > '\)`/,
      r,
    );
});

test("⛔⛔ PLANT: the STALE INSTALL — catalog 5, node_modules 4 — which a runner/vitest check alone PASSES", () => {
  // ⭐ The runner and vitest agree with each other here: an unpatched runner beside vitest 4 is
  // self-consistent, and a gate comparing only those two would report this tree clean. It is the CATALOG
  // that makes it a finding, and this is the case that was live in a shared clone on 2026-09-13.
  const { refusals } = assess({
    catalogVersion: "5.0.0",
    installedVitest: "4.1.11",
    sites: both(UNPATCHED),
  });
  assert.ok(
    refusals.some((r) =>
      /asks for vitest 5\.0\.0 but 4\.1\.11 is INSTALLED/.test(r),
    ),
    refusals.join("\n"),
  );
});

// ─── failing closed, which is the half that reads as success when it breaks ────────────────────────────

test("⛔ a runner whose dist layout moved is REFUSED, never passed over as 'nothing to check'", () => {
  const { refusals } = assess({
    catalogVersion: "5.0.0",
    installedVitest: "5.0.0",
    sites: { "stryker-setup.js": PATCHED }, // test-helpers.js absent
  });
  assert.equal(refusals.length, 1, refusals.join("\n"));
  assert.match(
    refusals[0],
    /test-helpers\.js is not in the installed runner/,
    refusals[0],
  );
});

test("⛔ a site spelling NEITHER form is refused, and said differently from one spelling the wrong form", () => {
  const { refusals, seen } = assess({
    catalogVersion: "5.0.0",
    installedVitest: "5.0.0",
    sites: both("return nameParts.join(SEPARATOR).trim();"),
  });
  assert.equal(refusals.length, 2, refusals.join("\n"));
  for (const r of refusals) assert.match(r, /and spells neither form/, r);
  for (const s of seen) assert.match(s, /NEITHER/, s);
});

test("⭐ the canaries discriminate — a predicate that stopped matching would pass everything", () => {
  assert.deepEqual(canaryRefusals(), []);
});

// ─── the catalog read, whose empty answer is the empty-subject-set defect ──────────────────────────────

test("⛔ a catalog with no `vitest:` line REFUSES rather than reading an empty subject set", () => {
  const { error } = catalogVitest(fileURLToPath(new URL(".", import.meta.url)));
  assert.match(error ?? "", /pnpm-workspace\.yaml is not there|found 0/);
});

test("⭐ and over THIS workspace it finds exactly one, which is the positive control on that shape", () => {
  const { version, error } = catalogVitest(ROOT);
  assert.equal(error, undefined, error);
  assert.match(version ?? "", /^[0-9]+\.[0-9]+\.[0-9]+/);
});

// ─── the gate as CI runs it ────────────────────────────────────────────────────────────────────────────

test("⭐ spawned over this tree as `pnpm verify` spawns it, the gate exits 0 and names both sites", () => {
  // ⚠️ The plants above drive the DECISION; this drives the WIRING — that the script reads a real
  // install, resolves the runner the tree actually links, and reports. Neither stands in for the other.
  const out = execFileSync(process.execPath, [GATE], { encoding: "utf8" });
  assert.match(out, /check:runner-patch — catalog vitest/, out);
  assert.match(out, /stryker-setup\.js=/, out);
  assert.match(out, /test-helpers\.js=/, out);
});
