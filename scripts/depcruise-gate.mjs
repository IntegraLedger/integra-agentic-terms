#!/usr/bin/env node
/**
 * Run dependency-cruiser AND refuse a vacuous cruise — the blind-gate canary.
 *
 * The architecture gate has gone silently blind twice, exit 0 both times: the tsc parser cruises ZERO
 * modules under TS 7, and a missing `enhancedResolveOptions` leaves every `^packages/…` path rule matching
 * nothing (both are documented in `.dependency-cruiser.cjs`, but a comment cannot fail a build). A gate
 * that inspects nothing reports nothing to violate, so "no violations" alone proves the rules held OR the
 * gate is blind — indistinguishable. This wrapper closes that: it asserts the cruise actually SAW the
 * workspace before believing its verdict.
 *
 * ⛔ **THIS WRAPPER WAS LEFT BEHIND WHEN `depcruise` WAS PORTED HERE ON 2026-08-27, AND `AGENTS.md`
 * COMPENSATED WITH AN INSTRUCTION TO A HUMAN** — *"check the module count, not the colour"*. That is the
 * exact shape this workspace's sibling gate calls out in its own docblock: an instruction to a human is
 * not a gate. Measured here: with `exclude: {path: "."}` the raw command prints
 * `✔ no dependency violations found (0 modules, 0 dependencies cruised)` and **exits 0**.
 *
 * The floor is deliberately far below the real count (59 modules on 2026-08-27) and far above zero: it
 * trips on blindness, never on refactoring. Raise it if the workspace grows; never delete it.
 */
import { execFileSync } from "node:child_process";

const MODULE_FLOOR = 40;

let stdout;
try {
  stdout = execFileSync(
    "depcruise",
    [
      "packages",
      "--config",
      ".dependency-cruiser.cjs",
      "--output-type",
      "json",
    ],
    { encoding: "utf8", maxBuffer: 256 * 1024 * 1024 },
  );
} catch (err) {
  // Non-zero exit = error-severity violations (or a crash). Print what depcruise said and fail loud.
  process.stderr.write(String(err.stdout ?? ""));
  process.stderr.write(String(err.stderr ?? err.message ?? err));
  process.exit(1);
}

const { summary } = JSON.parse(stdout);
if (summary.error > 0) {
  // Belt over braces: if depcruise ever stops encoding errors in its exit code, this still refuses.
  console.error(`depcruise-gate: ${summary.error} error-severity violation(s)`);
  process.exit(1);
}
if (summary.totalCruised < MODULE_FLOOR) {
  console.error(
    `depcruise-gate: BLIND GATE — cruised ${summary.totalCruised} modules, floor is ${MODULE_FLOOR}. ` +
      "The cruise saw too little of the workspace for 'no violations' to mean anything; " +
      "suspect the parser (TS-major bump?) or module resolution, not the rules.",
  );
  process.exit(1);
}
console.log(
  `depcruise-gate: ${summary.totalCruised} modules cruised (floor ${MODULE_FLOOR}), 0 violations`,
);
