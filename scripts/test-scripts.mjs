#!/usr/bin/env node
/**
 * Run the drives in `scripts/`, and refuse to report a pass over an empty subject set.
 *
 * ⛔⛔ `node --test scripts/*.test.mjs` EXITS 0 WHEN THE GLOB MATCHES NOTHING. Measured three ways: no
 * `scripts/` directory, an empty one, and a one-character rename of the only drive — all three print
 * `tests 0` and succeed. `sh`, which is what pnpm runs, passes an unmatched glob through literally and
 * Node's own expansion then finds nothing, so the shell never errors either. Deleting the drive would
 * have left `pnpm verify` green while proving nothing.
 *
 * Every other gate here has a floor — `check:vocab` refuses zero files, `check-commit-messages` refuses
 * zero commits, `depcruise-gate` refuses under 40 modules. This is that floor, for the drives.
 */
import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

/** Raise as drives are added; never lower it to make a deletion pass. */
const FLOOR = 1;

const dir = fileURLToPath(new URL(".", import.meta.url));
const drives = readdirSync(dir)
  .filter((name) => name.endsWith(".test.mjs"))
  .sort();

if (drives.length < FLOOR) {
  console.error(
    `⛔ test:scripts — found ${drives.length} drive(s) in scripts/, floor is ${FLOOR}.\n\n` +
      "   A renamed or deleted drive is indistinguishable from a passing one to `node --test`, so the\n" +
      "   count is asserted before anything runs. If a drive was removed on purpose, lower the floor in\n" +
      "   this file deliberately and say why.\n",
  );
  process.exit(1);
}

console.log(`test:scripts — ${drives.length} drive(s): ${drives.join(", ")}`);
process.exit(
  spawnSync(process.execPath, ["--test", ...drives.map((d) => `${dir}${d}`)], {
    stdio: "inherit",
  }).status ?? 1,
);
