/**
 * A temporary directory that removes itself when the process ends.
 *
 * ⛔⛔ **THIS EXISTS BECAUSE THE GATES FILLED A 1.8 TiB DISK AND TOOK THE MACHINE DOWN.** Measured
 * 2026-08-30: **~96,000 directories** under the OS temp root, left by the drives themselves —
 * `creds-*` 6,831, `review-controls-*` 6,708, `console-store-*` 5,679, `claims-drive-*` 2,838, plus a
 * dozen more `*-drive-*` prefixes. Fifty-six scripts called `mkdtempSync`; **exactly one**
 * (`check-configuration-field-survival.mjs`) removed what it made.
 *
 * The failure did not present as a full disk. Docker's daemon died on `ENOSPC`, the shared Postgres
 * went with it, and when Postgres came back its **volume was fresh** — so a lane that had touched
 * nothing met **98 loud connection failures** and had every reason to read them as its own regression.
 * One nearly did. ⇒ The cost of a leaked fixture is not disk. It is an hour spent disbelieving a
 * correct tree.
 *
 * ⚠️ **The drives are meticulous about proving a gate refuses and careless about what proving costs.**
 * That asymmetry is the thing to notice: the fixtures were never the subject of any check, so nothing
 * in fifty-five stages had an opinion about them. It is the same shape as a gate passing over an empty
 * subject set, one level down — the apparatus was correct about the question it asked and silent about
 * the ground it stood on.
 *
 * ## Why `process.on("exit")` and not a `finally`
 *
 * A gate that refuses calls `die()`, which exits. A `finally` in the caller would not run, and a
 * `try/finally` around every call site is fifty-six places to forget. Registering once and sweeping at
 * exit covers the refusal path, which is the path these scripts take most often when they are working.
 *
 * ⛔ `exit` handlers must be **synchronous**, which is why this uses `rmSync`. An `await` here silently
 * does nothing and the leak comes back wearing a fix.
 *
 * ⚠️ A `SIGKILL` still leaks, and nothing can change that. A crash-only sweep is therefore not a
 * substitute for this — it is the reason `INTEGRA_KEEP_SCRATCH` exists rather than a debugger flag that
 * leaves everything behind by default.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** Every directory this process made, in creation order. */
const made = [];

/** ⛔ Registered ONCE. Fifty-six scripts importing this must not install fifty-six handlers. */
let sweeping = false;

/**
 * ⚠️ Set `INTEGRA_KEEP_SCRATCH=1` to keep them — the one case that wants a leak is a human reading a
 * fixture a gate just refused over. It is opt-in because the default that filled the disk was the
 * default nobody chose.
 */
const keep = process.env["INTEGRA_KEEP_SCRATCH"] === "1";

function sweep() {
  if (keep) {
    if (made.length > 0)
      process.stderr.write(
        `INTEGRA_KEEP_SCRATCH=1 — keeping ${String(made.length)} scratch director${made.length === 1 ? "y" : "ies"}:\n  ${made.join("\n  ")}\n`,
      );
    return;
  }
  for (const dir of made) rmSync(dir, { recursive: true, force: true });
  made.length = 0;
}

/**
 * Make a scratch directory under the OS temp root and have it removed when this process ends.
 *
 * @param {string} prefix - what the directory is for, e.g. `"claims-drive-"`. Keep the trailing dash:
 *   `mkdtempSync` appends six random characters directly, and a prefix without one produces names that
 *   read as a single word and are miserable to grep for when one does escape.
 * @returns {string} the created directory's path.
 */
export function scratchDir(prefix) {
  if (!sweeping) {
    sweeping = true;
    // ⛔ `exit` covers the ordinary path AND `die()`. The signals cover a Ctrl-C mid-run, which is how
    // a developer usually leaves a long gate — and which left ~96,000 directories behind before this.
    process.on("exit", sweep);
    for (const signal of ["SIGINT", "SIGTERM"])
      process.on(signal, () => {
        sweep();
        process.exit(130);
      });
  }
  const dir = mkdtempSync(join(tmpdir(), prefix));
  made.push(dir);
  return dir;
}
