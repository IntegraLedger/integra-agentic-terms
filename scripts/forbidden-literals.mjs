/**
 * Markers that must never appear anywhere in this public repository.
 *
 * ONE LIST, TWO SURFACES. `CLAUDE.md` says everything here is world-readable — "including this file,
 * AGENTS.md, **commit messages**, and code comments". `check-vocab.mjs` enforced that over FILES and
 * nothing enforced it over commit messages, so five commits carrying a `Co-Authored-By` trailer and a
 * session URL reached a public remote without a gate noticing. The list lives here rather than in either
 * checker because a rule stated in two places is a rule that drifts in one of them — the same defect that
 * put this repository's vocabulary gate three minor lines out of date.
 *
 * A marker belongs here when a stranger reading it learns something about how this repository is worked on
 * rather than about the software. That is a different test from `check-vocab`'s unresolvable-identifier
 * rule: these are resolvable, and that is exactly the problem.
 */

/**
 * Each entry carries a SAMPLE it must match. ⛔ A pattern that stops matching reports every file and every
 * commit clean, which looks exactly like success — and the existing canaries used `.some()`, so one live
 * pattern vouched for all of them and a second broken one was invisible. The sample lives beside the
 * pattern for the same reason the list is single-sourced: a check stated somewhere else drifts.
 *
 * Samples may be spelled out here because this file is in `check-vocab`'s `SELF_NAMING` set, along with
 * `check-vocab.mjs` itself. Nothing else may spell them.
 *
 * @type {ReadonlyArray<readonly [RegExp, string, string]>}
 */
export const FORBIDDEN_LITERALS = [
  [
    /claude\.ai\/code\/session/i,
    "a Claude session URL",
    "see https://claude.ai/code/session_0123",
  ],
  [
    /Co-Authored-By:\s*Claude/i,
    "a Co-Authored-By trailer",
    "Co-Authored-By: Claude <noreply@anthropic.com>",
  ],
  [
    /integra-agentic-commerce/i,
    "the private seller-side repository by name",
    "cd ../integra-agentic-commerce && pnpm verify",
  ],
  [
    /integra-july-2026/i,
    "the internal working-directory layout",
    "cd integra-july-2026/integra-agentic-terms",
  ],
];

/** A line that must match NOTHING above — proof the patterns discriminate rather than flagging all prose. */
export const BENIGN_SAMPLE =
  "Reviewed-By: a colleague; see https://example.invalid/docs";
