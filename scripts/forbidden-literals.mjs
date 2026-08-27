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

/** @type {ReadonlyArray<readonly [RegExp, string]>} */
export const FORBIDDEN_LITERALS = [
  [/claude\.ai\/code\/session/i, "a Claude session URL"],
  [/Co-Authored-By:\s*Claude/i, "a Co-Authored-By trailer"],
  [/integra-agentic-commerce/i, "the private seller-side repository by name"],
];
