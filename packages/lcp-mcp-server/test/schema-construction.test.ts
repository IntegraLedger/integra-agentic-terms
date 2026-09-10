import { describe, expect, it } from "vitest";

/**
 * ⛔⛔ **EVERY IMPORT IN THIS FILE IS DYNAMIC, AND THAT IS THE WHOLE POINT OF THE FILE.**
 *
 * A tool module builds its `zod` schemas at MODULE SCOPE, so a schema that cannot be constructed throws
 * while the module is loading — before any test runs. `stryker.config.mjs` records what that does to a
 * mutation run, in its own words: *"A mutant that makes an import — or a `describe` body — throw fails the
 * whole test FILE before any test runs, and vitest reports zero FAILED tests. Stryker records that as
 * SURVIVED."* Its prescription is this file's shape — *"where the source itself throws at import, put the
 * guard in its own file and `await import()` it inside the test."*
 *
 * Measured 2026-09-10, repinning to protocol 0.18.1 and `zod` 4.5.4. Four mutants in
 * `extract-reference.ts` — the `termsUrl` discriminated union's three arms and one of its literals — went
 * from Killed to Survived with `tests=0` beside each. Nothing about the suite got worse. `zod` got
 * STRICTER: 4.4.3 accepted a `discriminatedUnion` arm with no discriminator and 4.5.4 refuses it at
 * construction (`Invalid discriminated union option at index "1"`). So the mutated module stopped being
 * loadable at all, every test file that reaches it died on import, and Stryker read the resulting silence
 * as survival. ⇒ **The mutants became IMPOSSIBLE, and impossibility scores as survival.**
 *
 * ⭐ The invariant did not weaken — it MOVED, from a test that catches a malformed union to a library that
 * refuses to build one. This file is what keeps it visible from inside a test, so the score reflects the
 * suite rather than the failure mode of the harness.
 *
 * ⚠️ Adding a static `import` anywhere above silently undoes all of it: this file would then fail to load
 * for exactly the same reason, and the mutants would go back to reading as survivors.
 */
describe("the tool modules construct their schemas at import", () => {
  it("⛔ loads extract-reference INSIDE the test, so an unconstructable schema fails a TEST and not a file", async () => {
    const mod = await import("../src/tools/extract-reference.js");
    expect(typeof mod.registerExtractReference).toBe("function");
  });

  it("⭐ and the published outputSchema keeps the three `termsUrl` answers distinct", async () => {
    // The distinction this asserts is the one the schema's own description insists on: `no-field-declared`
    // is a fact about the PROTOCOL — it has no slot for a locator — while `declared-fields-empty` is a fact
    // about the DOCUMENT, whose seller left every declared slot empty. Collapsing them reports a seller's
    // silence as a protocol's. Read off `tools/list`, which is what an agent host actually receives.
    const { connectTestClient, servingFetcher } = await import("./harness.js");
    const client = await connectTestClient({ fetcher: servingFetcher({}) });
    const tool = (await client.listTools()).tools.find(
      (t) => t.name === "lcp_extract_reference",
    );
    expect(tool, "lcp_extract_reference is not on the wire").toBeDefined();

    const published = JSON.stringify(tool?.outputSchema ?? {});
    // ⚠️ Spelled out rather than derived from the source: an assertion built out of the expression it
    // checks cannot fail.
    for (const kind of ["read", "no-field-declared", "declared-fields-empty"]) {
      expect(published, `termsUrl lost the "${kind}" answer`).toContain(kind);
    }
  });
});
