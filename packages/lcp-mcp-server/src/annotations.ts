import type { ToolAnnotations } from "@modelcontextprotocol/server";

/**
 * Does the tool reach outside this process?
 *
 * The ONLY axis on which this server's tools differ. Everything here reads; nothing writes, publishes,
 * files, or settles — see the mandate boundary in `server.ts`.
 */
export type ToolReach = "network" | "closed";

/**
 * The annotations every tool on this server carries, per the LIVE MCP `ToolAnnotations` definition
 * (`schema/2026-07-28/schema.ts`, read 2026-07-30; the specification check behind that date is recorded in
 * this package's README).
 *
 * THE DEFAULTS ARE WHY THESE ARE STATED RATHER THAN OMITTED. MCP documents `destructiveHint` as
 * **`Default: true`** and `openWorldHint` as **`Default: true`**, with `readOnlyHint` and `idempotentHint`
 * defaulting to `false`. An unannotated tool therefore reads to a client as *possibly destructive, possibly
 * non-idempotent, open to an arbitrary external world* — the most alarming reading available. Every value
 * below is the honest one for a surface that computes, fetches and reads, so stating them is not decoration:
 * omission would actively misdescribe the tools.
 *
 * THIS IS ALSO WHERE LCP's APPENDIX C IS AN ILLUSTRATION AND THE HOST PROTOCOL BINDS. LCP v1.38 §C.9
 * says tool annotations "such as `destructiveHint` and `openWorldHint` signal that LCP-aware tools perform
 * legally significant actions". MCP's own definition says something narrower and different:
 * `destructiveHint` means "the tool may perform destructive updates to **its environment**", and it is
 * "meaningful only when `readOnlyHint == false`". There is no MCP annotation that means "legally
 * significant", and repurposing one to imply it would be an assertion MCP's clients cannot read. So the
 * annotations here say what MCP defines them to say — `destructiveHint: false`, because none of these tools
 * updates anything — and the legal significance is carried where a client can actually read it: in each
 * tool's `description`.
 *
 * `destructiveHint: false` is stated even though `readOnlyHint: true` makes it formally not-meaningful. The
 * spec says the property is meaningful only when `readOnlyHint === false`; it does not require a client to
 * consult `readOnlyHint` first, and a client that reads `annotations.destructiveHint` directly would
 * otherwise inherit the `true` default. Stating it closes that read at no cost.
 *
 * A last honesty note that belongs in the code rather than only in a doc: MCP requires clients to
 * "consider tool annotations to be untrusted unless they come from trusted servers". These are hints a
 * server asserts about itself. They are not a security control and nothing here treats them as one.
 */
export function readOnlyToolAnnotations(
  title: string,
  reach: ToolReach,
): ToolAnnotations {
  return {
    title,
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: reach === "network",
  };
}
