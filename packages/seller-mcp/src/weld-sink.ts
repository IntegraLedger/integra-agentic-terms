/**
 * The weld sink, and the one rule about it that is not optional.
 *
 * ⛔ **A SINK THAT THROWS MUST NEVER REACH THE BUYER.** By the time a welded settlement exists the seller's
 * proposal has already been burned, and that is irreversible: there is no un-consume, no release and no
 * expiry. So a sink failure that propagated would answer a buyer WHO HAS PAID with a failure, for a sale
 * that completed — the money is gone, the resource is not served, and the seller's own logging preference
 * is what took it away. The response is the only thing still in our hands at that point, and it must be the
 * one the settle path produced.
 *
 * ⚠️ **This is not a fallback path, and the distinction matters here more than most places.** Nothing is
 * retried, defaulted or substituted; no second sink is tried; the failure is not absorbed. It is REPORTED,
 * in full, on the process's error channel, naming the `atrHash` and the payment identifier — the two things
 * a seller needs to reconcile a settlement they have already taken. {@link paidTool} gives a `fulfil` that
 * throws after settlement the same treatment, for the same reason.
 *
 * ⭐ **A durable store is the mechanism; this is the convenience.** A seller middleware that queues the
 * settlement notification inside the same statement that burns the proposal does not lose the sale when an
 * in-process sink call fails, which is what makes catching here the right answer rather than a swallowed
 * error. On an in-memory store there is no such queue and the notification is lost outright — the buyer's
 * response is still the wrong place to report it.
 *
 * `console.error` rather than `process.stderr`: this adapter is mounted on runtimes with no `process` at
 * all, and one report channel that exists everywhere beats several that do not.
 *
 * ⚠️ **Declared once, here.** The rule above is a property of a shape, and a shape written out separately
 * at each of several mount points is one that can be given a rule at some of them and not others. That is
 * how it came to be absent from the MCP mount while holding elsewhere.
 */

/**
 * The facts about a welded settlement this package reads.
 *
 * ⛔ **Structural, and deliberately minimal.** A seller middleware's own welded-settlement type carries far
 * more — the remembered proposal, the evidence bundle, the settlement reference, the host's settlement
 * response. None of it is this adapter's business, and restating it here would be a second copy of a shape
 * this package does not own, drifting from the day it was written. These two fields are what a failure
 * report must name, and every mount's weld has them.
 */
export interface WeldFacts {
  /** The welded `atrHash` — recovered from the settlement's on-chain EIP-3009 nonce, which IS the weld. */
  readonly atrHash: string;
  /** The x402 `payment_identifier` correlation id carried through proposal → receipt → evidence. */
  readonly paymentIdentifier: string;
}

/** An optional sink each welded settlement is handed to (an evidence store, a log). */
export type WeldSink<TWeld extends WeldFacts = WeldFacts> = (
  welded: TWeld,
) => void | Promise<void>;

/**
 * Hand a welded settlement to the sink, if there is one, and never let its failure reach the caller.
 *
 * Awaited on the success path, deliberately: an evidence-store write completes before the buyer is told
 * they paid.
 */
export async function deliverWeld<TWeld extends WeldFacts>(
  welded: TWeld,
  onWeld: WeldSink<TWeld> | undefined,
): Promise<void> {
  if (onWeld === undefined) return;
  try {
    await onWeld(welded);
  } catch (error) {
    console.error(
      "⛔ the onWeld sink THREW, and the proposal was ALREADY CONSUMED — the buyer has paid and this " +
        "in-process notification is lost. The buyer's response is unaffected, deliberately: the sale " +
        "completed and telling them otherwise would be false. " +
        `atrHash ${String(welded.atrHash)}, payment identifier ${String(welded.paymentIdentifier)}. ` +
        "Reconcile against the settlement; a durable store will still have queued it. " +
        `Cause: ${String(error)}`,
    );
  }
}
