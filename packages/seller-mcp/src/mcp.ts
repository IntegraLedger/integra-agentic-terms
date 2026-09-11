/**
 * The MCP seller face — a seller exposes a paid tool, and the payment that unlocks it welds a terms record.
 *
 * ## Why this package exists, and why there are not seven of these
 *
 * The obvious shape of "make agentic commerce reachable" is one seller-face adapter per agent framework.
 * Verified against live sources, **six of the seven candidates have no seller face to adapt**: Coinbase
 * AgentKit's x402 action provider is entirely buyer-side (discover, request, retry, register-a-service-to-
 * call, list); LangChain JS has no server or hosting surface at all; the OpenAI Agents SDK's MCP module is a
 * *client* that connects to MCP servers; Google ADK JS's server ships as a separate devtools package; and
 * AWS AgentCore is Python-only, so a TypeScript adapter is not installable. Agent frameworks are
 * overwhelmingly client-side orchestration.
 *
 * ⇒ **What they converge on is MCP.** A seller exposes a paid capability as an MCP tool, and every one of
 * those frameworks reaches it as a client. So the missing surface is this one, not seven near-duplicates —
 * and building the other six would mean inventing seller faces their owners have not defined.
 *
 * ## It is a TRANSPORT adapter, and deliberately nothing more
 *
 * The ordered on-chain gates in an x402 seller's settle path are the safety property, and burning the
 * proposal is irreversible. This package therefore **reimplements none of it**. It translates an MCP tool
 * call into the web-standard `Request` a seller middleware already takes, and translates the `Response`
 * back — exactly what a framework adapter for Express, Hono, Next or Workers does. The weld is identical
 * because it is the same code on the other side: the buyer's EIP-3009 nonce IS the `atrHash`. Only the
 * envelope differs.
 *
 * ## ⛔ Structurally typed at BOTH edges, and holding no credential
 *
 * Nothing here is imported from an MCP SDK, and nothing here is imported from a seller middleware. Both
 * edges are described by the minimal shapes this adapter actually reads — {@link McpToolResult} and
 * {@link McpToolExtraLike} on one side, {@link SellerMiddlewareLike} and {@link WeldFacts} on the other —
 * so a host on any MCP server implementation can mount it against any middleware with that shape.
 *
 * ⇒ **This package takes no dependency at all.** That is what lets it ship publicly beside a separately
 * licensed seller application rather than inside it: a transport adapter is not a settlement capability,
 * holds no key, and can be read by anyone who wants to know exactly what happens between a tool call and a
 * payment.
 *
 * ## ⛔ The middleware this wraps must answer the tool call itself
 *
 * An MCP tool's answer is an {@link McpToolResult} with its own content blocks, which no `Response` models
 * — so the seller's handler is {@link Fulfil} HERE, and the `Response` the middleware builds is never sent
 * anywhere. A middleware mounted so that it calls a fulfilment port of its own would call the seller's
 * system TWICE for one sale: once through that port and once through `fulfil`. Mount it to produce a
 * body-less 200 carrying the receipt, and let this adapter serve the buyer.
 *
 * ⇒ **And that sentence is why this is a LIBRARY MOUNT rather than a hosted route.** {@link paidTool} is a
 * mount-time factory, not an operation: two of its three arguments — a mounted middleware and the seller's
 * own tool handler — are things a wire cannot carry and a configuration document cannot hold. The supported
 * shape is the one the README shows: the seller builds the middleware, the seller supplies `fulfil`, and
 * the seller's own process answers their buyer.
 *
 * ## The carrier is `_meta`, which is MCP's own extension point
 *
 * The buyer's payment rides in `_meta["x402/payment"]` on the tool call, and the settlement receipt rides
 * back in `_meta["x402/payment-response"]`. That is a documented arbitrary-key map, which a host permits —
 * riding one is a loan the protocol already offers. Nothing here asks MCP for a field it has not defined.
 *
 * ⛔ **AND THE RECEIPT IS THE `PAYMENT-RESPONSE` HEADER, NOT THE 200'S BODY.** A middleware puts the host's
 * settlement response on that header, base64-encoded, and the body is the resource. Sending the body under
 * the receipt's key hands a buyer the thing they bought where the proof they bought it belongs — and no
 * proof at all. See the read site.
 *
 * ## ⚠️ A published MCP complement speaks a different protocol version, and that is measured
 *
 * `x402-mcp` declares `x402Version = 1`; this face declares and emits `x402Version: 2`. One major protocol
 * version apart, in both directions: our challenge announces version 2, and a version 1 client's payment
 * arrives shaped for version 1.
 *
 * **A mismatch cannot settle, and the reason is structural rather than a version check.** A seller reads
 * the presented payment for `payload.authorization.nonce`, and on this rail *the nonce IS the weld*. A
 * payload shaped differently yields no nonce, an empty nonce matches no proposal, and the weld check
 * refuses. There is no path on which a payment settles without a matching nonce.
 *
 * ⭐ **But that refusal names the wrong thing**, which is why {@link declaredX402Version} exists below.
 * Left alone, a seller whose client speaks version 1 sees a weld mismatch and goes looking for a corrupted
 * record, when the actual answer is a protocol version. The middleware cannot say so because it does not
 * read the field. This adapter can, and does — as an ADDED refusal with an accurate message, never as a new
 * acceptance path.
 */
import { deliverWeld, type WeldFacts, type WeldSink } from "./weld-sink.js";

/**
 * ## The two `_meta` keys this adapter reads and writes — and why they are spelled x402's way
 *
 * ⛔⛔ **THESE ARE X402'S KEYS, NOT OURS, AND THAT SETTLES THE SPELLING.** A conformance pass asked whether
 * they should be reverse-DNS (`org.x402/payment`). They should not be changed here, and the reasoning is
 * recorded because the question will be asked again.
 *
 * **They are conformant.** MCP's `_meta` key grammar: a prefix, if specified, *"MUST be a series of labels
 * separated by dots (`.`), followed by a slash (`/`)"*, and *"labels MUST start with a letter and end with
 * a letter or digit"*. `x402` is one such label — it starts with `x` and ends with `2`. The name segment
 * *"MUST begin and end with an alphanumeric character"*, which `payment` and `payment-response` do.
 *
 * **They are not reserved.** Reservation attaches to prefixes *"where the SECOND label is
 * `modelcontextprotocol` or `mcp`"*. `x402/` has no second label.
 *
 * ⚠️ **The reverse-DNS rule is a SHOULD, it is recent, and it binds the party choosing the prefix.** That
 * party is x402. A key this adapter did not define is not this adapter's to re-spell: emitting
 * `com.integraledger/x402-payment` would be read by no counterparty and would claim a namespace for
 * somebody else's protocol field. Where Integra DOES own a namespace the rule is followed.
 *
 * ⭐ **The trigger, so a future change is met with a decision rather than an improvisation:** if x402
 * publishes a reverse-DNS prefix, accept BOTH spellings on read for the transition, emit only the published
 * one, and **refuse when both are present and disagree** — the rule that already applies to two carriers of
 * one fact. Not built now: x402 has published no second spelling, and a reconciliation for a key that does
 * not exist is a branch no input can reach.
 *
 * The upstream venue is open rather than settled — MCP has a live discussion on a standard payment layer,
 * and several independent x402-over-MCP implementations exist. That is a steward conversation, not a local
 * fork.
 */

/** The `_meta` key a buyer's payment rides in on the tool call. */
export const MCP_PAYMENT_META_KEY = "x402/payment";

/** The `_meta` key the settlement receipt rides back in. */
export const MCP_PAYMENT_RESPONSE_META_KEY = "x402/payment-response";

/** The header an x402 version 2 seller reads the presented payment from. */
const PAYMENT_HEADER = "PAYMENT-SIGNATURE";

/** The header a seller returns the host's settlement response on — the receipt, and never the body. */
const PAYMENT_RESPONSE_HEADER = "PAYMENT-RESPONSE";

/** One block of MCP tool output. Text only — this adapter never invents a content type. */
export interface McpTextContent {
  readonly type: "text";
  readonly text: string;
}

/** An MCP tool result, structurally typed so no SDK dependency is taken. */
export interface McpToolResult {
  readonly content: readonly McpTextContent[];
  readonly isError?: boolean;
  readonly _meta?: Readonly<Record<string, unknown>>;
}

/** The per-call extra an MCP server hands a tool handler — only `_meta` is read. */
export interface McpToolExtraLike {
  readonly _meta?: Readonly<Record<string, unknown>> | undefined;
}

/**
 * The per-request outcome an x402 seller middleware produces, structurally typed.
 *
 * `welded` present is the discriminator: it means the settlement completed and the proposal was claimed.
 * Absent on a 402 (unpaid) or on a re-challenge (a payment that arrived but did not weld).
 */
export interface MiddlewareResultLike<TWeld extends WeldFacts = WeldFacts> {
  /** The web-standard `Response` the middleware built. */
  readonly response: Response;
  /** The settlement's artifacts, when one was welded. */
  readonly welded?: TWeld;
}

/**
 * A mounted x402 seller middleware, structurally typed.
 *
 * The same posture this package takes toward the MCP SDK, applied to the other edge: the shape is what this
 * adapter reads, not an import. `TWeld` flows through to {@link Fulfil} and {@link WeldSink}, so a seller
 * whose middleware carries a richer welded settlement keeps every field of it.
 */
export type SellerMiddlewareLike<TWeld extends WeldFacts = WeldFacts> = (
  request: Request,
) => Promise<MiddlewareResultLike<TWeld>>;

/** An adapted paid tool: the signature an MCP server mounts. */
export type PaidToolHandler<TArgs> = (
  args: TArgs,
  extra: McpToolExtraLike,
) => Promise<McpToolResult>;

/** What the seller returns once payment has settled. Receives the weld, so a result may cite its own record. */
export type Fulfil<TArgs, TWeld extends WeldFacts = WeldFacts> = (
  args: TArgs,
  welded: TWeld,
) => Promise<McpToolResult> | McpToolResult;

/** Configuration for one paid tool. */
export interface PaidToolOptions<TWeld extends WeldFacts = WeldFacts> {
  /**
   * The absolute URL of the resource this tool represents.
   *
   * REQUIRED and never defaulted. The middleware mints a proposal against the request's URL, and that URL
   * is what a counterparty later sees as the resource the terms were agreed for — a defaulted one would put
   * a placeholder inside the record.
   */
  readonly resourceUrl: string;
  /**
   * An optional sink for each welded settlement (an evidence store, a log).
   *
   * ⛔ **Its failure never reaches the buyer, and never skips `fulfil`.** This sink runs BEFORE the seller's
   * handler, so a throw here would otherwise do two things at once: answer a buyer who has paid with an
   * error, and stop them ever being given what they paid for. {@link deliverWeld} reports it on the error
   * channel instead.
   */
  readonly onWeld?: WeldSink<TWeld>;
}

/** The x402 protocol version this surface implements. Not the `x402` npm package's release number. */
export const SUPPORTED_X402_VERSION = 2;

/**
 * Best-effort read of the protocol version a presented payment declares, or `null` when it cannot be read.
 *
 * ⛔ **DIAGNOSIS ONLY. This must never become a second parser that can disagree with the middleware.** It
 * decodes far enough to read one integer and nothing else; anything it cannot read returns `null` and the
 * payment is forwarded unchanged for the middleware to judge. So it can only ever ADD a refusal with a
 * better message — never admit a payment the middleware would have refused, and never refuse one the
 * middleware would have taken on any ground it can actually check.
 */
export function declaredX402Version(presented: string): number | null {
  try {
    // ⛔ NO SHAPE GUARD, and its absence is the point rather than an omission. A `typeof decoded ===
    // "object" && decoded !== null` test in front of this read could not change one answer: a payload that
    // decodes to `null` throws on the property read and the catch returns `null`, and one that decodes to a
    // number, string, boolean or array has no `x402Version` and returns `null` too. It was four branches
    // nothing could observe.
    const decoded = JSON.parse(atob(presented)) as { x402Version?: unknown };
    const version = decoded.x402Version;
    return typeof version === "number" ? version : null;
  } catch {
    return null;
  }
}

function textResult(
  text: string,
  isError: boolean,
  meta?: Record<string, unknown>,
): McpToolResult {
  return meta === undefined
    ? { content: [{ type: "text", text }], isError }
    : { content: [{ type: "text", text }], isError, _meta: meta };
}

/**
 * Adapt a mounted x402 seller middleware into an MCP paid tool.
 *
 * The flow, and the order matters:
 *
 * 1. Read the payment from `_meta`, if the buyer sent one.
 * 2. Run the middleware over a web-standard `Request`. Every on-chain gate happens there, in its own order.
 * 3. **No weld ⇒ the payment was absent or did not settle.** Return the middleware's own body verbatim as
 *    an error result: it is the x402 challenge, and rewriting it would mean a client negotiating against
 *    our paraphrase of the terms rather than the terms.
 * 4. **Welded ⇒ settled.** Only now is the seller's `fulfil` called.
 */
export function paidTool<TArgs, TWeld extends WeldFacts = WeldFacts>(
  middleware: SellerMiddlewareLike<TWeld>,
  options: PaidToolOptions<TWeld>,
  fulfil: Fulfil<TArgs, TWeld>,
): PaidToolHandler<TArgs> {
  if (options.resourceUrl.trim() === "")
    throw new Error(
      "seller-mcp: resourceUrl is required — the record must name the resource the terms were agreed for",
    );

  return async function handler(
    args: TArgs,
    extra: McpToolExtraLike,
  ): Promise<McpToolResult> {
    const presented = extra._meta?.[MCP_PAYMENT_META_KEY];
    const headers = new Headers({ "content-type": "application/json" });

    // ⛔ ONE presence gate, not three. The key being absent is a single fact — the buyer sent no payment —
    // and asking it separately in front of the string check, the version check and the header write made
    // the second and third askings unobservable: no input reaches them with a different answer.
    if (presented !== undefined) {
      // A payment that is present but not a string is a malformed call, not an unpaid one. Treating it as
      // unpaid would answer a broken client with a challenge it would send again identically, forever.
      if (typeof presented !== "string")
        return textResult(
          `_meta["${MCP_PAYMENT_META_KEY}"] must be a string; received ${typeof presented}`,
          true,
        );

      // ⭐ Name the protocol version before the middleware turns a version 1 payment into a weld mismatch.
      // The middleware is right to refuse it and wrong about why, because it does not read this field.
      const version = declaredX402Version(presented);
      if (version !== null && version !== SUPPORTED_X402_VERSION)
        return textResult(
          `this surface implements x402 v${SUPPORTED_X402_VERSION}; the presented payment declares x402Version ${version}. It cannot settle — the weld rides a field this version does not place where v${SUPPORTED_X402_VERSION} reads it. Upgrade the client rather than retrying.`,
          true,
        );

      headers.set(PAYMENT_HEADER, presented);
    }

    const result: MiddlewareResultLike<TWeld> = await middleware(
      new Request(options.resourceUrl, {
        method: "POST",
        headers,
        body: JSON.stringify(args ?? {}),
      }),
    );

    if (result.welded === undefined)
      // The 402 challenge, a re-challenge for a payment that arrived unwelded, or a 503 for a quote the
      // seller's own terms intake could not answer. Verbatim, on purpose.
      return textResult(await result.response.text(), true);

    const welded = result.welded;
    await deliverWeld(welded, options.onWeld);

    // ⛔⛔ THE SETTLEMENT RECEIPT IS THE `PAYMENT-RESPONSE` HEADER, NOT THE BODY.
    //
    // A seller middleware puts the host's settlement response on that header, base64-encoded, and the 200's
    // BODY is the resource. Sending the body back under `_meta["x402/payment-response"]` is a buyer
    // receiving the thing they bought where the proof they bought it belongs — and no proof at all. It is
    // an easy substitution to make and a hard one to see, because a fixture whose stub body is shaped like
    // a settlement response performs it too.
    //
    // ⛔ NOT `?? ""` and not a synthesized block. A welded response always carries this header — a
    // middleware sets it unconditionally on the welded path — so absence means a middleware that is broken,
    // and an empty string would be a receipt that decodes to nothing while looking like one. Absent stays
    // absent, which is what the unpaid path already does.
    const receipt = result.response.headers.get(PAYMENT_RESPONSE_HEADER);
    const receiptMeta =
      receipt === null ? {} : { [MCP_PAYMENT_RESPONSE_META_KEY]: receipt };

    // ⛔ THE PROPOSAL IS ALREADY CONSUMED BY THIS POINT, AND THAT IS IRREVERSIBLE. A seller handler that
    // throws here means the buyer has paid and received nothing, so the failure must be LOUD and must name
    // the settled transaction — swallowing it, or returning a bare "tool failed", would leave the seller
    // unable to find the settlement they now owe against.
    try {
      const fulfilled = await fulfil(args, welded);
      return {
        ...fulfilled,
        _meta: { ...fulfilled._meta, ...receiptMeta },
      };
    } catch (error) {
      return textResult(
        `payment SETTLED and the tool then failed — the buyer has paid. atrHash ${welded.atrHash}, payment identifier ${welded.paymentIdentifier}. Reconcile against the settlement before retrying. Cause: ${String(error)}`,
        true,
        receiptMeta,
      );
    }
  };
}
