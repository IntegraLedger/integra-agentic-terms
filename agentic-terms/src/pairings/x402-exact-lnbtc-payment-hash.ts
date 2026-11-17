/**
 * The buyer piece for `x402/exact/lnbtc/payment-hash`: the buyer signs nothing; its node pays the BOLT 11 invoice the
 * seller's node issued after the agreement for the payment hash the ATR commits (`extra.paymentHash`), and its answer is
 * the payment preimage. The protocol package's build makes the client's checks of the option and its invoice before it
 * hands over the invoice to pay (lcp profile `x402-exact-lnbtc.md`, rules 6 and 7): the invoice's `p` is the committed
 * hash, its `h` the request hash of the buyer's own request, its signer `payTo`, its currency the network's, its amount
 * `amount` and its expiry `maxTimeoutSeconds`, and it is unexpired and not created in the future at the gate's clock.
 *
 * The buyer's request is the input `request`, the request the buyer means to make, from which the build computes the
 * scheme's request hash: over HTTP `{profile: "http:1", method, url, body?, headers?}`, `url` the absolute URL the
 * request is made to, `body` the content bytes as `0x` hex (absent for no body) and `headers` each field's line or lines
 * by name; over MCP `{profile: "mcp:1", server, name, arguments?, meta?}`, `server` the MCP server as the buyer's own
 * configuration spells it and `meta` the call's `params._meta`. It is read at the build, once the ATR's hash is held,
 * so an offer is chosen without it; absent there, or of another form, the payment is declined `x402/input-missing`.
 * The node moves the payment, so a decline after it keeps it.
 */
import type { Json, Refusal } from "@integraledger/lcp/core";
import type { PaymentRequirements } from "@integraledger/lcp/x402";
import type { BuyerPiece, Inputs, Signature } from "../types.js";
import { bytesOf, isObject, refuse } from "./common.js";
import { railPiece } from "./x402-rail.js";

const PAIRING = "x402/exact/lnbtc/payment-hash";
/** The payer is named in nothing the node pays, so the account's address is not read. */
const ANY_ADDRESS = /^/;

/** The buyer's request, where `inputs` gives it as an object; else nothing, the build declining it. */
function inputs(_accepted: PaymentRequirements, given: Inputs): Record<string, Json> {
  const request = given["request"];
  return isObject(request) ? { request } : {};
}

/** The choice as the build takes it: the request's body, on `http:1`, as bytes. */
function revive(c: Record<string, unknown>): Record<string, unknown> | Refusal {
  const request = c["request"];
  if (!isObject(request)) return refuse("x402/input-missing");
  if (request["profile"] !== "http:1") return c;
  const body = bytesOf(request["body"] ?? "0x");
  return body === undefined ? refuse("x402/input-missing") : { ...c, request: { ...request, body } };
}

export const x402ExactLnbtcPaymentHash: BuyerPiece = Object.freeze({
  ...railPiece({
    pairing: PAIRING,
    namespace: "lnbtc",
    address: ANY_ADDRESS,
    payer: null,
    now: true,
    inputs,
    revive,
    answer: (signature: Signature) => (typeof signature === "string" ? signature : refuse("ln/preimage-malformed")),
  }),
  moves: () => true,
});
