/**
 * The buyer piece for `mpp/session/xrpl`: the `PaymentChannelCreate` and the first claim handed to the wallet as the
 * build's `xrpl-session-open` request, exactly as built. The wallet answers `{signedBlob, claimSignature}` as hex
 * digits without `0x`, as the XRP Ledger writes them and as a later `xrpl-claim` is answered, which completes the
 * build's own credential. The deposit and the channel's terms are the buyer's.
 */
import type { Json, Refusal } from "@integraledger/lcp/core";
import type { Inputs, Signature } from "../types.js";
import { inputsOf, isObject, isRefusal, refuse } from "./common.js";
import { completeWith, hexDigits, mppRailPiece, sessionRevive, XRPL_ADDRESS } from "./mpp-rails.js";

const PAIRING = "mpp/session/xrpl";

function inputs(_request: Record<string, unknown>, given: Inputs): Record<string, Json> | Refusal {
  const read = inputsOf(given, PAIRING, { deposit: "decimal", xrpl: "object" });
  if (isRefusal(read)) return read;
  const x = inputsOf(read["xrpl"] as Inputs, PAIRING, {
    publicKey: "hex",
    settleDelay: "uint",
    fee: "decimal",
    sequence: "uint",
    lastLedgerSequence: "uint",
    cancelAfter: "optional-uint",
  });
  if (isRefusal(x)) return x;
  const publicKey = hexDigits(x["publicKey"]);
  if (publicKey === undefined) return refuse("mpp/input-missing");
  return { ...read, xrpl: { ...x, publicKey } };
}

/** `{signedBlob, claimSignature}` as given: the build's `complete` reads each as hex digits without `0x`. */
function answer(signature: Signature): { signedBlob: string; claimSignature: string } | Refusal {
  if (!isObject(signature)) return refuse("mpp/credential-malformed");
  const { signedBlob, claimSignature } = signature;
  if (typeof signedBlob !== "string" || typeof claimSignature !== "string") return refuse("mpp/credential-malformed");
  return { signedBlob, claimSignature };
}

export const mppSessionXrpl = mppRailPiece({
  pairing: PAIRING,
  namespace: "xrpl",
  address: XRPL_ADDRESS,
  payer: "from",
  now: true,
  inputs,
  revive: sessionRevive,
  complete: completeWith(answer),
});
