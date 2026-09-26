/**
 * The buyer piece for `x402/exact/hedera`: the transaction body whose memo is the hash's LCP string, signed by the payer
 * as `hedera-body`, and the payment whose `payload.transaction` is the signed transaction in base64. The node, the
 * valid start and the maximum fee are the buyer's; the signer answers `{publicKey, signature, type}`.
 */
import type { Json, Refusal } from "@integraledger/lcp";
import type { PaymentRequirements } from "@integraledger/lcp/x402";
import type { Inputs, Signature } from "../types.js";
import { bigintOf, bytesOf, inputsOf, isObject, isRefusal, refuse } from "./common.js";
import { railPiece } from "./x402-rail.js";

const PAIRING = "x402/exact/hedera";
/** A Hedera entity id, `shard.realm.num`. */
export const HEDERA_ENTITY = /^[0-9]{1,20}\.[0-9]{1,20}\.[0-9]{1,20}$/;
const KEY_TYPES: readonly string[] = ["ed25519", "ecdsa-secp256k1"];

function inputs(_accepted: PaymentRequirements, given: Inputs): Record<string, Json> | Refusal {
  const read = inputsOf(given, PAIRING, { node: "string", validStart: "object", maxFee: "decimal", decimals: "optional-uint" });
  if (isRefusal(read)) return read;
  const validStart = inputsOf(read["validStart"] as Inputs, PAIRING, { seconds: "decimal", nanos: "uint" });
  if (isRefusal(validStart)) return validStart;
  return { ...read, validStart };
}

function revive(c: Record<string, unknown>): Record<string, unknown> | Refusal {
  const vs = c["validStart"];
  const seconds = isObject(vs) ? bigintOf(vs["seconds"]) : undefined;
  const maxFee = bigintOf(c["maxFee"]);
  if (!isObject(vs) || seconds === undefined || maxFee === undefined) return refuse("x402/choice-malformed");
  return { ...c, validStart: { ...vs, seconds }, maxFee };
}

/** `{publicKey, signature, type}` with the key and signature as bytes. */
function answer(signature: Signature): unknown {
  if (!isObject(signature)) return refuse("x402/signature-malformed");
  const publicKey = bytesOf(signature["publicKey"]);
  const bytes = bytesOf(signature["signature"]);
  const type = signature["type"];
  if (publicKey === undefined || bytes === undefined || typeof type !== "string" || !KEY_TYPES.includes(type)) {
    return refuse("x402/signature-malformed");
  }
  return { publicKey, signature: bytes, type };
}

export const x402ExactHedera = railPiece({
  pairing: PAIRING,
  namespace: "hedera",
  address: HEDERA_ENTITY,
  payer: "payer",
  now: false,
  inputs,
  revive,
  answer,
  payload: (transaction) => ({ transaction }),
});
