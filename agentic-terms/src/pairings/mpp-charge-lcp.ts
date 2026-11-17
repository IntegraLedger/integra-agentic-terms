/**
 * The buyer pieces of the `lcp` MPP method's `charge` (lcp profile `mpp-method-lcp.md`), one per rail, each its own
 * pairing named by the challenge's `methodDetails.rail`. The protocol package's build holds the chosen challenge to the
 * method's filter, refuses one whose id is not the hash's, and writes what the buyer signs, whose memo or precondition
 * carries the hash; its `complete` writes the credential `{type: "transaction", transaction}`, the signed bytes the
 * party that submits sends unchanged. The piece never broadcasts and never writes a `hash` credential.
 *
 * `mpp/charge/lcp/hedera`: the `TransactionBody` whose memo is the hash's LCP string, debiting the buyer's account
 * alone, its transaction id naming `feePayerAccountId` where the request's `feePayer` is true and the buyer otherwise,
 * handed to the signer as `hedera-body`. The node, the valid start and the maximum fee are the buyer's, and a token's
 * decimals where it gives them; the signer answers `{publicKey, signature, type}`, the key and signature as `0x` hex.
 */
import type { Json, Refusal } from "@integraledger/lcp/core";
import type { Inputs, Signature } from "../types.js";
import { bigintOf, bytesOf, inputsOf, isObject, isRefusal, refuse } from "./common.js";
import { completeWith, mppRailPiece } from "./mpp-rails.js";
import { HEDERA_ENTITY } from "./x402-exact-hedera.js";

const HEDERA = "mpp/charge/lcp/hedera";
const KEY_TYPES: readonly string[] = ["ed25519", "ecdsa-secp256k1"];

/** The node, the valid start `{seconds, nanos}`, the maximum fee and, for a token, its decimals. */
function hederaInputs(_request: Record<string, unknown>, given: Inputs): Record<string, Json> | Refusal {
  const read = inputsOf(given, HEDERA, {
    node: "string",
    validStart: "object",
    maxFee: "decimal",
    decimals: "optional-uint",
  });
  if (isRefusal(read)) return read;
  const validStart = inputsOf(read["validStart"] as Inputs, HEDERA, { seconds: "decimal", nanos: "uint" });
  if (isRefusal(validStart)) return validStart;
  return { ...read, validStart };
}

/** The choice as the build takes it: the valid start's seconds and the maximum fee as bigints. */
function hederaRevive(c: Record<string, unknown>): Record<string, unknown> | Refusal {
  const vs = c["validStart"];
  const seconds = isObject(vs) ? bigintOf(vs["seconds"]) : undefined;
  const maxFee = bigintOf(c["maxFee"]);
  if (!isObject(vs) || seconds === undefined || maxFee === undefined) return refuse("mpp/choice-malformed");
  return { ...c, validStart: { ...vs, seconds }, maxFee };
}

/** `{publicKey, signature, type}` with the key and signature as bytes, as the build's `complete` takes them. */
function hederaAnswer(signature: Signature): unknown {
  if (!isObject(signature)) return refuse("mpp/credential-malformed");
  const publicKey = bytesOf(signature["publicKey"]);
  const bytes = bytesOf(signature["signature"]);
  const type = signature["type"];
  if (publicKey === undefined || bytes === undefined || typeof type !== "string" || !KEY_TYPES.includes(type)) {
    return refuse("mpp/credential-malformed");
  }
  return { publicKey, signature: bytes, type };
}

export const mppChargeLcpHedera = mppRailPiece({
  pairing: HEDERA,
  namespace: "hedera",
  address: HEDERA_ENTITY,
  payer: "payer",
  now: false,
  inputs: hederaInputs,
  revive: hederaRevive,
  complete: completeWith(hederaAnswer),
});
