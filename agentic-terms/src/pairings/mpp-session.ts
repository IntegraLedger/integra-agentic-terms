/**
 * The buyer pieces for MPP's channel pairings. A session is signed in two steps: the funding (a token authorization, an
 * open call the signer broadcasts, or a signed Tempo transaction), then the first voucher, whose channel id depends on
 * the funding. A subscription is one step: the root key signs the key authorization's digest.
 */
import type { Refusal } from "@integraledger/lcp";
import type { Hex } from "@integraledger/lcp/evm";
import type { SessionUnsigned } from "@integraledger/lcp/mpp";
import type { BuyerPiece, Choose, Chosen, Inputs, Next, Presented, Read, Signature, SigningRequest } from "../types.js";
import { optionalInputs } from "./batch.js";
import { broadcasts, isRefusal, refuse } from "./common.js";
import { mppChoice, mppChoose, mppComplete, mppRequest } from "./mpp.js";

const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const CREDENTIAL_TYPE = /^(authorization|permit2|hash)$/;

/**
 * The first challenge offering `pairing` on the account's chain, with `deposit` and the optional `authorizedSigner`,
 * `credentialType` and `tokenDomain` inputs.
 */
function sessionChoose(pairing: string): Choose {
  const choose = mppChoose(pairing, { deposit: "decimal" });
  return (read: Read, account: string, inputs: Inputs, now: number, ref: string, doc: unknown): Chosen | Refusal => {
    const chosen = choose(read, account, inputs, now, ref, doc);
    if (isRefusal(chosen)) return chosen;
    const given = optionalInputs(inputs, "mpp", {
      authorizedSigner: EVM_ADDRESS,
      credentialType: CREDENTIAL_TYPE,
      tokenDomain: "object",
    });
    if (isRefusal(given)) return given;
    return { ...chosen, choice: { ...(chosen.choice as object), ...given } };
  };
}

/** The funding request, exactly as built. */
function fundingRequest(unsigned: unknown): SigningRequest {
  return (unsigned as SessionUnsigned).funding as SigningRequest;
}

/**
 * With the funding answer alone, the next request: the voucher over the channel the funding opens. With the list
 * `[funded, voucherSignature]`, the credential.
 */
async function sessionComplete(unsigned: unknown, signature: Signature): Promise<Presented | Next | Refusal> {
  const u = unsigned as SessionUnsigned;
  if (typeof signature === "string") {
    const voucher = u.voucher(signature as Hex);
    if (isRefusal(voucher)) return voucher;
    return { next: { kind: "eip712", typedData: voucher } as unknown as SigningRequest };
  }
  if (!Array.isArray(signature) || signature.length !== 2) return refuse("mpp/credential-malformed");
  const [funded, voucherSignature] = signature;
  if (typeof funded !== "string" || typeof voucherSignature !== "string") return refuse("mpp/credential-malformed");
  return u.complete(funded as Hex, voucherSignature as Hex);
}

/** A buyer piece for an MPP session pairing. */
export function mppSessionPiece(pairing: string): BuyerPiece {
  return Object.freeze({
    choose: sessionChoose(pairing),
    choice: mppChoice,
    request: fundingRequest,
    complete: sessionComplete,
    moves: broadcasts,
  });
}

/** The buyer piece for `mpp/subscription/tempo`: the root key signs the key authorization's digest. */
export const mppSubscriptionPiece: BuyerPiece = Object.freeze({
  choose: mppChoose("mpp/subscription/tempo", {}),
  choice: mppChoice,
  request: mppRequest,
  complete: mppComplete,
});
