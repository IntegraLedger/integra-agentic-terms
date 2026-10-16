/**
 * The buyer piece for `mpp/charge/hedera`: the transaction body whose memo is MPP's attribution memo for the chosen
 * challenge, handed to the payer as `hedera-body`. The node, the valid start, the maximum fee, the optional client id
 * and the optional `credentialType` are the buyer's. A challenge that names no `chainId` is read on the account's own
 * network.
 * - `credentialType` `hash` (push, the default when none is named): the build's request carries `broadcast: true`; the
 *   signer signs and broadcasts the body and answers `{transactionId}`, which must name the body's payer and valid
 *   start. The credential is `{challenge, payload: {type: "hash", transactionId}}`, with its landed read held under
 *   the payment's own `FETCHED` member: the network and the body's memo, which `bound` reads. The signer moves the
 *   payment, so a decline keeps it.
 * - `credentialType` `transaction` (pull): the signer answers `{publicKey, signature, type}`, and the credential is
 *   `{challenge, payload: {type: "transaction", transaction}}`, the signed body in base64.
 */
import type { AtrHash, Json, Refusal } from "@integraledger/lcp/core";
import { attributionMemo, chargeHedera, type MppChallenge, type MppCredential } from "@integraledger/lcp/mpp";
import type { BuyerPiece, Choose, Chosen, Inputs, Presented, Signature } from "../types.js";
import {
  accountOf,
  bigintOf,
  broadcasts,
  bytesOf,
  choiceOf,
  held,
  inputsOf,
  isObject,
  isRefusal,
  refuse,
  withoutFetched,
} from "./common.js";
import { requestOf } from "./mpp.js";
import { mppRailPiece, railChoose, type MppRail } from "./mpp-rails.js";
import { HEDERA_ENTITY } from "./x402-exact-hedera.js";

const PAIRING = "mpp/charge/hedera";
const KEY_TYPES: readonly string[] = ["ed25519", "ecdsa-secp256k1"];
const CREDENTIAL_TYPES: readonly string[] = ["transaction", "hash"];
/** A Hedera transaction id, `shard.realm.num@seconds.nanos`. */
const TX_ID = /^((?:0|[1-9][0-9]{0,18})\.(?:0|[1-9][0-9]{0,18})\.(?:0|[1-9][0-9]{0,18}))@(0|[1-9][0-9]{0,18})\.([0-9]{1,9})$/;

function inputs(_request: Record<string, unknown>, given: Inputs): Record<string, Json> | Refusal {
  const read = inputsOf(given, PAIRING, {
    node: "string",
    validStart: "object",
    maxFee: "decimal",
    clientId: "optional-string",
    credentialType: "optional-string",
  });
  if (isRefusal(read)) return read;
  if (read["credentialType"] !== undefined && !CREDENTIAL_TYPES.includes(read["credentialType"] as string)) {
    return refuse("mpp/input-malformed");
  }
  const validStart = inputsOf(read["validStart"] as Inputs, PAIRING, { seconds: "decimal", nanos: "uint" });
  if (isRefusal(validStart)) return validStart;
  return { ...read, validStart };
}

function revive(c: Record<string, unknown>): unknown {
  const vs = c["validStart"];
  const seconds = isObject(vs) ? bigintOf(vs["seconds"]) : undefined;
  const maxFee = bigintOf(c["maxFee"]);
  if (!isObject(vs) || seconds === undefined || maxFee === undefined) return refuse("mpp/choice-malformed");
  return { ...c, validStart: { ...vs, seconds }, maxFee };
}

/** `{publicKey, signature, type}` with the key and signature as bytes. */
function answer(signature: Signature): { publicKey: Uint8Array; signature: Uint8Array; type: "ed25519" | "ecdsa-secp256k1" } | Refusal {
  if (!isObject(signature)) return refuse("mpp/credential-malformed");
  const publicKey = bytesOf(signature["publicKey"]);
  const bytes = bytesOf(signature["signature"]);
  const type = signature["type"];
  if (publicKey === undefined || bytes === undefined || typeof type !== "string" || !KEY_TYPES.includes(type)) {
    return refuse("mpp/credential-malformed");
  }
  return { publicKey, signature: bytes, type: type as "ed25519" | "ecdsa-secp256k1" };
}

const isPush = (c: Record<string, unknown> | undefined): boolean => c !== undefined && c["credentialType"] !== "transaction";

/** The push answer's transaction id, when it names the body's payer and valid start. */
function pushedId(signature: Signature, c: Record<string, unknown>): string | Refusal {
  const id = isObject(signature) ? signature["transactionId"] : undefined;
  const m = typeof id === "string" ? TX_ID.exec(id) : null;
  if (m === null) return refuse("mpp/credential-malformed");
  const vs = c["validStart"];
  const seconds = isObject(vs) ? bigintOf(vs["seconds"]) : undefined;
  const nanos = isObject(vs) ? vs["nanos"] : undefined;
  if (m[1] !== c["payer"] || seconds === undefined || BigInt(m[2]!) !== seconds || Number(m[3]!.padEnd(9, "0")) !== nanos) {
    return refuse("hedera/tx-mismatch");
  }
  return id as string;
}

async function complete(unsigned: unknown, signature: Signature, chosen: Chosen): Promise<Presented | Refusal> {
  const c = choiceOf(chosen);
  const challenge = c?.["challenge"];
  if (c === undefined || !isObject(challenge)) return refuse("mpp/choice-malformed");
  const echoed = challenge as unknown as MppCredential["challenge"];
  if (isPush(c)) {
    const transactionId = pushedId(signature, c);
    if (isRefusal(transactionId)) return transactionId;
    const clientId = typeof c["clientId"] === "string" ? c["clientId"] : undefined;
    const memo = attributionMemo(String(challenge["realm"]), String(challenge["id"]), clientId);
    return held({ challenge: echoed, payload: { type: "hash", transactionId } } satisfies MppCredential, { network: c["network"], memo });
  }
  const a = answer(signature);
  if (isRefusal(a)) return a;
  const transaction = (unsigned as { complete(s: typeof a): string | Refusal }).complete(a);
  if (isRefusal(transaction)) return transaction;
  return { challenge: echoed, payload: { type: "transaction", transaction } } satisfies MppCredential;
}

/**
 * The binding's build, called with the chosen challenge, the payer's values, `credentialType` among them, and H. The
 * binding holds the challenge as `bound` holds an echoed one, with `bound`'s code for each fault, and refuses one whose
 * id does not derive from H with `mpp/id-not-ours`. The body carries no hash of its own: the challenge's id derives
 * from it, and `bound` reads it from there.
 */
export async function buildHederaCharge(choice: unknown, h: AtrHash): Promise<unknown> {
  if (isRefusal(choice)) return choice;
  const c = choice as Parameters<typeof chargeHedera.build>[0];
  if (requestOf(c.challenge) === undefined || typeof c.challenge.id !== "string") return refuse("mpp/choice-malformed");
  return chargeHedera.build(
    {
      challenge: c.challenge,
      payer: c.payer,
      node: c.node,
      validStart: c.validStart,
      maxFee: c.maxFee,
      ...(c.clientId !== undefined ? { clientId: c.clientId } : {}),
      ...(c.credentialType !== undefined ? { credentialType: c.credentialType } : {}),
    },
    h,
  );
}

const spec: MppRail = {
    pairing: PAIRING,
    namespace: "hedera",
    address: HEDERA_ENTITY,
    payer: "payer",
    now: false,
    inputs,
    revive,
    complete,
    network: (c: MppChallenge, accountNetwork: string) => chargeHedera.network(requestOf(c) as never, accountNetwork as never),
};
const rail = mppRailPiece(spec);
const railChosen = railChoose(spec);

/**
 * The choice, with the account's network, which the challenge's network equals, for a push credential's landed read.
 */
function choose(...args: Parameters<Choose>): Chosen | Refusal {
  const chosen = railChosen(...args);
  if (isRefusal(chosen)) return chosen;
  const network = accountOf(args[1])!.network;
  return { ...chosen, choice: { ...(chosen.choice as Record<string, Json>), network } };
}

export const mppChargeHedera: BuyerPiece & { build(choice: unknown, h: AtrHash): Promise<unknown> } = Object.freeze({
  ...rail,
  choose,
  build: buildHederaCharge,
  moves: broadcasts,
  sent(signed: Presented): Presented {
    return withoutFetched(signed as object) as Presented;
  },
});
