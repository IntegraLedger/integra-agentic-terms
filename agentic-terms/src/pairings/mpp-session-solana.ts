/**
 * The buyer piece for `mpp/session/solana`: the opening's values handed to the signer as the build's
 * `solana-session-open` request, exactly as built. The buyer's channel client composes and signs the `open` from them
 * and answers the open payload, which completes the build's own credential. When the challenge's `voucherSigner` is
 * `"operator"`, the payer then signs the session proof over the channel, the payer and the challenge id as
 * `ed25519-raw`, answered in base58, and the open payload carries it as `authentication`.
 */
import type { Refusal } from "@integraledger/lcp";
import type { MppChallenge } from "@integraledger/lcp/mpp";
import { sessionProof } from "@integraledger/lcp/svm";
import type { Chosen, Inputs, Next, Presented, Signature } from "../types.js";
import { choiceOf, inputsOf, isObject, isRefusal, refuse } from "./common.js";
import { requestOf } from "./mpp.js";
import { completeWith, mppRailPiece, sessionRevive } from "./mpp-rails.js";
import { SOLANA_ADDRESS } from "./x402-exact-solana.js";

const PAIRING = "mpp/session/solana";
/** Base58 of a 64-byte Ed25519 signature. */
const SIGNATURE_BASE58 = /^[1-9A-HJ-NP-Za-km-z]{64,88}$/;

const completeOpen = completeWith((s: Signature) => (isObject(s) ? s : refuse("mpp/credential-malformed")));

/** The challenge and payer of the choice, when its challenge asks for the operator mode's session proof. */
function operatorMode(chosen: Chosen): { challenge: MppChallenge & { id: string }; payer: string } | null | Refusal {
  const c = choiceOf(chosen);
  const challenge = c?.["challenge"] as (MppChallenge & { id?: unknown }) | undefined;
  if (!isObject(challenge)) return refuse("mpp/choice-malformed");
  const details = requestOf(challenge)?.["methodDetails"];
  if (!isObject(details) || details["voucherSigner"] !== "operator") return null;
  const payer = c?.["from"];
  if (typeof challenge.id !== "string" || typeof payer !== "string") return refuse("mpp/choice-malformed");
  return { challenge: challenge as MppChallenge & { id: string }, payer };
}

/**
 * The open payload alone completes the credential, unless the challenge asks for the operator mode's session proof:
 * then the open payload asks for the proof's signature next, and `[open, proofSignature]` completes the credential
 * with `authentication` = `{type: "proof", challengeId, payer, signature}`.
 */
async function complete(unsigned: unknown, signature: Signature, chosen: Chosen): Promise<Presented | Next | Refusal> {
  const mode = operatorMode(chosen);
  if (mode === null) return completeOpen(unsigned, signature, chosen);
  if (isRefusal(mode)) return mode;
  if (isObject(signature)) {
    const channelId = signature["channelId"];
    if (typeof channelId !== "string" || !SOLANA_ADDRESS.test(channelId)) return refuse("mpp/credential-malformed");
    const message = sessionProof({ channelId, payer: mode.payer, challengeId: mode.challenge.id });
    return { next: { kind: "ed25519-raw", message, signer: mode.payer } };
  }
  if (!Array.isArray(signature) || signature.length !== 2) return refuse("mpp/credential-malformed");
  const [open, proof] = signature;
  if (!isObject(open) || typeof proof !== "string" || !SIGNATURE_BASE58.test(proof)) {
    return refuse("mpp/credential-malformed");
  }
  const authentication = { type: "proof", challengeId: mode.challenge.id, payer: mode.payer, signature: proof };
  return completeOpen(unsigned, { ...open, authentication }, chosen);
}

export const mppSessionSolana = mppRailPiece({
  pairing: PAIRING,
  namespace: "solana",
  address: SOLANA_ADDRESS,
  payer: "from",
  now: true,
  inputs: (_request: Record<string, unknown>, given: Inputs) => inputsOf(given, PAIRING, { deposit: "optional-decimal" }),
  revive: sessionRevive,
  complete,
});
