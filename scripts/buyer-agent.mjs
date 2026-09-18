#!/usr/bin/env node
/**
 * **A buyer that can pay — the verify-before-sign gate wired to a wallet of its own.**
 *
 * Every other thing in this estate that pays on a test rail is a GATE DRIVER: it exists to turn a proof
 * red, and a transcript it produced would say the appliance works rather than that a buyer does. This is
 * the buyer. It holds its own key, answers a seller's 402 on its own account, and reaches a settled
 * transaction through the published package's own gate.
 *
 * ## ⛔⛔ THE KEY IS STRUCTURALLY GATED, AND THAT IS NOT A FLOURISH
 *
 * `transact` invokes the signer **only** when `evaluate` returns Proceed. A fingerprint that does not match
 * the terms the seller advertised is a Decline, and on a Decline **the signer is never reached** — not
 * "reached and refused". That is the package's *"halt before any signing key is invoked"* guarantee, and
 * this runtime is built so the guarantee is the load-bearing wall rather than a comment: nothing here can
 * sign except through `transact`, and the authorization is assembled *inside* the gated signer, from the
 * hash the gate verified.
 *
 * ⇒ The plant this runtime is measured by is exactly that: tamper with the advertised ATR, and the wallet
 * must record **zero** signing calls. A buyer that refused after signing would have paid.
 *
 * ## What it composes, all of it published
 *
 *   `decodeX402Challenge`      the 402, read rather than guessed
 *   `parseProposalFromChallenge`  the typed proposal — throws on a bad hash, a non-HTTPS terms URL, a
 *                              non-base-unit amount, at the trust boundary
 *   `transact` + `GatedSigner` verify-before-sign, with the key behind the decision
 *   `x402PaymentHeader`        the payment, built from the challenge it answers
 *   `verifySettled`            the independent read afterwards
 *
 * ⛔ **It holds no chain SDK**, exactly as `@integraledger/agentic-terms` holds none: the EIP-712 domain and
 * message are assembled here, and the signature comes from an injected `wallet.signTypedData`. ⚠️ **Which
 * wallet is a decision this file does not take** — see the module note on `WALLET` below.
 *
 * USAGE (by hand; it reaches a network and is therefore in no test)
 *   node scripts/buyer-agent.mjs --resource https://<host>/<path> --terms-level 2
 */
import { realpathSync } from "node:fs";
import { argv } from "node:process";
import { fileURLToPath } from "node:url";
import {
  decodeX402Challenge,
  parseProposalFromChallenge,
  transact,
  x402PaymentHeader,
} from "@integraledger/agentic-terms";

/** The x402 version this buyer speaks. The seller's challenge is answered in its own version or not at all. */
export const X402_VERSION = 2;

/** `transferWithAuthorization`, as EIP-3009 types it. The token contract computes this exact struct. */
export const TRANSFER_WITH_AUTHORIZATION_TYPES = Object.freeze({
  TransferWithAuthorization: Object.freeze([
    Object.freeze({ name: "from", type: "address" }),
    Object.freeze({ name: "to", type: "address" }),
    Object.freeze({ name: "value", type: "uint256" }),
    Object.freeze({ name: "validAfter", type: "uint256" }),
    Object.freeze({ name: "validBefore", type: "uint256" }),
    Object.freeze({ name: "nonce", type: "bytes32" }),
  ]),
});

const record = (value) =>
  typeof value === "object" && value !== null && !Array.isArray(value)
    ? /** @type {Record<string, unknown>} */ (value)
    : null;

/**
 * The EIP-712 domain the TOKEN CONTRACT will compute, read off the seller's own challenge.
 *
 * ⛔ Every field is REQUIRED and none is defaulted. A domain assembled from a guess produces a signature
 * the contract rejects — after the buyer has committed to it — and the failure surfaces at the facilitator
 * as an opaque revert. Refusing here, by name, is the difference between a buyer that cannot pay and a
 * buyer that pays into nothing.
 *
 * @param {unknown} accepted - one entry of the challenge's `accepts[]`.
 * @returns {{name: string, version: string, chainId: number, verifyingContract: string}}
 */
export function eip712Domain(accepted) {
  const entry = record(accepted);
  const extra = record(entry?.["extra"]);
  const name = extra?.["name"];
  const version = extra?.["version"];
  const asset = entry?.["asset"];
  const network = entry?.["network"];
  if (typeof name !== "string" || name === "")
    throw new Error(
      "the challenge advertises no EIP-712 domain `name` for the token — the signature would be over a domain the token contract does not compute",
    );
  if (typeof version !== "string" || version === "")
    throw new Error(
      "the challenge advertises no EIP-712 domain `version` for the token — the signature would be over a domain the token contract does not compute",
    );
  if (typeof asset !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(asset))
    throw new Error(
      `the challenge advertises \`asset\` as ${JSON.stringify(asset)}, which is not a contract address — there is no \`verifyingContract\` to sign against`,
    );
  const caip2 = /^eip155:(\d+)$/.exec(
    typeof network === "string" ? network : "",
  );
  if (caip2 === null)
    throw new Error(
      `the challenge advertises the network ${JSON.stringify(network)}, which is not a CAIP-2 \`eip155:<id>\` identifier — this buyer signs an EIP-712 domain and has no chain id to put in it`,
    );
  return {
    name,
    version,
    chainId: Number(caip2[1]),
    verifyingContract: asset,
  };
}

/**
 * The authorization this buyer will sign — **with the weld riding as the nonce**.
 *
 * ⭐ `nonce` IS the verified `atrHash`. That is the whole mechanism: the token contract never learns what a
 * terms document is, and the payment still commits to one, because the nonce it replays-protects with is
 * the hash of the record. ⇒ The nonce is taken from the gate's own verified value and from nowhere else.
 */
export function authorizationFor({
  accepted,
  from,
  verifiedAtrHash,
  nowSeconds,
  validitySeconds,
}) {
  // ⛔⛔ THE CLOCK IS CHECKED LIKE EVERY OTHER INPUT, AND IT WAS NOT. `ports.now()` was trusted, so a clock
  // returning a number, or a string that is not a date, made `Date.parse` yield `NaN` — and the
  // authorization was signed with `validAfter: "NaN"`, `validBefore: "NaN"`. Driven: the seller settled it.
  // A validity window that is not a window is not a smaller window; it is a signature over a struct whose
  // meaning nobody can state.
  if (!Number.isFinite(nowSeconds) || !Number.isInteger(nowSeconds))
    throw new Error(
      `the clock returned ${JSON.stringify(nowSeconds)}, which is not a whole number of seconds — this buyer will not sign a validity window it cannot state`,
    );
  if (!Number.isInteger(validitySeconds) || validitySeconds <= 0)
    throw new Error(
      `the validity window is ${JSON.stringify(validitySeconds)} seconds, which is not a positive whole number — an authorization with no window is not one`,
    );
  const entry = record(accepted);
  const to = entry?.["payTo"];
  // ⛔⛔ `amount`, NOT `maxAmountRequired`, AND THIS WAS WRONG THE FIRST TIME. x402's own field name is
  // `maxAmountRequired`, and a first cut of this file used it on that authority. The gate this runtime is
  // built on requires the other one: `packages/agentic-terms/src/proposal.ts:46` declares
  // `amount: z.string()`, NON-optional, so a challenge carrying only `maxAmountRequired` throws in the
  // parser before this line is ever reached. ⇒ Reading the spec instead of the code would have built every
  // authorization with `undefined` as its value, on a buyer that had already passed its gate.
  const value = entry?.["amount"];
  if (typeof to !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(to))
    throw new Error(
      `the challenge advertises \`payTo\` as ${JSON.stringify(to)}, which is not an address — this buyer will not sign a transfer with no payee`,
    );
  if (typeof value !== "string" || !/^[0-9]+$/.test(value))
    throw new Error(
      `the challenge advertises \`amount\` as ${JSON.stringify(value)}, which is not an integer in base units`,
    );
  return Object.freeze({
    from,
    to,
    value,
    validAfter: String(nowSeconds - 1),
    validBefore: String(nowSeconds + validitySeconds),
    nonce: verifiedAtrHash,
  });
}

/**
 * Buy one resource: 402 → gate → sign → present → settled.
 *
 * ⛔ The signer is assembled INSIDE this function and handed to `transact`, so there is no path from here
 * to the wallet that does not pass the gate's decision. `signed` counts the invocations, and the plant that
 * matters reads it: on a tampered ATR it must be **0**.
 */
export async function buy({
  resourceUrl,
  wallet,
  policy,
  context,
  ports,
  validitySeconds = 600,
  settlement,
}) {
  const challengeResponse = await ports.fetch(resourceUrl, { method: "GET" });
  if (challengeResponse.status !== 402)
    throw new Error(
      `expected a 402 from ${resourceUrl} and got ${challengeResponse.status} — there is no offer to pay`,
    );
  const challenge = decodeX402Challenge(challengeResponse);
  const proposal = parseProposalFromChallenge(challenge, context);

  const accepted = record(challenge)?.["accepts"];
  const entry = Array.isArray(accepted) ? accepted[0] : null;
  const domain = eip712Domain(entry);

  /** What the gated signer actually signed, kept for the transcript. Written only on Proceed. */
  let authorization = null;
  let signed = 0;
  const result = await transact(proposal, policy, ports, {
    async sign(verifiedAtrHash) {
      signed += 1;
      authorization = authorizationFor({
        accepted: entry,
        from: wallet.address,
        verifiedAtrHash,
        nowSeconds: Math.floor(Date.parse(ports.now()) / 1000),
        validitySeconds,
      });
      const signature = await wallet.signTypedData({
        domain,
        types: TRANSFER_WITH_AUTHORIZATION_TYPES,
        primaryType: "TransferWithAuthorization",
        message: authorization,
      });
      return { signature };
    },
  });

  if (result.kind !== "signed")
    return Object.freeze({
      kind: "halted",
      decision: result.decision,
      signed,
      proposal,
    });

  const header = x402PaymentHeader({
    challenge,
    authorization,
    signature: result.signature,
    paymentIdentifier: proposal.advertisedAtrHash,
    assetTransferMethod: "eip3009",
  });
  const paid = await ports.fetch(resourceUrl, {
    method: "GET",
    headers: { "PAYMENT-SIGNATURE": header },
  });
  if (paid.status !== 200)
    throw new Error(
      `the seller answered ${paid.status} to a signed payment — the authorization was built but nothing settled`,
    );
  /* ⛔⛔ THE INDEPENDENT READ, WHICH THIS MODULE CLAIMED AND DID NOT DO. `buy()` used to end at the
   * seller's 200 — the seller's own word that the seller was paid. For the producer of an acceptance
   * transcript that is the whole difference between a receipt and evidence.
   *
   * ⭐ It runs through `verifySettled` from the published package, with `verifierPorts` and the weld
   * adapter INJECTED — the same discipline that keeps the package itself free of a chain SDK. ⚠️ When the
   * caller supplies none, the read DID NOT HAPPEN, and `verification: null` says so rather than the
   * transcript quietly omitting a clause it owes.
   */
  let verification = null;
  if (settlement !== undefined) {
    const { verifySettled } = await import("@integraledger/agentic-terms");
    verification = await verifySettled(settlement.ref, settlement.adapter, {
      verifierPorts: settlement.verifierPorts,
      atrBytes: settlement.atrBytes,
      asOf: ports.now(),
      coverage: settlement.coverage ?? { ports: [], bindings: [] },
      identity: {
        sellerAssurance: context.sellerAssurance,
        payer: wallet.address,
      },
      ...(settlement.claimedClass === undefined
        ? {}
        : { claimedClass: settlement.claimedClass }),
    });
  }
  return Object.freeze({
    kind: "settled",
    signed,
    proposal,
    authorization,
    domain,
    response: paid,
    verification,
  });
}

/**
 * §7.3's transcript block.
 *
 * ⛔ `purpose` is carried and NOT chosen here. What a settlement's stated purpose is, and what vocabulary it
 * is drawn from, is an open position call; a runtime that invented one would put a word into a record that
 * commits to it. Until it is ruled this prints what the caller was given, and prints `UNRULED` when the
 * caller was given nothing — never a default.
 */
export function renderTranscript({
  host,
  transaction,
  amount,
  atrHash,
  drivenBy,
  buyer,
  purpose,
  verification,
}) {
  return [
    `⭐ SETTLED — against ${host}, on Base Sepolia, through the shipped facilitator path.`,
    `   transaction  ${transaction}`,
    `   amount       ${amount} USDC base units (6dp)`,
    `   atrHash      ${atrHash} — carried as the EIP-3009 nonce`,
    `   driven by    ${drivenBy}`,
    `   buyer        ${buyer}`,
    `   purpose      ${purpose ?? "UNRULED — the vocabulary is an open position call"}`,
    // ⛔ The acceptance clause asks for an INDEPENDENT verify at mechanical depth. A transcript that left
    // this line out when the read did not happen would read as one where it did.
    `   verified     ${
      verification === null || verification === undefined
        ? "NOT READ — no verifier ports were supplied to this run, so nothing independent has confirmed the seller's 200"
        : `${String(verification.verified)} (${String(verification.supportedClass ?? "class not stated")})`
    }`,
  ].join("\n");
}

/**
 * ⛔ **THE WALLET IS NOT CHOSEN HERE, AND THAT IS A DECISION RATHER THAN AN OMISSION.**
 *
 * Signing EIP-712 needs keccak256 and secp256k1, and Node ships neither — `crypto`'s SHA-3 is NIST's, not
 * Ethereum's keccak. So a default wallet means a dependency, in a repository whose own instructions open
 * with *"anything that makes any of them harder to install is a defect, not a hardening measure."* A
 * devDependency would not reach an installer of the published packages — but it would be the first chain
 * SDK in a tree that has deliberately held none, and `@integraledger/agentic-terms` says of itself that it
 * *"halts before a signing key is invoked and holds no chain SDK."*
 *
 * ⇒ The wallet is a PORT: `{ address, signTypedData }`. An operator supplies one, and which one — and
 * whether this repository takes a chain SDK at all — is a call for whoever owns that question, with this
 * paragraph as the statement of what it costs either way.
 */
export const WALLET_PORT_SHAPE = Object.freeze({
  address: "0x…",
  signTypedData: "({domain, types, primaryType, message}) => Promise<0x…>",
});

// ⛔ `realpathSync`, not a bare compare: a drive that imports this module must not run it.
if (
  process.argv[1] !== undefined &&
  realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))
) {
  console.error(
    "buyer-agent — this runtime needs a wallet port, a resource URL and a seller to answer.\n" +
      "It reaches a network and is therefore driven by hand, never from a test.\n" +
      `argv: ${argv.slice(2).join(" ") || "(none)"}`,
  );
  process.exit(2);
}
