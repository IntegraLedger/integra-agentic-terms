// x402/exact/stellar/precondition, the agreement on Stellar: its buyer piece and the summary of the request it hands the
// signer, over the protocol package's x402-exact-stellar-precondition.json, whose expected values that file's about
// names as stellar-sdk 13.0.0's output. The buyer's key is Ed25519 seed 05×32, the file's test value; Ed25519 signs
// deterministically, so its signatures are the file's.
import { createHash, createPrivateKey, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { AtrHash } from "@integraledger/lcp";
import { PASSPHRASE } from "@integraledger/lcp/stellar";
import { exactStellarPrecondition } from "@integraledger/lcp/x402-exact-stellar";
import type { PaymentRequired, PaymentRequirements } from "@integraledger/lcp/x402";
import { summaryOf } from "../src/summary.js";
import { NETWORK_IDS } from "../src/summary/stellar-precondition.js";
import type { Binding, SigningRequest } from "../src/index.js";
import { ABC, buildAndSign, H, toHex, vectors, type Pairing } from "./support.js";

const V = vectors<{
  fixed: { seller: string; buyer: string; asset: string; network: string; option: PaymentRequirements; resource: { url: string }; link: string };
  build: {
    simulatedXdr: string;
    currentLedger: number;
    expectExpiration: number;
    expectPreimageSha256: string;
    expectPayload: string;
    entrySignature: string;
    payloadSignature: string;
    expectPayment: Record<string, unknown>;
  };
}>("x402-exact-stellar-precondition.json");
const f = V.fixed;
const binding = exactStellarPrecondition as unknown as Binding;

/** The seller's document for the file's option, as the pairing's `advertise` places H and the file's link. */
function docOf(h: AtrHash): PaymentRequired {
  const base = { x402Version: 2, resource: f.resource, accepts: [f.option] } as PaymentRequired;
  const placed = exactStellarPrecondition.advertise(base, h, f.link, f.option);
  if ("refused" in placed) throw new Error(placed.code);
  return placed;
}

const seed = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from("05".repeat(32), "hex")]);
const buyerKey = createPrivateKey({ key: seed, format: "der", type: "pkcs8" });
const sha256 = (b: Uint8Array): Uint8Array => Uint8Array.from(createHash("sha256").update(b).digest());

const p: Pairing = {
  binding,
  doc: docOf(H),
  placed: docOf,
  account: `${f.network}:${f.buyer}`,
  inputs: { simulatedXdr: V.build.simulatedXdr, currentLedger: V.build.currentLedger },
  // The buyer's key signs the SHA-256 of the entry's preimage, and the payload raw.
  answer: async (r: SigningRequest) => {
    if (r.kind !== "stellar-precondition") throw new Error(r.kind);
    return { entry: toHex(Uint8Array.from(sign(null, sha256(r.preimage), buyerKey))), payload: toHex(Uint8Array.from(sign(null, r.payload, buyerKey))) };
  },
};

describe("x402/exact/stellar/precondition", () => {
  it("build: the preimage and payload are the file's; the buyer's two signatures complete its payment, and the gate pays it over a JSON ATR", async () => {
    const { signed, request } = await buildAndSign(p, async (r) => {
      if (r.kind !== "stellar-precondition") throw new Error(r.kind);
      expect([toHex(sha256(r.preimage)), toHex(r.payload)]).toEqual([`0x${V.build.expectPreimageSha256}`, V.build.expectPayload]);
      expect(await p.answer(r)).toEqual({ entry: `0x${V.build.entrySignature}`, payload: `0x${V.build.payloadSignature}` });
    });
    const { extensions: _echoed, ...payment } = signed as unknown as Record<string, unknown>;
    expect(payment).toEqual(V.build.expectPayment);

    // The approval summary (profile buyer-gate.md, rule 13): the transfer the file's simulated envelope holds,
    // transfer(buyer, seller, 10000000) on the file's asset, on testnet, the entry expiring at the file's ledger.
    expect(await summaryOf(binding.id, request, ABC)).toEqual({
      amount: f.option.amount,
      payees: [{ account: f.seller, amount: f.option.amount }],
      asset: f.asset,
      network: f.network,
      validity: { notBefore: null, notAfter: String(V.build.expectExpiration), unit: "ledger" },
      atr: ABC,
    });
  });

  it("the summary's network ids are the SHA-256 of the protocol package's Stellar passphrases", () => {
    const ids = Object.entries(PASSPHRASE).map(([network, phrase]) => [createHash("sha256").update(phrase).digest("hex"), network]);
    expect([...NETWORK_IDS.entries()].sort()).toEqual(ids.sort());
  });
});
