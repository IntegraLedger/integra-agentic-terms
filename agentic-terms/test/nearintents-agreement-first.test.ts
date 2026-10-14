// mpp/charge/nearintents is confirm-only: the buyer's own wallet broadcasts the deposit and presents its transaction
// hash (draft-nearintents-charge-01, section 5.2), and nothing the buyer deposits carries the ATR hash. So the gate
// compares the hash, then pays the agreement the offer's agreement URL asks for and waits for its 200, and only then
// answers, with nothing signed: the protocol package's record of the pairing begins "Before this payment, the buyer
// signed and paid an agreement transaction carrying this ATR's hash". The deposit's own fields reach the wallet in the
// challenge `confirm` chose, as the seller issued it: `methodDetails.depositMemo`, "Deposit memo required by some origin
// chains (e.g., Stellar). Absent or null when not required." (draft-nearintents-charge-01, Method Details), is the
// seller's value or null, and the gate adds none. The ATR, the agreement challenge, its receipts, BA1's agreement nonce
// and the payer key are buyer.json's; the request is MPP's own example in mpp-charge-nearintents.json, placed by the
// protocol package's `advertise`.
import { describe, expect, it } from "vitest";
import type { TypedDataDefinition } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import type { AtrHash } from "@integraledger/lcp";
import { chargeNearIntents, type MppChallenge } from "@integraledger/lcp/mpp";
import { confirm, transact, type Binding, type Fetch, type Signer, type SigningRequest } from "../src/index.js";
import { isDeclined, vectors } from "./support.js";

// Vector files are read as loose JSON data; each use names the fields it reads.
type Loose = any;

const B = vectors<Loose>("buyer.json");
const N = vectors<Loose>("mpp-charge-nearintents.json");
const fromHex = (h: string): Uint8Array => Uint8Array.from(Buffer.from(h, "hex"));
const A = fromHex(B.fixed.A);
const C = fromHex(B.fixed.C);
const H: AtrHash = B.rows.find((r: Loose) => r.name === "B1").expect.h;
const LINK = `https://atr.seller.example/${H}`;
const AG = B.fixed.agreement;
const AGREEMENT_NONCE: string = B.rows.find((r: Loose) => r.name === "BA1").expect.agreementMessage.nonce;
const MD = N.fixed.request.methodDetails;
const ACCOUNT = `${MD.originNetwork}:${MD.refundTo}`;
const payer = privateKeyToAccount(B.fixed.payerKey);
const binding = chargeNearIntents as unknown as Binding;

const base64Json = (v: unknown): string => Buffer.from(JSON.stringify(v), "utf8").toString("base64");
const requestOf = (c: MppChallenge): Loose => JSON.parse(Buffer.from(String(c.request), "base64url").toString("utf8"));

/** The seller's document: MPP's example request with `depositMemo` as given, placed for H, LINK and the agreement URL. */
function documentWith(depositMemo: string | null): MppChallenge[] {
  const request = { ...N.fixed.request, methodDetails: { ...MD, depositMemo } };
  const issued = { ...N.challenge, request: Buffer.from(JSON.stringify(request), "utf8").toString("base64url") };
  const placed = chargeNearIntents.advertise([issued], H, LINK, issued, AG.url);
  if (!Array.isArray(placed)) throw new Error(JSON.stringify(placed));
  return placed;
}

/**
 * The seller, recording each request in `events`: the ATR link serves `atr`; the agreement URL answers 402 with the
 * agreement challenge when unpaid, and 200 with `receipt` once paid.
 */
function seller(events: string[], receipt: unknown, atr: Uint8Array = A): Fetch {
  return async (url, init) => {
    const paid = init.headers?.["PAYMENT-SIGNATURE"] !== undefined;
    events.push(url === LINK ? "atr fetched" : url === AG.url ? (paid ? "agreement paid" : "agreement asked") : url);
    if (url === LINK) return new Response(new Uint8Array(atr), { status: 200 });
    if (url !== AG.url) return new Response(null, { status: 404 });
    if (!paid) return new Response(null, { status: 402, headers: { "payment-required": base64Json(AG.required) } });
    return new Response(JSON.stringify(receipt), { status: 200 });
  };
}

/** The buyer's wallet on the deposit's origin network: the deposit is its own, so the gate never hands it a request. */
function wallet(events: string[]): Signer {
  return {
    account: ACCOUNT,
    async sign() {
      events.push("wallet signed");
      throw new Error("the deposit is the wallet's own");
    },
  };
}

/** The agreement signer, over buyer.json's payer key, recording each request it signs. */
function agreementSigner(events: string[], signed: SigningRequest[]): Signer {
  return {
    account: B.fixed.account,
    async sign(r: SigningRequest) {
      events.push("agreement signed");
      signed.push(r);
      if (r.kind !== "eip712") throw new Error(r.kind);
      return payer.signTypedData(r.typedData as unknown as TypedDataDefinition);
    },
  };
}

describe("mpp/charge/nearintents: the gate compares the hash and pays the agreement before it answers", () => {
  it("the first call returns the agreement payment to approve; the second pays it, then answers with nothing signed", async () => {
    const doc = documentWith(null);
    const events: string[] = [];
    const signed: SigningRequest[] = [];
    const options = { agreementSigner: agreementSigner(events, signed) };

    const first = await transact(doc, binding, wallet(events), seller(events, AG.receipt), options);
    if (!("approve" in first)) throw new Error(JSON.stringify(first));
    expect(first).not.toHaveProperty("signed");
    expect(events).toEqual(["atr fetched", "agreement asked"]);

    events.length = 0;
    const second = await transact(doc, binding, wallet(events), seller(events, AG.receipt), { ...options, approved: first.approve });
    expect(events).toEqual(["atr fetched", "agreement signed", "agreement paid"]);
    expect(second).toEqual({ signed: null, bytes: A, h: H, agreement: AG.receipt });
    expect(signed.map((r) => (r as Loose).typedData.message.nonce)).toEqual([AGREEMENT_NONCE]);
  });

  it("an ATR that does not hash to the advertised H is declined before the agreement URL is asked; nothing is signed", async () => {
    const events: string[] = [];
    const out = await transact(documentWith(null), binding, wallet(events), seller(events, AG.receipt, C), {
      agreementSigner: agreementSigner(events, []),
    });
    expect(isDeclined(out) && out.decline.code).toBe("hash-mismatch");
    expect(events).toEqual(["atr fetched"]);
  });

  it("an agreement receipt for another hash is declined: the gate never gives its answer with nothing signed", async () => {
    const doc = documentWith(null);
    const events: string[] = [];
    const options = { agreementSigner: agreementSigner(events, []) };
    const first = await transact(doc, binding, wallet(events), seller(events, AG.receiptOtherHash), options);
    if (!("approve" in first)) throw new Error(JSON.stringify(first));
    const out = await transact(doc, binding, wallet(events), seller(events, AG.receiptOtherHash), { ...options, approved: first.approve });
    expect(isDeclined(out) && out.decline.code).toBe("agreement-failed");
    expect(out).not.toHaveProperty("signed");
    expect(events).not.toContain("wallet signed");
  });
});

describe("mpp/charge/nearintents: the challenge the wallet deposits on is the seller's, depositMemo as issued", () => {
  it.each([
    ["a depositMemo", "4120"],
    ["a null depositMemo", null],
  ])("%s reaches the wallet unchanged, and the gate adds nothing", async (_name, depositMemo) => {
    const doc = documentWith(depositMemo);
    const issued = structuredClone(doc);
    const confirmed = await confirm(doc, binding, ACCOUNT, seller([], AG.receipt));
    if (isDeclined(confirmed)) throw new Error(confirmed.decline.detail);
    expect(confirmed.request).toBeNull();
    expect(confirmed.chosen.choice).toEqual({ challenge: issued[0] });
    const challenge = (confirmed.chosen.choice as Loose).challenge as MppChallenge;
    expect(challenge.request).toBe(issued[0]!.request);
    expect(requestOf(challenge).methodDetails.depositMemo).toBe(depositMemo);

    const events: string[] = [];
    const options = { agreementSigner: agreementSigner(events, []) };
    const first = await transact(doc, binding, wallet(events), seller(events, AG.receipt), options);
    if (!("approve" in first)) throw new Error(JSON.stringify(first));
    const second = await transact(doc, binding, wallet(events), seller(events, AG.receipt), { ...options, approved: first.approve });
    expect(second).toMatchObject({ signed: null, h: H });
    expect(doc).toEqual(issued);
  });
});
