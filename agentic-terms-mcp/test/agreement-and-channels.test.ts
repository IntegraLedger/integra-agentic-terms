// The agreement and the channel over MCP. A pairing whose payment is not itself a public proof gets its signing request
// from `atr_confirm` only with the agreement's receipt for H (the agreement step: the buyer pays the agreement URL and
// waits for its receipt before it starts the full payment); `atr_agree` pays the agreement with the host's signer, or
// its agreement signer; `atr_transact` pays the agreement with the agreement signer. A channel opened for a compared
// ATR is held, its recorded charge stays within what was signed, and a later voucher's `maxClaimableAmount` is the
// recorded charge plus the option's amount (x402 batch-settlement's client rule). The ATR, its hash, the agreement's
// challenge and receipts, and the batch-settlement opening's signatures are the lcp vector files'.
import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Fetch, Signer, SigningRequest } from "@integraledger/terms";
import { BINDINGS } from "../src/index.js";
import { at, connect } from "./stdio.js";

const vectors = (name: string) =>
  JSON.parse(readFileSync(new URL(`../node_modules/@integraledger/lcp/vectors/${name}`, import.meta.url), "utf8"));
const B = vectors("buyer.json");
const E = vectors("x402-exact-eip155-erc7710.json");
const BV = vectors("x402-batch-settlement.json");
const A = Uint8Array.from(Buffer.from(B.fixed.A, "hex"));
const H: string = B.rows.find((r: { name: string }) => r.name === "B1").expect.h;
const LINK = `https://atr.seller.example/${H}`;
const AG = B.fixed.agreement;
const S: string = B.rows.find((r: { name: string }) => r.name === "B6").input.then.finish.signature;
const M = { "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {} };
const base64Json = (v: unknown): string => Buffer.from(JSON.stringify(v), "utf8").toString("base64");

type Advertises = { advertise(d: object, h: string, l: string, o: object, agreementUrl?: string): object };
const bindingOf = (id: string) => BINDINGS.find((b) => b.id === id) as unknown as Advertises;

type Recording = Signer & { requests: SigningRequest[] };
function recording(account: string, answer: (r: SigningRequest) => unknown): Recording {
  const s: Recording = {
    account,
    requests: [],
    async sign(r: SigningRequest) {
      s.requests.push(r);
      return answer(r) as never;
    },
  };
  return s;
}

/** `abc`, whose SHA-256 (FIPS 180-2) is the hash the batch-settlement vectors carry, and its link. */
const ABC = new TextEncoder().encode("abc");
const H_ABC = "0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const LINK_ABC = `https://atr.seller.example/${H_ABC}`;

/**
 * The ATR links serve A and `abc`; the agreement URL answers 402 with the vector challenge unpaid, and the receipt once
 * paid.
 */
function seller(): Fetch & { paid: number } {
  const f = (async (url: string, init: { headers?: Record<string, string> }) => {
    if (url === LINK) return new Response(new Uint8Array(A), { status: 200 });
    if (url === LINK_ABC) return new Response(new Uint8Array(ABC), { status: 200 });
    if (url === AG.url && init.headers?.["PAYMENT-SIGNATURE"] !== undefined) {
      f.paid++;
      return new Response(JSON.stringify(AG.receipt), { status: 200 });
    }
    if (url === AG.url) return new Response(null, { status: 402, headers: { "payment-required": base64Json(AG.required) } });
    return new Response(null, { status: 404 });
  }) as unknown as Fetch & { paid: number };
  f.paid = 0;
  return f;
}

const call = (c: ReturnType<typeof connect>, name: string, args: object) =>
  c.request("tools/call", { name, arguments: args, _meta: M });

describe("the agreement over MCP: x402/exact/eip155/erc7710, whose payment is not itself a public proof", () => {
  const pairing = "x402/exact/eip155/erc7710";
  const document = () =>
    bindingOf(pairing).advertise({ x402Version: 2, resource: E.fixed.resource, accepts: [E.fixed.option] }, H, LINK, E.fixed.option, AG.url);
  const account = `${E.fixed.option.network}:${E.fixed.payer}`;

  it("atr_confirm without a receipt names the agreement URL and returns no request", async () => {
    const c = connect({ fetch: seller() });
    const m = await call(c, "atr_confirm", { pairing, document: document(), account });
    await c.close();
    expect(at(m, "result.isError")).toBeUndefined();
    expect(at(m, "result.structuredContent.agreement")).toBe(AG.url);
    expect(at(m, "result.structuredContent.atrHash")).toBe(H);
    expect(at(m, "result.structuredContent")).not.toHaveProperty("request");
  });

  it("atr_confirm with the receipt for H returns the request; with a receipt for another hash it declines agreement-failed", async () => {
    const c = connect({ fetch: seller() });
    const ok = await call(c, "atr_confirm", { pairing, document: document(), account, receipt: AG.receipt });
    const other = await call(c, "atr_confirm", { pairing, document: document(), account, receipt: AG.receiptOtherHash });
    await c.close();
    expect(at(ok, "result.isError")).toBeUndefined();
    expect(at(ok, "result.structuredContent.request.kind")).toBe("erc7710");
    expect(at(ok, "result.structuredContent.request.salt")).toBe(H);
    expect(at(other, "result.isError")).toBe(true);
    expect(at(other, "result.structuredContent.decline.code")).toBe("agreement-failed");
    expect(at(other, "result.structuredContent")).not.toHaveProperty("request");
  });

  it("atr_agree pays the agreement URL with the agreement signer and returns the vector receipt", async () => {
    const fetch = seller();
    const agreementSigner = recording(B.fixed.account, () => S);
    const c = connect({ fetch, agreementSigner });
    const m = await call(c, "atr_agree", { atr: Buffer.from(A).toString("base64"), agreement: AG.url });
    await c.close();
    expect(at(m, "result.isError")).toBeUndefined();
    expect(at(m, "result.structuredContent.receipt")).toEqual(AG.receipt);
    expect(at(m, "result.structuredContent.atrHash")).toBe(H);
    expect(agreementSigner.requests.map((r) => r.kind)).toEqual(["eip712"]);
    expect(fetch.paid).toBe(1);
  });

  it("atr_transact pays the agreement with the agreement signer, and hands the full payment to the payment signer", async () => {
    const fetch = seller();
    const agreementSigner = recording(B.fixed.account, () => S);
    const signer = recording(account, () => {
      throw new Error("declined by the test wallet");
    });
    const c = connect({ fetch, signer, agreementSigner });
    const m = await call(c, "atr_transact", { pairing, document: document() });
    await c.close();
    expect(agreementSigner.requests.map((r) => r.kind)).toEqual(["eip712"]);
    expect(signer.requests.map((r) => r.kind)).toEqual(["erc7710"]);
    expect(fetch.paid).toBe(1);
    expect(at(m, "result.structuredContent.decline.code")).toBe("signer-failed");
  });
});

describe("a channel over MCP: x402/batch-settlement/eip155", () => {
  const pairing = "x402/batch-settlement/eip155";
  const EV = BV.fixed.evm;
  const document = () =>
    bindingOf(pairing).advertise({ x402Version: 2, resource: BV.fixed.resource, accepts: [EV.option] }, H_ABC, LINK_ABC, EV.option);
  const account = `eip155:84532:${EV.payer}`;
  const inputs = { payerAuthorizer: EV.payerAuthorizer, deposit: EV.deposit, authSalt: EV.authSalt };
  // The opening's two signatures: EB3's deposit authorization by the payer, EB2's first voucher by the payer authorizer.
  const opening = () => recording(account, (r) => (r.kind === "batch" && r.requests.length === 2 ? [BV.EB3.signature, BV.EB2.signature] : [BV.EB2.signature]));
  const atr = Buffer.from(ABC).toString("base64");

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(EV.now * 1000);
  });
  afterEach(() => vi.useRealTimers());

  it("atr_channel_open holds the opening with EB6's channel; atr_channel_record_charge stays within what was signed; atr_channel_within signs the next voucher at charge plus amount", async () => {
    const signer = opening();
    const c = connect({ fetch: seller(), signer });
    const opened = await call(c, "atr_transact", { pairing, document: document(), inputs });
    expect(at(opened, "result.isError")).toBeUndefined();
    const signed = at(opened, "result.structuredContent.signed");
    const mac = at(opened, "result.structuredContent.mac");

    const held = await call(c, "atr_channel_open", { pairing, atr, signed, mac });
    expect(at(held, "result.structuredContent.hold")).toMatchObject({
      pairing,
      network: BV.EB6.expectRef.network,
      channel: BV.EB6.expectRef.channel,
      h: H_ABC,
      atr,
      charged: "0",
      signedMax: BV.EB2.maxClaimableAmount,
    });
    const hold = at(held, "result.structuredContent.hold") as object;

    const over = await call(c, "atr_channel_record_charge", { hold, charged: String(BigInt(BV.EB2.maxClaimableAmount) + 1n) });
    expect(at(over, "result.structuredContent.decline.code")).toBe("offer-unreadable");
    const charged = await call(c, "atr_channel_record_charge", { hold, charged: BV.EB2.maxClaimableAmount });
    expect(at(charged, "result.structuredContent.hold.charged")).toBe(BV.EB2.maxClaimableAmount);

    const next = await call(c, "atr_channel_within", {
      pairing,
      hold: at(charged, "result.structuredContent.hold"),
      document: document(),
    });
    await c.close();
    expect(at(next, "result.isError")).toBeUndefined();
    const ceiling = String(BigInt(BV.EB2.maxClaimableAmount) + BigInt(EV.option.amount));
    expect(at(next, "result.structuredContent.signed.payload.voucher.maxClaimableAmount")).toBe(ceiling);
    expect(at(next, "result.structuredContent.hold.signedMax")).toBe(ceiling);
  });

  it("atr_channel_open refuses an opening against other bytes", async () => {
    const c = connect({ fetch: seller(), signer: opening() });
    const opened = await call(c, "atr_transact", { pairing, document: document(), inputs });
    const m = await call(c, "atr_channel_open", {
      pairing,
      atr: Buffer.from("abd").toString("base64"),
      signed: at(opened, "result.structuredContent.signed"),
      mac: at(opened, "result.structuredContent.mac"),
    });
    await c.close();
    expect(at(m, "result.isError")).toBe(true);
    expect(at(m, "result.structuredContent")).not.toHaveProperty("hold");
  });
});
