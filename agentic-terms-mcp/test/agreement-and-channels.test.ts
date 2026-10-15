// The agreement and the channel over MCP. A pairing whose payment is not itself a public proof gets its signing request
// from `atr_confirm` only with the agreement's receipt for H (the agreement step: the buyer pays the agreement URL and
// waits for its receipt before it starts the full payment), and `atr_confirm` carries the agreement URL in `chosen`.
// The agreement payment is approved like any other: `atr_agree`, given that `chosen`, returns the payment as `approve`
// and signs nothing, and pays it with the host's signer, or its agreement signer, only when called again with it as
// `approved`; `atr_transact` does the same in its own two calls. A channel opened for a compared ATR is held, its
// recorded charge stays within what was signed, and a later voucher's `maxClaimableAmount` is the recorded charge plus
// the option's amount (x402 batch-settlement's client rule). The ATR, its hash, the agreement's challenge and receipts,
// and the batch-settlement opening's signatures are the lcp vector files'.
import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Fetch, Signer, SigningRequest } from "@integraledger/terms";
import { BINDINGS, createBuyerServer } from "../src/index.js";
import { at, connect } from "./stdio.js";

const vectors = (name: string) =>
  JSON.parse(readFileSync(new URL(`../node_modules/@integraledger/lcp/vectors/${name}`, import.meta.url), "utf8"));
const B = vectors("buyer.json");
const E = vectors("x402-exact-eip155-erc7710.json");
const BV = vectors("x402-batch-settlement.json");
const A = Uint8Array.from(Buffer.from(B.fixed.A, "hex"));
const H: string = B.rows.find((r: { name: string }) => r.name === "B1").expect.h;
const LINK: string = B.fixed.link;
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
const LINK_ABC: string = vectors("mpp-challenge.json").fixed.link;

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

  it("atr_confirm without a receipt carries the agreement URL in chosen and returns no request", async () => {
    const c = connect({ fetch: seller() });
    const m = await call(c, "atr_confirm", { pairing, document: document(), account });
    await c.close();
    expect(at(m, "result.isError")).toBeUndefined();
    expect(at(m, "result.structuredContent.chosen.agreement")).toBe(AG.url);
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

  it("atr_agree returns the agreement payment to approve, signing nothing, then pays it once approved", async () => {
    const fetch = seller();
    const agreementSigner = recording(B.fixed.account, () => S);
    const c = connect({ fetch, agreementSigner });
    const confirmed = await call(c, "atr_confirm", { pairing, document: document(), account });
    const chosen = at(confirmed, "result.structuredContent.chosen");
    const atr = Buffer.from(A).toString("base64");
    const shown = await call(c, "atr_agree", { atr, chosen });
    expect(at(shown, "result.isError")).toBeUndefined();
    expect(at(shown, "result.structuredContent")).toEqual({
      atrHash: H,
      approve: { url: AG.url, option: AG.option, required: AG.required },
    });
    expect(agreementSigner.requests.length).toBe(0);
    expect(fetch.paid).toBe(0);
    const m = await call(c, "atr_agree", { atr, chosen, approved: at(shown, "result.structuredContent.approve") });
    await c.close();
    expect(at(m, "result.isError")).toBeUndefined();
    expect(at(m, "result.structuredContent.receipt")).toEqual(AG.receipt);
    expect(at(m, "result.structuredContent.atrHash")).toBe(H);
    expect(agreementSigner.requests.map((r) => r.kind)).toEqual(["eip712"]);
    expect(fetch.paid).toBe(1);
  });

  // `chosen` carries a `mac`, the server process's HMAC-SHA-256 over its other members, so `atr_agree` takes only the
  // agreement URL `atr_confirm` returned. A `chosen` with a member changed, added or removed is declined
  // `chosen-unverified` before anything is fetched or signed.
  it.each([
    ["chosen.agreement changed", (c: Record<string, unknown>) => ({ ...c, agreement: "https://pay.elsewhere.example/agreement" })],
    ["chosen.agreement removed", (c: Record<string, unknown>) => ({ ...c, agreement: undefined })],
    ["a member added", (c: Record<string, unknown>) => ({ ...c, extra: 1 })],
    ["the mac removed", (c: Record<string, unknown>) => ({ ...c, mac: undefined })],
    ["the mac changed", (c: Record<string, unknown>) => ({ ...c, mac: `0x${"00".repeat(32)}` })],
    ["a chosen built by hand", (c: Record<string, unknown>) => ({ pairing: c["pairing"], choice: {}, ref: "r", agreement: AG.url })],
  ])("atr_agree declines %s: chosen-unverified, with 0 requests and 0 signer calls", async (_, edit) => {
    const fetch = seller();
    let requests = 0;
    const counted = (async (url: string, init: { headers?: Record<string, string> }) => {
      requests++;
      return fetch(url, init as never);
    }) as unknown as Fetch;
    const agreementSigner = recording(B.fixed.account, () => S);
    const c = connect({ fetch: counted, agreementSigner });
    const confirmed = await call(c, "atr_confirm", { pairing, document: document(), account });
    const chosen = at(confirmed, "result.structuredContent.chosen") as Record<string, unknown>;
    expect(chosen["agreement"]).toBe(AG.url);
    expect(chosen["mac"]).toMatch(/^0x[0-9a-f]{64}$/);
    const before = requests;
    const edited = JSON.parse(JSON.stringify(edit(chosen)));
    const m = await call(c, "atr_agree", { atr: Buffer.from(A).toString("base64"), chosen: edited });
    await c.close();
    expect(at(m, "result.isError")).toBe(true);
    expect(at(m, "result.structuredContent.decline")).toEqual({
      code: "chosen-unverified",
      detail: "The chosen payment is not one this server process returned, unchanged. Pass chosen exactly as atr_confirm returned it.",
    });
    expect(requests - before).toBe(0);
    expect(agreementSigner.requests.length).toBe(0);
  });

  it("atr_agree takes chosen exactly as returned, in any member order", async () => {
    const fetch = seller();
    const agreementSigner = recording(B.fixed.account, () => S);
    const c = connect({ fetch, agreementSigner });
    const confirmed = await call(c, "atr_confirm", { pairing, document: document(), account });
    const chosen = at(confirmed, "result.structuredContent.chosen") as Record<string, unknown>;
    const reordered = Object.fromEntries(Object.entries(chosen).reverse());
    const m = await call(c, "atr_agree", { atr: Buffer.from(A).toString("base64"), chosen: reordered });
    await c.close();
    expect(at(m, "result.isError")).toBeUndefined();
    expect(at(m, "result.structuredContent.approve.url")).toBe(AG.url);
  });

  it("atr_agree with a verified chosen that names no agreement URL: offer-unreadable, and nothing is fetched", async () => {
    let requests = 0;
    const served = (async () => {
      requests++;
      return new Response(new Uint8Array(A), { status: 200 });
    }) as unknown as Fetch;
    const agreementSigner = recording(B.fixed.account, () => S);
    const c = connect({ fetch: served, agreementSigner });
    const confirmed = await call(c, "atr_confirm", { pairing: "x402/exact/eip155/eip3009", document: B.fixed.D, account: B.fixed.account });
    const chosen = at(confirmed, "result.structuredContent.chosen") as Record<string, unknown>;
    expect(chosen).not.toHaveProperty("agreement");
    const before = requests;
    const m = await call(c, "atr_agree", { atr: Buffer.from(A).toString("base64"), chosen });
    const loose = await call(c, "atr_agree", { atr: Buffer.from(A).toString("base64"), agreement: AG.url });
    await c.close();
    expect(at(m, "result.structuredContent.decline")).toEqual({
      code: "offer-unreadable",
      detail: "The chosen payment names no agreement URL.",
    });
    // A free `agreement` argument with no `chosen` fails the tool's input schema, as the SDK validates it.
    expect(at(loose, "result.isError")).toBe(true);
    expect(String(at(loose, "result.content.0.text"))).toContain("chosen");
    expect(requests - before).toBe(0);
    expect(agreementSigner.requests.length).toBe(0);
  });

  it("atr_finish takes the sealed chosen as returned", async () => {
    const c = connect({ fetch: seller() });
    const confirmed = await call(c, "atr_confirm", { pairing, document: document(), account, receipt: AG.receipt });
    const chosen = at(confirmed, "result.structuredContent.chosen") as Record<string, unknown>;
    expect(chosen["mac"]).toMatch(/^0x[0-9a-f]{64}$/);
    const m = await call(c, "atr_finish", {
      pairing,
      atr: Buffer.from(A).toString("base64"),
      chosen,
      signature: { delegationManager: E.fixed.option.payTo, permissionContext: "0x00", delegator: E.fixed.payer },
    });
    await c.close();
    expect(at(m, "result.isError")).toBeUndefined();
    expect(at(m, "result.structuredContent.atrHash")).toBe(H);
  });

  it("a cancelled atr_agree call ends the agreement exchange: the payment is not sent again", async () => {
    let paid = 0;
    let cancel: () => void = () => undefined;
    // Settles with the paid call's own result, which the server computes when its handler ends and does not send for a
    // cancelled call, or with nothing at a second payment, whichever comes first.
    let end: (result: unknown) => void = () => undefined;
    const ended = new Promise<unknown>((resolve) => (end = resolve));
    const fetch = (async (url: string, init: { headers?: Record<string, string> }) => {
      if (url === LINK) return new Response(new Uint8Array(A), { status: 200 });
      if (init.headers?.["PAYMENT-SIGNATURE"] === undefined) {
        return new Response(null, { status: 402, headers: { "payment-required": base64Json(AG.required) } });
      }
      paid++;
      if (paid === 1) cancel();
      else end(undefined);
      return new Response(null, { status: 202, headers: { "retry-after": "1" } });
    }) as unknown as Fetch;
    const agreementSigner = recording(B.fixed.account, () => S);
    const c = connect({ fetch, agreementSigner }, (options) => {
      const server = createBuyerServer(options);
      const project = server.server.projectCallToolResult.bind(server.server);
      server.server.projectCallToolResult = (result, schema) => {
        if (paid > 0) end(result);
        return project(result, schema);
      };
      return server;
    });
    const confirmed = await call(c, "atr_confirm", { pairing, document: document(), account });
    const chosen = at(confirmed, "result.structuredContent.chosen");
    const atr = Buffer.from(A).toString("base64");
    const shown = await call(c, "atr_agree", { atr, chosen });
    // The paid call is request 3 on this connection; the client cancels it once its payment has been sent, and gets no
    // answer to it.
    cancel = () => c.notify("notifications/cancelled", { requestId: 3, _meta: M });
    void call(c, "atr_agree", { atr, chosen, approved: at(shown, "result.structuredContent.approve") });
    const result = await ended;
    await c.close();
    expect(paid).toBe(1);
    expect(agreementSigner.requests.length).toBe(1);
    expect(at(result, "structuredContent.decline")).toEqual({
      code: "agreement-pending",
      detail: "The caller's signal ended the exchange after the agreement payment was sent.",
    });
  });

  it("atr_transact returns the agreement payment to approve, then pays it with the agreement signer and hands the full payment to the payment signer", async () => {
    const fetch = seller();
    const agreementSigner = recording(B.fixed.account, () => S);
    const signer = recording(account, () => {
      throw new Error("declined by the test wallet");
    });
    const c = connect({ fetch, signer, agreementSigner });
    const shown = await call(c, "atr_transact", { pairing, document: document() });
    expect(at(shown, "result.isError")).toBeUndefined();
    expect(at(shown, "result.structuredContent.approve")).toEqual({ url: AG.url, option: AG.option, required: AG.required });
    expect(at(shown, "result.structuredContent.atrHash")).toBe(H);
    expect(agreementSigner.requests.length + signer.requests.length).toBe(0);
    const approved = at(shown, "result.structuredContent.approve");
    const m = await call(c, "atr_transact", { pairing, document: document(), approved });
    await c.close();
    expect(agreementSigner.requests.map((r) => r.kind)).toEqual(["eip712"]);
    expect(signer.requests.map((r) => r.kind)).toEqual(["erc7710"]);
    expect(fetch.paid).toBe(1);
    expect(at(m, "result.structuredContent.decline.code")).toBe("signer-failed");
  });
});

// x402/batch-settlement/cloudflare's build is itself the payment (x402-batch-settlement.json EC1): once the agreement's
// receipt is passed, atr_confirm returns `request: null`, and atr_finish with `signature: null` returns the payment.
describe("x402/batch-settlement/cloudflare over MCP, whose build is the payment", () => {
  const pairing = "x402/batch-settlement/cloudflare";
  const option = BV.EC1.payload.accepted;
  const document = () => bindingOf(pairing).advertise({ x402Version: 2, resource: BV.fixed.resource, accepts: [option] }, H, LINK, option, AG.url);
  const account = "cloudflare:402:agent.example";

  it("atr_finish with signature null returns the payment, which atr_check reads H from", async () => {
    const c = connect({ fetch: seller() });
    const unpaid = await call(c, "atr_confirm", { pairing, document: document(), account });
    expect(at(unpaid, "result.structuredContent.chosen.agreement")).toBe(AG.url);
    expect(at(unpaid, "result.structuredContent")).not.toHaveProperty("request");
    const confirmed = await call(c, "atr_confirm", { pairing, document: document(), account, receipt: AG.receipt });
    expect(at(confirmed, "result.isError")).toBeUndefined();
    expect(at(confirmed, "result.structuredContent.request")).toBeNull();
    const atr = at(confirmed, "result.structuredContent.atr.base64");
    const m = await call(c, "atr_finish", { pairing, atr, chosen: at(confirmed, "result.structuredContent.chosen"), signature: null });
    const signed = at(m, "result.structuredContent.signed");
    const checked = await call(c, "atr_check", { pairing, atr, presented: signed });
    await c.close();
    expect(at(m, "result.isError")).toBeUndefined();
    expect(at(m, "result.structuredContent.atrHash")).toBe(H);
    expect(at(signed, "payload")).toEqual(BV.EC1.payload.payload);
    expect(at(signed, "accepted")).toEqual(option);
    expect(at(signed, "extensions.legalContext.info.value")).toBe(H);
    expect(at(checked, "result.structuredContent")).toEqual({ atrHash: H });
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

describe("a Solana channel's refund over MCP: x402/batch-settlement/solana", () => {
  const pairing = "x402/batch-settlement/solana";
  const BS = BV.fixed.svm;
  // The seller's settle failure that takes a Solana refund again (x402's scheme_batch_settlement_svm, the
  // PAYMENT-RESPONSE errorReason x402's reference client/refund.ts reads first).
  const RETRY = "invalid_batch_settlement_svm_receiver_binding_unavailable";
  const document = () =>
    bindingOf(pairing).advertise({ x402Version: 2, resource: BV.fixed.resource, accepts: [BS.option] }, H_ABC, LINK_ABC, BS.option);
  const account = `${BS.option.network}:${BS.payer}`;
  const inputs = { payerAuthorizer: BS.payer, openSlot: BS.openSlot, tokenProgram: BS.tokenProgram, recentBlockhash: BS.blockhash, deposit: BS.deposit };
  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const base58 = (b: Uint8Array): string => {
    let n = BigInt(`0x${Buffer.from(b).toString("hex")}`);
    let s = "";
    while (n > 0n) {
      s = ALPHABET[Number(n % 58n)] + s;
      n /= 58n;
    }
    return s;
  };
  // Each request answered with 64 bytes in base58; bound reads the memos and verifies no signature.
  const signer = () =>
    recording(account, (r) => (r.kind === "batch" ? r.requests.map((_, i) => base58(new Uint8Array(64).fill(i + 1))) : []));
  const atr = Buffer.from(ABC).toString("base64");

  async function held(c: ReturnType<typeof connect>): Promise<object> {
    const opened = await call(c, "atr_transact", { pairing, document: document(), inputs });
    expect(at(opened, "result.isError")).toBeUndefined();
    const signed = at(opened, "result.structuredContent.signed");
    const mac = at(opened, "result.structuredContent.mac");
    return at(await call(c, "atr_channel_open", { pairing, atr, signed, mac }), "result.structuredContent.hold") as object;
  }

  it("atr_channel_within passes refund.paymentResponse to within: its errorReason takes the refund again, with the request_close", async () => {
    const s = signer();
    const c = connect({ fetch: seller(), signer: s });
    const hold = await held(c);
    const first = await call(c, "atr_channel_within", { pairing, hold, document: document(), refund: {} });
    const again = await call(c, "atr_channel_within", {
      pairing,
      hold,
      document: document(),
      refund: { paymentResponse: { success: false, errorReason: RETRY } },
      inputs: { recentBlockhash: BS.blockhash },
    });
    await c.close();
    expect(at(first, "result.isError")).toBeUndefined();
    expect(at(first, "result.structuredContent.signed.payload")).not.toHaveProperty("transaction");
    expect(at(again, "result.isError")).toBeUndefined();
    expect(at(again, "result.structuredContent.signed.payload.type")).toBe("refund");
    expect(at(again, "result.structuredContent.signed.payload")).toHaveProperty("transaction");
    const last = s.requests.at(-1)!;
    expect(last.kind === "batch" && last.requests.map((r) => r.kind)).toEqual(["solana-message", "ed25519-raw"]);
  });

  it("atr_channel_within declines x402/input-malformed, and calls no signer, for a paymentResponse that is a string or whose errorReason is not a string", async () => {
    const s = signer();
    const c = connect({ fetch: seller(), signer: s });
    const hold = await held(c);
    const before = s.requests.length;
    const declines = [];
    for (const paymentResponse of [RETRY, { errorReason: 5 }, { errorReason: [RETRY] }]) {
      const m = await call(c, "atr_channel_within", {
        pairing,
        hold,
        document: document(),
        refund: { paymentResponse },
        inputs: { recentBlockhash: BS.blockhash },
      });
      declines.push([at(m, "result.structuredContent.decline.code"), at(m, "result.structuredContent.decline.detail")]);
    }
    await c.close();
    expect(declines).toEqual(Array(3).fill(["no-payable-option", "x402/input-malformed"]));
    expect(s.requests.length - before).toBe(0);
  });
});
