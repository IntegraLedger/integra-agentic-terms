// The agent tools' rows over raw JSON-RPC lines on stdio. The ATRs A and C, the document D, the signature S, the clock
// and the account are the gate's rows in @integraledger/lcp's vectors/buyer.json; the protocol values are MCP's.
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Fetch, Signer, SigningRequest } from "@integraledger/terms";
import { BINDINGS } from "../src/index.js";
import { at, connect, REQUEST, summaryPending, transacted, type Message } from "./stdio.js";
import { chargeUsdcGateway, evmAuthorization, usdcGatewaySalt, type GatewayPreimage } from "@integraledger/lcp/mpp";

const B = JSON.parse(
  readFileSync(new URL("../node_modules/@integraledger/lcp/vectors/buyer.json", import.meta.url), "utf8"),
);
/** A vector file of @integraledger/lcp. */
const vectors = (name: string) =>
  JSON.parse(readFileSync(new URL(`../node_modules/@integraledger/lcp/vectors/${name}`, import.meta.url), "utf8"));
/** SHA-256 of `abc` (FIPS 180-2), the hash the MPP vectors advertise. */
const H_ABC = "0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
/** The vectors' link and agreement URL for H_ABC, each a random token's path. */
const ABC_FIXED: { link: string; agreementUrl: string } = vectors("mpp-challenge.json").fixed;
const row = (name: string) => B.rows.find((r: { name: string }) => r.name === name);
const fromHex = (h: string) => Uint8Array.from(Buffer.from(h.replace(/^0x/, ""), "hex"));
const A = fromHex(B.fixed.A);
const C = fromHex(B.fixed.C);
const D = B.fixed.D;
const ACCOUNT: string = B.fixed.account;
const S: string = row("B6").input.then.finish.signature;
const M = { "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {} };

const serving = (bytes: Uint8Array): Fetch => async () => new Response(new Uint8Array(bytes), { status: 200 });

type Counting = Signer & { calls: number };
/** A signer that counts its calls and answers buyer.json's B6 signature S, the Anvil key's over D's request. */
function counting(): Counting {
  const s: Counting = {
    account: ACCOUNT,
    calls: 0,
    async sign(_request: SigningRequest) {
      s.calls++;
      return S;
    },
  };
  return s;
}

const call = (c: ReturnType<typeof connect>, name: string, args: object) =>
  c.request("tools/call", { name, arguments: args, _meta: M });
const names = (m: Message): string[] => (at(m, "result.tools") as { name: string }[]).map((t) => t.name).sort();

describe("the MCP server over stdio", () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(1_790_000_000_000);
  });
  afterEach(() => vi.useRealTimers());

  const results: Message[] = [];

  // The tools with no host signer: the gate's confirm, finish and check, and the channel steps that sign nothing.
  const UNSIGNED = ["atr_channel_open", "atr_channel_record_charge", "atr_check", "atr_confirm", "atr_finish"];

  it("a modern opening with no signer lists the tools that sign nothing", async () => {
    const c = connect({ fetch: serving(A) });
    expect(names(await c.request("tools/list", { _meta: M }))).toEqual(UNSIGNED);
    await c.close();
  });

  it("with a signer, atr_transact, atr_agree and atr_channel_within as well", async () => {
    const c = connect({ fetch: serving(A), signer: counting() });
    expect(names(await c.request("tools/list", { _meta: M }))).toEqual(
      [...UNSIGNED, "atr_agree", "atr_channel_within", "atr_transact"].sort(),
    );
    await c.close();
  });

  it("with an agreement signer only, atr_agree as well, and nothing that signs the payment itself", async () => {
    const c = connect({ fetch: serving(A), agreementSigner: counting() });
    expect(names(await c.request("tools/list", { _meta: M }))).toEqual([...UNSIGNED, "atr_agree"].sort());
    await c.close();
  });

  it("a modern request whose _meta lacks clientCapabilities is -32602", async () => {
    const c = connect({ fetch: serving(A) });
    const m = await c.request("tools/list", { _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28" } });
    expect(m.error?.code).toBe(-32602);
    await c.close();
  });

  it("a claimed version of 2099-01-01 is -32022 listing 2026-07-28", async () => {
    const c = connect({ fetch: serving(A) });
    const m = await c.request("tools/list", {
      _meta: { ...M, "io.modelcontextprotocol/protocolVersion": "2099-01-01" },
    });
    expect(m.error?.code).toBe(-32022);
    expect(at(m, "error.data.supported")).toContain("2026-07-28");
    await c.close();
  });

  it("a 2025-11-25 opening is answered with that version and the same tools", async () => {
    const c = connect({ fetch: serving(A) });
    const init = await c.request("initialize", {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "t", version: "1" },
    });
    expect(at(init, "result.protocolVersion")).toBe("2025-11-25");
    c.notify("notifications/initialized");
    expect(names(await c.request("tools/list"))).toEqual(UNSIGNED);
    await c.close();
  });

  it("plant: atr_confirm where the link serves C is hash-mismatch, with no request", async () => {
    const c = connect({ fetch: serving(C) });
    const m = await call(c, "atr_confirm", { pairing: "x402/exact/eip155/eip3009", document: D, account: ACCOUNT, resourceRequest: REQUEST });
    results.push(m);
    expect(at(m, "result.isError")).toBe(true);
    expect(at(m, "result.structuredContent.decline.code")).toBe("hash-mismatch");
    expect(at(m, "result.structuredContent")).not.toHaveProperty("request");
    await c.close();
  });

  it("plant: atr_transact where the link serves C never calls the signer", async () => {
    const signer = counting();
    const c = connect({ fetch: serving(C), signer });
    const m = await call(c, "atr_transact", { pairing: "x402/exact/eip155/eip3009", document: D, resourceRequest: REQUEST });
    results.push(m);
    expect(at(m, "result.isError")).toBe(true);
    expect(at(m, "result.structuredContent.decline.code")).toBe("hash-mismatch");
    expect(signer.calls).toBe(0);
    await c.close();
  });

  let chosen: object;
  it("atr_confirm where the link serves A", async () => {
    const c = connect({ fetch: serving(A) });
    const m = await call(c, "atr_confirm", { pairing: "x402/exact/eip155/eip3009", document: D, account: ACCOUNT, resourceRequest: REQUEST });
    results.push(m);
    const s = (k: string) => at(m, `result.structuredContent.${k}`);
    expect(s("atrHash")).toBe("0x8b1e122580ae3f6a8c3d36a24294e1260a87bde70f597279b973e39310072938");
    expect(s("atr.base64")).toBe(
      "eyJhdHJWZXJzaW9uIjoiMSIsImlkIjoiMGY4ZmFkNWItZDljYi00NjlmLWExNjUtNzA4Njc3Mjg5NTBlIiwieDQwMiI6eyJ6IjoxLjAsImEiOiJjYWZcdTAwZTkifSwic2VsbGVyIjp7Im5vdGUiOiJDYWbDqSDigJQgMzAgZMOtYXMg4pyTIn19",
    );
    expect(s("request.typedData.message.nonce")).toBe(s("atrHash"));
    expect(s("chosen.choice.accepted")).toEqual(D.accepts[0]);
    // The summary beside the request: the amount, payee, asset and network of D's option, and the ATR as `atr` is written.
    const option = D.accepts[0];
    expect(s("summary")).toMatchObject({ amount: option.amount, payees: [{ account: option.payTo, amount: option.amount }], asset: option.asset, network: option.network });
    expect(s("summary.atr")).toEqual(s("atr"));
    chosen = s("chosen") as object;
    await c.close();
  });

  it("atr_finish with A, the chosen atr_confirm returned and S; then atr_check with C and that signed", async () => {
    const c = connect({ fetch: serving(A) });
    const base64 = Buffer.from(A).toString("base64");
    const m = await call(c, "atr_finish", { pairing: "x402/exact/eip155/eip3009", atr: base64, chosen, signature: S });
    results.push(m);
    const signed = at(m, "result.structuredContent.signed");
    expect(at(signed, "payload.authorization.nonce")).toBe("0x8b1e122580ae3f6a8c3d36a24294e1260a87bde70f597279b973e39310072938");
    expect(at(signed, "payload.signature")).toBe(S);
    expect(at(m, "result.structuredContent")).not.toHaveProperty("mac");
    const checked = await call(c, "atr_check", {
      pairing: "x402/exact/eip155/eip3009",
      atr: Buffer.from(C).toString("base64"),
      presented: signed,
    });
    results.push(checked);
    expect(at(checked, "result.isError")).toBe(true);
    expect(at(checked, "result.structuredContent.decline.code")).toBe("signed-not-bound");
    await c.close();
  });

  it("atr_check over the byte 0xff and a payment carrying its hash", async () => {
    const h = "0xa8100ae6aa1940d0b663bb31cd466142ebbdbd5187131b92d93818987832eb89";
    const presented = {
      x402Version: 2,
      accepted: D.accepts[0],
      payload: {
        signature: S,
        authorization: { from: ACCOUNT.split(":")[2], to: D.accepts[0].payTo, value: "10000", validAfter: "0", validBefore: "1790000060", nonce: h },
      },
    };
    const c = connect({ fetch: serving(A) });
    const m = await call(c, "atr_check", { pairing: "x402/exact/eip155/eip3009", atr: "/w==", presented });
    results.push(m);
    expect(at(m, "result.structuredContent")).toEqual({ atrHash: h });
    await c.close();
  });

  it("atr_confirm over the byte 0xff advertised as its hash: the bytes are no JSON text, atr-malformed, with no request", async () => {
    const h = "0xa8100ae6aa1940d0b663bb31cd466142ebbdbd5187131b92d93818987832eb89";
    const doc = structuredClone(D);
    doc.extensions.legalContext.info.value = h;
    doc.extensions.legalContext.info.legalContextUrl = `https://atr.seller.example/${randomUUID()}`;
    const c = connect({ fetch: serving(Uint8Array.of(0xff)) });
    const m = await call(c, "atr_confirm", { pairing: "x402/exact/eip155/eip3009", document: doc, account: ACCOUNT, resourceRequest: REQUEST });
    results.push(m);
    expect(at(m, "result.isError")).toBe(true);
    expect(at(m, "result.structuredContent.decline.code")).toBe("atr-malformed");
    expect(at(m, "result.structuredContent")).not.toHaveProperty("request");
    expect(at(m, "result.structuredContent")).not.toHaveProperty("atr");
    await c.close();
  });

  // The MPP breadth pairings pay buyer.json's JSON ATR A, each challenge placed for H(A) by the pairing's own advertise.
  // While terms' SUMMARY_PENDING lists a pairing, the gate shows no summary of its request and declines it
  // summary-missing before any signer call; once it is filled, the pairing is paid through the tools in full.
  const HA: `0x${string}` = row("B1").expect.h;
  const LINK: string = B.fixed.link;

  it("a breadth pairing: MPP's EVM authorization, a list of challenges and the buyer's inputs, through confirm and finish", async () => {
    const V = vectors("mpp-challenge.json");
    const Z = vectors("mpp-charge-evm-authorization.json");
    const issued = {
      realm: V.fixed.realm,
      method: "evm",
      intent: "charge",
      request: Buffer.from(V.fixed.R_E, "utf8").toString("base64url"),
      expires: V.fixed.expires,
    };
    const document = evmAuthorization.advertise([issued] as never, HA, LINK, issued as never, 0);
    const c = connect({ fetch: serving(A) });
    const pairing = "mpp/charge/evm/authorization";
    const account = `eip155:84532:${Z.fixed.payer}`;
    const inputs = { tokenDomain: Z.fixed.tokenDomain };
    const confirmed = await call(c, "atr_confirm", { pairing, document, account, resourceRequest: REQUEST, inputs });
    if (summaryPending(pairing)) {
      expect(at(confirmed, "result.structuredContent.decline.code")).toBe("summary-missing");
      expect(at(confirmed, "result.structuredContent")).not.toHaveProperty("request");
      await c.close();
      return;
    }
    // MV5's nonce is the challenge's hash, whose id carries H: the vectors hold it for H(abc), which the pairing's own
    // rows check with no gate; validBefore and the payer's source do not depend on H.
    expect(at(confirmed, "result.structuredContent.request.typedData.message.validBefore")).toBe(Z.MV5.expectValidBefore);
    const finished = await call(c, "atr_finish", {
      pairing,
      atr: Buffer.from(A).toString("base64"),
      chosen: at(confirmed, "result.structuredContent.chosen"),
      signature: Z.MV5.expectSignature,
    });
    expect(at(finished, "result.structuredContent.atrHash")).toBe(HA);
    expect(at(finished, "result.structuredContent.signed.source")).toBe(Z.MV5.expectSource);
    await c.close();
  });

  it("usdc/gateway: the signing request carries the salt's preimage as JSON, and atr_transact's signer computes the salt", async () => {
    const G = vectors("mpp-charge-usdc-gateway.json");
    const f = G.fixed;
    const issued = {
      realm: f.realm,
      method: "usdc",
      intent: "charge",
      request: Buffer.from(G.M5.requestJson, "utf8").toString("base64url"),
      expires: f.expires,
    };
    // The pairing is at coverage none: its offer names the agreement URL, which answers the agreement's receipt for H in
    // buyer.json's receipt form, and the full payment is built once that receipt is in hand.
    const document = chargeUsdcGateway.advertise([issued] as never, HA, LINK, issued as never, 0, "payment", ABC_FIXED.agreementUrl);
    const receipt = { ...B.fixed.agreement.receipt, atrHash: HA };
    const seller: Fetch = async (url) =>
      url === ABC_FIXED.agreementUrl ? new Response(JSON.stringify(receipt), { status: 200 }) : new Response(new Uint8Array(A), { status: 200 });
    const pairing = "mpp/charge/usdc/gateway";
    // The build's inputs, as the vector file's B2 row gives the buyer; their ceiling is M5's maxBlockHeight.
    const inputs = G.buyer.rows.find((r: { name: string }) => r.name === "B2").input.inputs;
    const maxBlockHeight: string = G.ceiling.good.expectMaxBlockHeight;
    const c = connect({ fetch: seller });
    const confirmed = await call(c, "atr_confirm", { pairing, document, account: G.M5.source, resourceRequest: REQUEST, inputs, receipt });
    await c.close();

    const { recipient: _r, ...own } = G.M5.saltInput;
    const handed: unknown[] = [];
    const signer: Signer = {
      account: G.M5.source,
      async sign(request: SigningRequest) {
        handed.push(JSON.parse(JSON.stringify(request)));
        const given = (request as { preimage?: GatewayPreimage }).preimage;
        const salt = usdcGatewaySalt({ ...(given as GatewayPreimage), ...own });
        if (typeof salt !== "string") throw new Error(salt.code);
        const burnIntent = structuredClone(G.M5.payload.authorization.transfer.burnIntent);
        burnIntent.spec.salt = salt;
        const { authorization: _a, type: _t, ...routes } = G.M5.payload;
        return { source: G.M5.source, ...routes, burnIntent, signature: `0x${"11".repeat(65)}` };
      },
    };
    const t = connect({ fetch: seller, signer });
    const { m } = await transacted(t, { pairing, document, resourceRequest: REQUEST, inputs }, M);
    await t.close();
    if (summaryPending(pairing)) {
      expect(at(confirmed, "result.structuredContent.decline.code")).toBe("summary-missing");
      expect(at(m, "result.structuredContent.decline.code")).toBe("summary-missing");
      expect(handed).toEqual([]);
      return;
    }
    // The preimage's id is the challenge's as the pairing's advertise placed it for H(A).
    const placed = (document as unknown as { id: string }[])[0]!;
    const preimage = { id: placed.id, realm: f.realm, requestHash: G.M5.expectRequestHash, recipient: G.M5.saltInput.recipient };
    expect(at(confirmed, "result.structuredContent.atrHash")).toBe(HA);
    // The request also carries the challenge's request as issued, which the summary hashes to the preimage's requestHash.
    const request = { kind: "gateway-burn-intent", preimage, maxBlockHeight, challengeRequest: issued.request };
    expect(at(confirmed, "result.structuredContent.request")).toEqual(request);
    expect(handed).toEqual([request]);
    expect(at(m, "result.isError")).toBeUndefined();
    expect(at(m, "result.structuredContent.atrHash")).toBe(HA);
  });

  it("plant: atr_transact on a pairing with no public proof returns the agreement payment to approve, then each signing, then the receipt beside the payment", async () => {
    const E = vectors("x402-exact-eip155-erc7710.json");
    const AG = B.fixed.agreement;
    const H: string = row("B1").expect.h;
    const link: string = B.fixed.link;
    const pairing = "x402/exact/eip155/erc7710";
    const binding = BINDINGS.find((b) => b.id === pairing) as unknown as {
      advertise(d: object, h: string, l: string, o: object, agreementUrl: string): object;
    };
    const base = { x402Version: 2, resource: E.fixed.resource, accepts: [E.fixed.option] };
    const document = binding.advertise(base, H, link, E.fixed.option, AG.url);
    let agreementCalls = 0;
    const fetch: Fetch = async (url) => {
      if (url === link) return new Response(new Uint8Array(A), { status: 200 });
      if (url !== AG.url) return new Response(null, { status: 404 });
      agreementCalls++;
      if (agreementCalls === 1) {
        const required = Buffer.from(JSON.stringify(AG.required), "utf8").toString("base64");
        return new Response(null, { status: 402, headers: { "payment-required": required } });
      }
      return new Response(JSON.stringify(AG.receipt), { status: 200 });
    };
    const kinds: string[] = [];
    const signer: Signer = {
      account: ACCOUNT,
      async sign(request: SigningRequest) {
        kinds.push(request.kind);
        if (request.kind === "erc7710") return { delegationManager: E.fixed.option.payTo, permissionContext: "0x00", delegator: E.fixed.payer };
        return S;
      },
    };
    const c = connect({ fetch, signer });
    const args = { pairing, document, resourceRequest: REQUEST };
    const shown = await call(c, "atr_transact", args);
    expect(at(shown, "result.isError")).toBeUndefined();
    expect(at(shown, "result.structuredContent.approve.agreement.option")).toEqual(AG.option);
    expect(at(shown, "result.structuredContent")).not.toHaveProperty("signed");
    expect(kinds).toEqual([]);
    const approved = at(shown, "result.structuredContent.approve");
    // Approved, the agreement payment's signing is shown, then, once the agreement is recorded, the payment's.
    const { m, shown: signings } = await transacted(c, { ...args, approved }, M);
    expect(signings.map((s) => (s as { signings: { act: string }[] }).signings.map((x) => x.act))).toEqual([["agreement"], ["agreement", "payment"]]);
    expect(at(m, "result.isError")).toBeUndefined();
    expect(at(m, "result.structuredContent.atrHash")).toBe(H);
    expect(at(m, "result.structuredContent.agreement")).toEqual(AG.receipt);
    expect(at(m, "result.structuredContent.signed.payload.delegator")).toBe(E.fixed.payer);
    expect(kinds).toEqual(["eip712", "erc7710"]);
    const plain = await transacted(connect({ fetch: serving(A), signer: counting() }), { pairing: "x402/exact/eip155/eip3009", document: D, resourceRequest: REQUEST }, M);
    expect(at(plain.m, "result.structuredContent")).not.toHaveProperty("agreement");
    await c.close();
  });

  it("every result's text block is the JSON of its structured content", () => {
    expect(results.length).toBe(7);
    for (const m of results) {
      expect(at(m, "result.content.0.text")).toBe(JSON.stringify(at(m, "result.structuredContent")));
    }
  });
});

describe("the MCP server and the skill", () => {
  it("the skill names exactly the tools createBuyerServer can register", async () => {
    const text = readFileSync(
      new URL("../skills/confirming-the-atr-hash-before-paying/SKILL.md", import.meta.url),
      "utf8",
    );
    const named = [...new Set([...text.matchAll(/`(atr_[a-z_]+)`/g)].map((m) => m[1]))].sort();
    const c = connect({ fetch: serving(A), signer: counting() });
    expect(named).toEqual(names(await c.request("tools/list", { _meta: M })));
    await c.close();
  });
});
