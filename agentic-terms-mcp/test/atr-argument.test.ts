// The `atr` argument of every tool that takes one is the ATR's bytes as padded standard base64 in its canonical form
// (RFC 4648 §3.5). Any other spelling fails the tool's input schema, as any malformed argument does, so the tool
// fetches and signs nothing for it. The ATR is the byte 0xff: its padded standard base64 is `/w==` (RFC 4648 §4), and
// its SHA-256 is node:crypto's. The offers, the agreement and the channel opening are the lcp vector files' (buyer.json,
// x402-exact-eip155-erc7710.json and x402-batch-settlement.json), each placed for that hash by its pairing's advertise.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Fetch, Signer, SigningRequest } from "@integraledger/terms";
import { BINDINGS } from "../src/index.js";
import { at, connect, type Message } from "./stdio.js";

const vectors = (name: string) =>
  JSON.parse(readFileSync(new URL(`../node_modules/@integraledger/lcp/vectors/${name}`, import.meta.url), "utf8"));
const B = vectors("buyer.json");
const E = vectors("x402-exact-eip155-erc7710.json");
const BV = vectors("x402-batch-settlement.json");
const M = { "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {} };
const AG = B.fixed.agreement;
const S: string = B.rows.find((r: { name: string }) => r.name === "B6").input.then.finish.signature;

const FF = Uint8Array.of(0xff);
const H = `0x${createHash("sha256").update(FF).digest("hex")}`;
const LINK = `https://atr.seller.example/${H}`;
/** 0xff in padded standard base64: `/` holds six one bits, and `w` two one bits and four zero pad bits. */
const CANONICAL = "/w==";

/** Every other spelling: none is the canonical padded standard base64 of any bytes. */
const SPELLINGS: [string, unknown][] = [
  ["a pad bit set past the last byte, /x==", "/x=="],
  ["a pad bit set past the last byte, one = form, //9=", "//9="],
  ["one = missing, /w=", "/w="],
  ["both = missing, /w", "/w"],
  ["the URL-safe alphabet (RFC 4648 §5), _w==", "_w=="],
  ["a trailing line feed", "/w==\n"],
  ["a space inside it", "/w =="],
  ["a character outside the alphabet, /w=*", "/w=*"],
  ["a number, 255", 255],
];

/** An EIP-3009 payment for buyer.json's document D whose nonce is `h`, signed with B6's signature S. */
function paymentFor(h: string): object {
  const option = B.fixed.D.accepts[0];
  const authorization = { from: B.fixed.account.split(":")[2], to: option.payTo, value: "10000", validAfter: "0", validBefore: "1790000060", nonce: h };
  return { x402Version: 2, accepted: option, payload: { signature: S, authorization } };
}

type Advertises = { advertise(d: object, h: string, l: string, o: object, agreementUrl?: string): object };
const bindingOf = (id: string) => BINDINGS.find((b) => b.id === id) as unknown as Advertises;

/** The agreement URL's payment request: buyer.json's agreement option placed for H and its link. */
const REQUIRED = bindingOf("x402/exact/eip155/eip3009").advertise(
  { x402Version: 2, resource: AG.required.resource, accepts: [AG.option] },
  H,
  LINK,
  AG.option,
);

type Counted = { fetches: number; signs: number };

/** The ATR link serves 0xff; the agreement URL answers 402 with REQUIRED. Every fetch is counted. */
function seller(n: Counted): Fetch {
  return (async (url: string) => {
    n.fetches++;
    if (url === LINK) return new Response(new Uint8Array(FF), { status: 200 });
    if (url === AG.url) {
      const header = Buffer.from(JSON.stringify(REQUIRED), "utf8").toString("base64");
      return new Response(null, { status: 402, headers: { "payment-required": header } });
    }
    return new Response(null, { status: 404 });
  }) as unknown as Fetch;
}

/** A signer that counts its calls and answers with `answer`. */
function signer(n: Counted, account: string, answer: (r: SigningRequest) => unknown): Signer {
  return {
    account,
    async sign(r: SigningRequest) {
      n.signs++;
      return answer(r) as never;
    },
  };
}

type Conn = ReturnType<typeof connect>;
const call = (c: Conn, name: string, args: object) => c.request("tools/call", { name, arguments: args, _meta: M });

type Tool = {
  /** A connection, and the tool's arguments other than `atr`, from the calls that come before it. */
  open(n: Counted): Promise<{ c: Conn; args: Record<string, unknown> }>;
  /** What the canonical spelling returns. */
  control(m: Message, n: Counted): void;
};

const TOOLS: Record<string, Tool> = {
  // An EIP-3009 payment whose nonce is H.
  atr_check: {
    async open(n) {
      return { c: connect({ fetch: seller(n) }), args: { pairing: "x402/exact/eip155/eip3009", presented: paymentFor(H) } };
    },
    control(m) {
      expect(at(m, "result.structuredContent")).toEqual({ atrHash: H });
    },
  },
  // buyer.json's document D advertising H, confirmed, then finished with B6's signature S.
  atr_finish: {
    async open(n) {
      const document = structuredClone(B.fixed.D);
      document.extensions.legalContext.info.value = H;
      document.extensions.legalContext.info.legalContextUrl = LINK;
      const c = connect({ fetch: seller(n) });
      const pairing = "x402/exact/eip155/eip3009";
      const confirmed = await call(c, "atr_confirm", { pairing, document, account: B.fixed.account });
      return { c, args: { pairing, chosen: at(confirmed, "result.structuredContent.chosen"), signature: S } };
    },
    control(m) {
      expect(at(m, "result.isError")).toBeUndefined();
      expect(at(m, "result.structuredContent.signed.payload.authorization.nonce")).toBe(H);
      expect(at(m, "result.structuredContent.signed.payload.signature")).toBe(S);
    },
  },
  // An x402/exact/eip155/erc7710 offer for H naming buyer.json's agreement URL; the agreement payment is shown to
  // approve, with nothing signed.
  atr_agree: {
    async open(n) {
      const pairing = "x402/exact/eip155/erc7710";
      const document = bindingOf(pairing).advertise(
        { x402Version: 2, resource: E.fixed.resource, accepts: [E.fixed.option] },
        H,
        LINK,
        E.fixed.option,
        AG.url,
      );
      const c = connect({ fetch: seller(n), agreementSigner: signer(n, B.fixed.account, () => S) });
      const confirmed = await call(c, "atr_confirm", { pairing, document, account: `${E.fixed.option.network}:${E.fixed.payer}` });
      return { c, args: { chosen: at(confirmed, "result.structuredContent.chosen") } };
    },
    control(m, n) {
      expect(at(m, "result.structuredContent")).toEqual({ atrHash: H, approve: { url: AG.url, option: AG.option, required: REQUIRED } });
      expect(n).toEqual({ fetches: 1, signs: 0 });
    },
  },
  // An x402/batch-settlement/eip155 opening for H, signed with EB3's and EB2's signatures.
  atr_channel_open: {
    async open(n) {
      const pairing = "x402/batch-settlement/eip155";
      const EV = BV.fixed.evm;
      const document = bindingOf(pairing).advertise({ x402Version: 2, resource: BV.fixed.resource, accepts: [EV.option] }, H, LINK, EV.option);
      const account = `eip155:84532:${EV.payer}`;
      const answer = (r: SigningRequest) =>
        r.kind === "batch" && r.requests.length === 2 ? [BV.EB3.signature, BV.EB2.signature] : [BV.EB2.signature];
      const c = connect({ fetch: seller(n), signer: signer(n, account, answer) });
      const inputs = { payerAuthorizer: EV.payerAuthorizer, deposit: EV.deposit, authSalt: EV.authSalt };
      const opened = await call(c, "atr_transact", { pairing, document, inputs });
      const signed = at(opened, "result.structuredContent.signed");
      return { c, args: { pairing, signed, mac: at(opened, "result.structuredContent.mac") } };
    },
    control(m) {
      expect(at(m, "result.structuredContent.atrHash")).toBe(H);
      expect(at(m, "result.structuredContent.hold.h")).toBe(H);
      expect(at(m, "result.structuredContent.hold.atr")).toBe(CANONICAL);
    },
  },
};

describe("the atr argument: padded standard base64 in its canonical form", { timeout: 60_000 }, () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(B.fixed.now * 1000);
  });
  afterEach(() => vi.useRealTimers());

  describe.each(Object.keys(TOOLS))("%s", (name) => {
    const tool = TOOLS[name]!;

    it(`${CANONICAL} is read as the byte 0xff`, async () => {
      const n: Counted = { fetches: 0, signs: 0 };
      const { c, args } = await tool.open(n);
      const before = { ...n };
      const m = await call(c, name, { ...args, atr: CANONICAL });
      await c.close();
      tool.control(m, { fetches: n.fetches - before.fetches, signs: n.signs - before.signs });
    });

    it.each(SPELLINGS)("%s fails the input schema, and nothing is fetched or signed", async (_, spelled) => {
      const n: Counted = { fetches: 0, signs: 0 };
      const { c, args } = await tool.open(n);
      const before = { ...n };
      const m = await call(c, name, { ...args, atr: spelled });
      await c.close();
      expect(at(m, "result.isError")).toBe(true);
      expect(at(m, "result")).not.toHaveProperty("structuredContent");
      expect(at(m, "result.content")).toEqual([
        { type: "text", text: expect.stringMatching(new RegExp(`^Input validation error: Invalid arguments for tool ${name}: atr: `)) },
      ]);
      expect({ fetches: n.fetches - before.fetches, signs: n.signs - before.signs }).toEqual({ fetches: 0, signs: 0 });
    });
  });
});

// RFC 4648 §10's test vectors, and every byte value in order (encoded by node:buffer): atr_confirm returns the ATR's
// bytes as `atr.base64`, that encoding, and atr_check, given that text back, reads the same bytes.
const EVERY_BYTE = Uint8Array.from({ length: 256 }, (_, i) => i);
const ROUND_TRIPS: [string, Uint8Array, string][] = [
  ...(
    [
      ["f", "Zg=="],
      ["fo", "Zm8="],
      ["foo", "Zm9v"],
      ["foob", "Zm9vYg=="],
      ["fooba", "Zm9vYmE="],
      ["foobar", "Zm9vYmFy"],
    ] as const
  ).map(([text, base64]): [string, Uint8Array, string] => [text, new TextEncoder().encode(text), base64]),
  ["every byte value", EVERY_BYTE, Buffer.from(EVERY_BYTE).toString("base64")],
];

describe("atr.base64 from atr_confirm, read back by atr_check", { timeout: 60_000 }, () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(B.fixed.now * 1000);
  });
  afterEach(() => vi.useRealTimers());

  it.each(ROUND_TRIPS)("%s", async (_, bytes, base64) => {
    const h = `0x${createHash("sha256").update(bytes).digest("hex")}`;
    const document = structuredClone(B.fixed.D);
    document.extensions.legalContext.info.value = h;
    document.extensions.legalContext.info.legalContextUrl = `https://atr.seller.example/${h}`;
    const c = connect({ fetch: (async () => new Response(new Uint8Array(bytes), { status: 200 })) as unknown as Fetch });
    const pairing = "x402/exact/eip155/eip3009";
    const confirmed = await call(c, "atr_confirm", { pairing, document, account: B.fixed.account });
    const returned = at(confirmed, "result.structuredContent.atr.base64");
    const checked = await call(c, "atr_check", { pairing, atr: returned, presented: paymentFor(h) });
    await c.close();
    expect(returned).toBe(base64);
    expect(at(checked, "result.structuredContent")).toEqual({ atrHash: h });
  });
});
