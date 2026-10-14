// B2, B6, B10 and B16 for the protocol-group pairings: card, AP2, UCP, ACP and ACK. Every expected request, answer
// and bound hash is the vector files' (card.json, ap2-checkout-mandate.json, ucp.json, acp-checkout.json,
// ack-payment-request.json). The card documents are the vectors' own and advertise H = SHA-256("abc"); the AP2, UCP and
// ACP documents advertise the vectors' own H, over the vectors' own ATR bytes.
import { createECDH, createHash, createPrivateKey, createPublicKey, sign as signWith, verify } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { Refusal } from "@integraledger/lcp";
import { binding as a2aBinding } from "@integraledger/lcp/a2a";
import { paymentRequest } from "@integraledger/lcp/ack";
import { delegated, undelegated } from "@integraledger/lcp/acp";
import { checkoutMandate, readMandate } from "@integraledger/lcp/ap2";
import { sellerReference, viAutonomous, viImmediate, visaTap } from "@integraledger/lcp/card";
import { ap2Mandate, bookingAp2Mandate, bookingUnsigned, unsigned } from "@integraledger/lcp/ucp";
import { check, confirm, finish, transact, type Binding, type Presented, type Signature, type SigningRequest } from "../src/index.js";
import { PIECES } from "../src/pairings/index.js";
import type { BuyerPiece, Chosen, Read } from "../src/types.js";
import { ABC, ABD, code, counting, H, isDeclined, isPublicProof, LINK, offered, receiptFor, serving, vectors, type Pairing } from "./support.js";

/* eslint-disable @typescript-eslint/no-explicit-any */
type V = any;
const CARD: V = vectors("card.json");
const AP2: V = vectors("ap2-checkout-mandate.json");
const UCP: V = vectors("ucp.json");
const ACP: V = vectors("acp-checkout.json");
const ACK: V = vectors("ack-payment-request.json");
const SD_JWT: V = vectors("sd-jwt.json");

const BUYER = "eip155:84532:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const enc = new TextEncoder();
const b64u = (s: string): string => Buffer.from(s, "utf8").toString("base64url");
const sha256b64u = (s: string): string => createHash("sha256").update(Buffer.from(s, "ascii")).digest("base64url");
const never = async (): Promise<never> => {
  throw new Error("the signer was called");
};

/**
 * B6 over the given ATR and its hash: `confirm` gives the request `inspect` checks; `finish` with the test signer's
 * answer returns a payment bound to `h`; `transact` signs once; `check` confirms the payment against the ATR and
 * declines it against other bytes.
 */
async function signsOver(
  p: Pairing,
  atr: Uint8Array,
  h: string,
  inspect: (r: SigningRequest) => void | Promise<void>,
): Promise<Presented> {
  const confirmed = await confirm(p.doc, offered(p.binding), p.account, serving(atr), p.inputs);
  if (isDeclined(confirmed)) throw new Error(`${confirmed.decline.code}: ${confirmed.decline.detail}`);
  expect(confirmed.h).toBe(h);
  expect(confirmed.bytes).toEqual(atr);
  if (confirmed.request === null) throw new Error("nothing to sign");
  await inspect(confirmed.request);

  const answer = await p.answer(confirmed.request);
  const done = await finish(atr, JSON.parse(JSON.stringify(confirmed.chosen)), answer, p.binding);
  if (isDeclined(done)) throw new Error(`${done.decline.code}: ${done.decline.detail}`);
  if ("next" in done) throw new Error("the piece asked for a second signature");
  expect(done.h).toBe(h);

  const signer = counting(p.account, p.answer);
  const whole = await transact(p.doc, offered(p.binding), signer, serving(atr), { inputs: p.inputs ?? {} });
  if (isDeclined(whole)) throw new Error(`${whole.decline.code}: ${whole.decline.detail}`);
  if ("approve" in whole) throw new Error("an agreement payment to approve");
  expect(signer.requests.length).toBe(1);
  expect(whole.signed).toEqual(done.signed);
  expect(whole.bytes).toEqual(atr);
  expect(whole.agreement).toEqual(isPublicProof(p.binding) ? undefined : receiptFor(h));

  expect(await check(atr, done.signed, p.binding)).toEqual({ h });
  expect(code(await check(ABD, done.signed, p.binding))).toBe("signed-not-bound");
  return done.signed;
}

/** B6 for a confirm-only pairing: `confirm` gives no request and the hash; `transact` gives no payment, unsigned. */
async function confirmsOnly(p: Pairing, atr: Uint8Array, h: string): Promise<Chosen> {
  const confirmed = await confirm(p.doc, offered(p.binding), p.account, serving(atr), p.inputs);
  if (isDeclined(confirmed)) throw new Error(`${confirmed.decline.code}: ${confirmed.decline.detail}`);
  expect(confirmed.request).toBeNull();
  expect(confirmed.h).toBe(h);
  expect(confirmed.bytes).toEqual(atr);
  expect(JSON.parse(JSON.stringify(confirmed.chosen))).toEqual(confirmed.chosen);

  const signer = counting(p.account, never);
  const whole = await transact(p.doc, offered(p.binding), signer, serving(atr), { inputs: p.inputs ?? {} });
  expect(whole).toEqual({ signed: null, bytes: atr, h, ...(isPublicProof(p.binding) ? {} : { agreement: receiptFor(h) }) });
  expect(signer.requests.length).toBe(0);
  return confirmed.chosen;
}

/** B10: a document whose link is `http://` is `offer-unreadable` with the pairing's code, before any fetch. */
async function httpLink(p: Pairing, httpDoc: unknown, detail: string): Promise<void> {
  const f = serving(ABC);
  const out = await confirm(httpDoc, p.binding, p.account, f, p.inputs);
  expect(out).toEqual({ decline: { code: "offer-unreadable", detail } });
  const signer = counting(p.account, never);
  expect(code(await transact(httpDoc, p.binding, signer, f, { inputs: p.inputs ?? {} }))).toBe("offer-unreadable");
  expect(f.calls).toBe(0);
  expect(signer.requests.length).toBe(0);
}

/** B16: each account is declined `no-payable-option` before any fetch. */
async function unpayable(p: Pairing, accounts: readonly string[]): Promise<void> {
  for (const account of accounts) {
    const f = serving(ABC);
    const out = await confirm(p.doc, p.binding, account, f, p.inputs);
    expect(code(out)).toBe("no-payable-option");
    expect(f.calls).toBe(0);
  }
}

/** Accounts that name no buyer: the pairings whose offer has no network take any CAIP-10 account. */
const UNNAMED = ["not-an-account", "eip155:84532", ""];

// ── card ──

const tapDoc = CARD.C2.build.doc;
const CJ: string = CARD.vi.CJ;
const [cjHeader, cjPayload, cjSignature] = CJ.split(".") as [string, string, string];
const httpLinkOf = (lc: Record<string, unknown>) => ({ ...lc, legalContextUrl: CARD.C1.httpLink.link });
const cjHttp = (() => {
  const payload = JSON.parse(Buffer.from(cjPayload, "base64url").toString("utf8"));
  payload.legalContext = httpLinkOf(payload.legalContext);
  return `${cjHeader}.${b64u(JSON.stringify(payload))}.${cjSignature}`;
})();
const tapHttp = { legalContext: httpLinkOf(tapDoc.legalContext) };

/** The agent's RFC 9421 signer, as the vectors publish it: sig2 over a base that carries the `lcp-hash` line. */
async function tapAnswer(r: SigningRequest) {
  expect(r).toEqual({ kind: "tap-field", ...CARD.C2.build.expect });
  if (r.kind !== "tap-field") throw new Error(r.kind);
  const base: string = CARD.C2.sig2Base;
  expect(base.split("\n")).toContain(`"lcp-hash": ${r.value}`);
  expect(createHash("sha256").update(base).digest("hex")).toBe(CARD.C2.expectSig2BaseSha256);
  const sig2 = /sig2=:([^:]+):/.exec(CARD.C2.request.signature)![1]!;
  const key = createPublicKey({ key: Buffer.from(CARD.C2.testKeyEd25519Spki, "base64"), format: "der", type: "spki" });
  expect(verify(null, Buffer.from(base), key, Buffer.from(sig2, "base64"))).toBe(true);
  return { signatureInput: CARD.C2.request.signatureInput, signature: CARD.C2.request.signature, lcpHash: CARD.C2.request.lcpHash };
}

const viRequest = { kind: "vi-checkout-mandate", ...CARD.C5.build.expect };
const card = {
  tap: { binding: visaTap, doc: tapDoc, account: BUYER, answer: tapAnswer } as Pairing,
  immediate: {
    binding: viImmediate,
    doc: CJ,
    account: BUYER,
    answer: async (r: SigningRequest) => {
      expect(r).toEqual(viRequest);
      return { l2: CARD.C6.bound.presented.l2 };
    },
  } as Pairing,
  autonomous: {
    binding: viAutonomous,
    doc: CJ,
    account: BUYER,
    answer: async (r: SigningRequest) => {
      expect(r).toEqual(viRequest);
      return { ...CARD.C7.bound.presented };
    },
  } as Pairing,
  sellerReference: { binding: sellerReference, doc: tapDoc, account: BUYER, answer: never } as Pairing,
};

describe("card: the pieces over the vectors' requests and answers", () => {
  const read: Read = { h: H, link: LINK };
  const piece = (id: string): BuyerPiece => PIECES.get(id)!;
  const through = async (p: Pairing, doc: unknown) => {
    const pc = piece(p.binding.id);
    const chosen = (pc.choose as (...a: unknown[]) => Chosen | Refusal)(read, BUYER, {}, 1790000000, "r".repeat(32), doc);
    if ("refused" in chosen) throw new Error(chosen.code);
    const revived = pc.choice(JSON.parse(JSON.stringify(chosen)), ABC);
    const u = await (p.binding as unknown as { build(d: unknown, h: string): Promise<unknown> }).build(revived, H);
    return { pc, chosen, u };
  };

  for (const p of [card.tap, card.immediate, card.autonomous]) {
    it(`${p.binding.id}: choose keeps the document; the request and answer complete a payment bound to H`, async () => {
      const { pc, chosen, u } = await through(p, p.doc);
      expect(chosen.choice).toEqual({ doc: p.doc });
      const request = pc.request(u);
      if (request === null || "refused" in request) throw new Error("no request");
      const signed = await pc.complete(u, await p.answer(request as SigningRequest), chosen);
      if ((signed as Refusal).refused === true) throw new Error((signed as Refusal).code);
      expect(await check(ABC, signed, p.binding)).toEqual({ h: H });
      expect(code(await check(ABD, signed, p.binding))).toBe("signed-not-bound");
    });
  }

  it("card/visa-tap: the payment carries the lcp-hash lines the signer sent: C2's repeated field is refused, an upper-case line is read, another hash is not bound", async () => {
    const { pc, chosen, u } = await through(card.tap, tapDoc);
    const answer = { signatureInput: CARD.C2.request.signatureInput, signature: CARD.C2.request.signature };
    const completed = async (lcpHash: unknown) => pc.complete(u, { ...answer, lcpHash } as Signature, chosen);
    const repeated = await completed(CARD.C2.repeatedField.lcpHash);
    expect(await visaTap.bound(repeated)).toEqual({ refused: true, code: CARD.C2.repeatedField.expect });
    expect(code(await check(ABC, repeated, card.tap.binding))).toBe("signed-not-bound");
    expect(await check(ABC, await completed(CARD.C2.upperCaseField.lcpHash), card.tap.binding)).toEqual({ h: CARD.C2.upperCaseField.expectBound });
    const other = await completed([`0x${"11".repeat(32)}`]);
    expect(code(await check(ABC, other, card.tap.binding))).toBe("signed-not-bound");
    expect(await pc.complete(u, answer as Signature, chosen)).toEqual({ refused: true, code: "card/signature-malformed" });

    const signer = counting(BUYER, async () => ({ ...answer, lcpHash: CARD.C2.repeatedField.lcpHash }));
    const out = await finish(ABC, chosen, await signer.sign((pc.request(u) as SigningRequest)), card.tap.binding);
    expect(isDeclined(out) && out.decline).toEqual({ code: "signed-not-bound", detail: "What was signed does not carry the hash of these bytes." });
  });

  it("card/visa-tap: the payment carries the one lcp-hash line the build gave, and the signer's two fields", async () => {
    const { pc, chosen, u } = await through(card.tap, tapDoc);
    const signed = await pc.complete(u, await tapAnswer(pc.request(u) as SigningRequest), chosen);
    expect(signed).toEqual({
      signatureInput: CARD.C2.request.signatureInput,
      signature: CARD.C2.request.signature,
      lcpHash: CARD.C2.request.lcpHash,
    });
  });

  it("card/seller-reference: build refuses card/no-signed-place, so the piece hands nothing to a signer", async () => {
    const { pc, u } = await through(card.sellerReference, tapDoc);
    expect(u).toEqual({ refused: true, code: CARD.C8.expect });
    expect("refused" in (pc.request(u) as object)).toBe(true);
  });

  it("an account that is not CAIP-10 is card/no-payable-option", () => {
    for (const account of UNNAMED) {
      const choose = piece("card/visa-tap").choose as (...a: unknown[]) => Chosen | Refusal;
      expect(choose(read, account, {}, 0, "r", tapDoc)).toEqual({
        refused: true,
        code: "card/no-payable-option",
      });
    }
  });

  it("B10: an http link is offer-unreadable, card/legal-context-malformed (card.json's agreed refusal), with no fetch", async () => {
    const row = CARD.agreedRefusals.rows.find((r: V) => r.case === "read with a legalContext whose link is not https");
    expect(row.expect).toBe("card/legal-context-malformed");
    await httpLink(card.tap, tapHttp, row.expect);
    await httpLink(card.sellerReference, tapHttp, row.expect);
    await httpLink(card.immediate, cjHttp, row.expect);
    await httpLink(card.autonomous, cjHttp, row.expect);
  });
});

describe("card: through the gate", () => {
  for (const p of [card.tap, card.immediate, card.autonomous, card.sellerReference]) {
    it(`${p.binding.id} B16: an account that names no buyer is no-payable-option, with no fetch`, () =>
      unpayable(p, UNNAMED));
  }
  it("card/visa-tap B6: the TAP field the vectors give, and sig2 over it, complete a payment bound to H", async () => {
    await signsOver(card.tap, ABC, H, () => undefined);
  });
  it("card/mastercard-vi/immediate B6: the checkout mandate the vectors give; the user's L2 is bound to H", async () => {
    await signsOver(card.immediate, ABC, H, (r) => expect(r).toEqual(viRequest));
  });
  it("card/mastercard-vi/autonomous B6: the same mandate; the agent's L3b chain is bound to H", async () => {
    await signsOver(card.autonomous, ABC, H, (r) => expect(r).toEqual(viRequest));
  });
  it("card/seller-reference B6: confirm-only; no request, no payment, the signer never called", async () => {
    expect(await confirmsOnly(card.sellerReference, ABC, H)).toMatchObject({ choice: { doc: tapDoc } });
  });
});

describe("card.json agreedRefusals: the rows the buyer's bound reads", () => {
  const presented = CARD.C7.bound.presented as { l1: string; l2: string; l3b: string };
  const USER = CARD.fixed.USER as { x: string; y: string };
  const AGENT = CARD.fixed.AGENT as { x: string; y: string };
  const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  /** The P-256 key derived as SHA-256(name) mod n, as @integraledger/lcp's card test derives its keys, as a JWK. */
  const recipeKey = (name: string) => {
    const d = BigInt(`0x${createHash("sha256").update(name, "ascii").digest("hex")}`) % N;
    const ecdh = createECDH("prime256v1");
    ecdh.setPrivateKey(Buffer.from(d.toString(16).padStart(64, "0"), "hex"));
    const point = ecdh.getPublicKey();
    const coordinate = (from: number) => point.subarray(from, from + 32).toString("base64url");
    return { kty: "EC", crv: "P-256", d: ecdh.getPrivateKey().toString("base64url"), x: coordinate(1), y: coordinate(33) };
  };
  /** A compact JWS over the ASCII signing input, ES256 under the key `name` derives. */
  const recipeSign = (name: string, signingInput: string): string => {
    const key = createPrivateKey({ key: recipeKey(name), format: "jwk" });
    const signature = signWith("sha256", Buffer.from(signingInput, "ascii"), { key, dsaEncoding: "ieee-p1363" });
    return `${signingInput}.${signature.toString("base64url")}`;
  };
  const segments = (layer: string) => layer.split("~")[0]!.split(".") as [string, string, string];
  const decoded = (segment: string): V => JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
  const encoded = (value: unknown): string => b64u(JSON.stringify(value));
  /** A layer from its first `~`: its disclosures and what follows them. */
  const rest = (layer: string): string => layer.slice(layer.indexOf("~"));
  /**
   * C7's presented chain with L1's `cnf.jwk` set to `user` and the `cnf.jwk` of L2's open checkout mandate to `agent`,
   * where given, and every sd_hash re-pointed: L2 signed again under USER and L3b under AGENT, so the chain differs
   * from C7's only in the keys it names.
   */
  const resigned = (keys: { user?: unknown; agent?: unknown }) => {
    const l1Payload = decoded(segments(presented.l1)[1]);
    if (keys.user !== undefined) l1Payload.cnf.jwk = keys.user;
    const [l1Head, , l1Signature] = presented.l1.slice(0, -1).split(".");
    const l1 = `${l1Head}.${encoded(l1Payload)}.${l1Signature}~`;
    const l2Payload = decoded(segments(presented.l2)[1]);
    let disclosures = presented.l2.split("~").slice(1, -1);
    if (keys.agent !== undefined) {
      const opened = disclosures.find((d) => decoded(d)[1].vct === "mandate.checkout.open.1")!;
      const [salt, value] = decoded(opened);
      const swapped = encoded([salt, { ...value, cnf: { jwk: keys.agent } }]);
      const [from, to] = [sha256b64u(opened), sha256b64u(swapped)];
      l2Payload._sd = l2Payload._sd.map((s: string) => (s === from ? to : s));
      l2Payload.delegate_payload = l2Payload.delegate_payload.map((e: { "...": string }) => ({ "...": e["..."] === from ? to : e["..."] }));
      disclosures = disclosures.map((d) => (d === opened ? swapped : d));
    }
    l2Payload.sd_hash = sha256b64u(l1);
    const l2 = `${recipeSign("lcp-test/user", `${segments(presented.l2)[0]}.${encoded(l2Payload)}`)}~${disclosures.map((d) => `${d}~`).join("")}`;
    const l3Payload = { ...decoded(segments(presented.l3b)[1]), sd_hash: sha256b64u(l2) };
    const l3b = `${recipeSign("lcp-test/agent", `${segments(presented.l3b)[0]}.${encoded(l3Payload)}`)}${rest(presented.l3b)}`;
    return { l1, l2, l3b };
  };
  const bound = (keys: { user?: unknown; agent?: unknown }) => viAutonomous.bound(resigned(keys) as never);
  const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  /**
   * `s`, base64url without padding, with its last character's lowest pad bit set: the same bytes in a form that is not
   * canonical (RFC 4648 section 3.5). Its length is 2 or 3 mod 4, so that the last character has pad bits.
   */
  const padBit = (s: string): string => {
    expect(s.length % 4).toBeGreaterThanOrEqual(2);
    return s.slice(0, -1) + ALPHABET[ALPHABET.indexOf(s.at(-1)!) | 1];
  };

  // The keys card.json's USER and AGENT name, so a chain re-signed under them as given is bound to H and each chain a
  // case below refuses differs from it in its key alone.
  it("the derived keys are card.json's USER and AGENT, and a chain re-signed under them as given is bound to H", async () => {
    for (const [name, jwk] of [["lcp-test/user", USER], ["lcp-test/agent", AGENT]] as const) {
      const { x, y } = recipeKey(name);
      expect({ x, y }).toEqual({ x: jwk.x, y: jwk.y });
    }
    expect(await bound({ user: USER })).toBe(CARD.C7.bound.expect);
    expect(await bound({ agent: AGENT })).toBe(CARD.C7.bound.expect);
  });

  /** Each case builds the inputs its row describes. */
  const cases: Record<string, () => Promise<unknown[]>> = {
    // RFC 7518 section 6.2.1.2-3: x and y are the full 32-byte P-256 coordinates, base64url-encoded, and RFC 7515
    // section 2 omits the padding.
    "VI Autonomous bound with an L1 or L2 cnf.jwk whose x or y is not unpadded base64url of 32 bytes": () => {
      const x = Buffer.from(USER.x, "base64url");
      const y = Buffer.from(USER.y, "base64url");
      return Promise.all([
        bound({ user: { ...USER, x: `${USER.x}=` } }),
        bound({ user: { ...USER, y: `${USER.y}=` } }),
        bound({ user: { ...USER, x: Buffer.concat([Buffer.of(0), x]).toString("base64url") } }),
        bound({ user: { ...USER, y: y.subarray(1).toString("base64url") } }),
        bound({ agent: { ...AGENT, x: `${AGENT.x}=` } }),
      ]);
    },
    "VI Autonomous bound with an L1 or L2 cnf.jwk whose x or y has a pad bit set in its last character": () =>
      Promise.all([
        bound({ user: { ...USER, x: padBit(USER.x) } }),
        bound({ user: { ...USER, y: padBit(USER.y) } }),
        bound({ agent: { ...AGENT, x: padBit(AGENT.x) } }),
      ]),
    "VI read or bound with a checkout_jwt or layer segment, or a disclosure, that has a pad bit set in its last character": async () => {
      const [ch, cp, cs] = CJ.split(".") as [string, string, string];
      const [h3, p3, s3] = segments(presented.l3b);
      const [h2, p2, s2] = segments(presented.l2);
      // L2's signature with a pad bit set: L3b's sd_hash names L2's text, so L3b is re-pointed and signed again.
      const l2 = `${h2}.${p2}.${padBit(s2)}${rest(presented.l2)}`;
      const l3b = `${recipeSign("lcp-test/agent", `${h3}.${encoded({ ...decoded(p3), sd_hash: sha256b64u(l2) })}`)}${rest(presented.l3b)}`;
      // L3b's checkout mandate disclosure with a pad bit set, listed by that text's digest, and L3b signed again.
      const disclosures = presented.l3b.split("~").slice(1, -1);
      const mandate = disclosures.find((d) => decoded(d)[1].vct === "mandate.checkout.1")!;
      const [from, to] = [sha256b64u(mandate), sha256b64u(padBit(mandate))];
      const swap = (d: string) => (d === from ? to : d);
      const swapped = decoded(p3);
      if (Array.isArray(swapped._sd)) swapped._sd = swapped._sd.map(swap);
      swapped.delegate_payload = swapped.delegate_payload.map((e: { "...": string }) => ({ "...": swap(e["..."]) }));
      const listed = disclosures.map((d) => `${d === mandate ? padBit(d) : d}~`).join("");
      const l3bDisclosure = `${recipeSign("lcp-test/agent", `${h3}.${encoded(swapped)}`)}~${listed}`;
      return [
        viImmediate.read(`${padBit(ch)}.${cp}.${cs}` as never),
        viImmediate.read(`${ch}.${padBit(cp)}.${cs}` as never),
        viImmediate.read(`${ch}.${cp}.${padBit(cs)}` as never),
        await viAutonomous.bound({ ...presented, l3b: `${h3}.${p3}.${padBit(s3)}${rest(presented.l3b)}` } as never),
        await viAutonomous.bound({ ...presented, l2, l3b } as never),
        await viAutonomous.bound({ ...presented, l3b: l3bDisclosure } as never),
      ];
    },
  };
  it.each(Object.keys(cases))("%s", async (c) => {
    const rows = (CARD.agreedRefusals.rows as V[]).filter((r) => r.case === c);
    expect(rows.length).toBeGreaterThan(0);
    const answers = await cases[c]!();
    expect(answers.length).toBeGreaterThan(0);
    for (const row of rows) for (const answer of answers) expect(answer).toEqual({ refused: true, code: row.expect });
  });
});

// ── AP2 ──

describe("ap2/checkout-mandate", () => {
  const F = AP2.fixed;
  const J: string = AP2.built.J;
  const p: Pairing = {
    binding: checkoutMandate,
    doc: J,
    account: BUYER,
    answer: async (r) => {
      expect(r).toEqual({
        kind: "ap2-checkout-mandate",
        content: { vct: AP2.V4.expectVct, checkout_jwt: J, checkout_hash: AP2.V4.expectCheckoutHash },
      });
      return AP2.built.M;
    },
  };

  it("the document is the merchant's checkout_jwt over the payload advertise gives", () => {
    const a = AP2.V2.advertise;
    const payload = JSON.parse(Buffer.from(J.split(".")[1]!, "base64url").toString("utf8"));
    expect(payload).toEqual(checkoutMandate.advertise(a.payload, a.h, a.link, a.offer));
  });
  it("B6: the closed mandate's claims are V4's; the vectors' mandate completes a payment bound to H", async () => {
    const signed = await signsOver(p, enc.encode(F.A), F.H, () => undefined);
    expect(signed).toEqual({ checkout_mandate: AP2.built.M, checkout_jwt: J });
    expect(await checkoutMandate.bound(signed as never)).toBe(AP2.V5.expectBound);
  });
  it("B10: an http link is offer-unreadable, ap2/legal-context-malformed (the read-http-link row), with no fetch", async () => {
    const row = AP2.implementation.find((r: V) => r.name === "read-http-link");
    expect(row.expect).toEqual({ refused: true, code: "ap2/legal-context-malformed" });
    await httpLink(p, row.input.doc, row.expect.code);
  });
  it("B16: an account that names no buyer is no-payable-option, with no fetch", () => unpayable(p, UNNAMED));

  // RFC 9901 section 7.1 step 4 rejects a digest met more than once. sd-jwt.json's C4 array-element disclosure (RFC 9901
  // section 4.2.4.2, "FR"), listed once in a mandate's _sd and once as {"...": digest}, resolves where the element sits;
  // listed twice in _sd, the mandate is malformed, as sd-jwt.json's C8 rows give for it.
  it("a digest of a two-element disclosure listed twice in the mandate's _sd is ap2/mandate-malformed; once, the mandate reads", async () => {
    const fr = SD_JWT.C4[1];
    expect(sha256b64u(fr.disclosure)).toBe(fr.expectDigest);
    const checkoutHash = sha256b64u("abc");
    const mandate = (listings: number) => {
      const payload = { vct: "mandate.checkout.1", checkout_hash: checkoutHash, nationalities: [{ "...": fr.expectDigest }], _sd: Array(listings).fill(fr.expectDigest), _sd_alg: "sha-256" };
      return `${b64u(JSON.stringify({ alg: "ES256" }))}.${b64u(JSON.stringify(payload))}.${"A".repeat(86)}~${fr.disclosure}~`;
    };
    expect(await readMandate(mandate(1))).toEqual({ checkout_hash: checkoutHash });
    expect(await readMandate(mandate(2))).toEqual({ refused: true, code: "ap2/mandate-malformed" });
  });
});

// ── UCP ──

describe("ucp", () => {
  const F = UCP.fixed;
  const atr = enc.encode(F.A);
  const signedBy = (c: V) => ({ ...c, ap2: { merchant_authorization: F.merchantAuthorization } });
  const checkout = signedBy(UCP.V2.expectCheckout);
  const booking = signedBy(UCP.V2b.expectBooking);

  /** The fixed recipe for J, D and M over a checkout the mandate discloses. */
  function mandateOver(c: V): { J: string; M: string } {
    const J = `${b64u(F.jwtHeader)}.${b64u(JSON.stringify(c))}.${F.signature}`;
    const D = b64u(F.disclosureTemplate.replace("<J>", J));
    const payload = (F.mandatePayload as string)
      .replace(UCP.V4.expectCheckoutHash, sha256b64u(J))
      .replace(UCP.V4.expectDisclosureDigest, sha256b64u(D));
    return { J, M: `${b64u(F.mandateHeader)}.${b64u(payload)}.${F.signature}~${D}~` };
  }
  const ucpHttp = (c: V) => ({
    ...c,
    links: c.links.map((l: V) => (l.type === "legal_context" ? { ...l, url: l.url.replace("https://", "http://") } : l)),
  });

  it("the recipe reproduces the vectors' J and M; the documents are advertise's", () => {
    expect(mandateOver(UCP.V2.expectCheckout)).toEqual({ J: UCP.built.J, M: UCP.built.M });
    const a = UCP.V2.advertise;
    expect(ap2Mandate.advertise(a.doc, a.h, a.link, a.offer)).toEqual(UCP.V2.expectCheckout);
    const b = UCP.V2b.advertise;
    expect(bookingAp2Mandate.advertise(UCP.V2b.B0, b.h, b.link, b.offer)).toEqual(UCP.V2b.expectBooking);
  });

  const mandates: [string, Binding, V, V][] = [
    ["ucp/checkout/ap2-mandate", ap2Mandate, checkout, UCP.V2.expectCheckout],
    ["ucp/booking/ap2-mandate", bookingAp2Mandate, booking, UCP.V2b.expectBooking],
  ];
  describe.each(mandates)("%s", (_id, binding, doc, payload) => {
    const { J, M } = mandateOver(payload);
    const p: Pairing = {
      binding,
      doc,
      account: BUYER,
      answer: async (r) => {
        expect(r).toEqual({ kind: "ucp-checkout", checkout: doc });
        return M;
      },
    };
    it("B6: the signed checkout goes to the issuer unchanged; its mandate completes a payment bound to H", async () => {
      const signed = await signsOver(p, atr, F.H, () => undefined);
      expect(signed).toEqual({ checkout_mandate: M, checkout_jwt: J });
      expect(await (binding as typeof ap2Mandate).bound(signed as never)).toBe(UCP.V4.expectBound);
    });
    it("B10: an http link is offer-unreadable, ucp/link-not-https, with no fetch", () =>
      httpLink(p, ucpHttp(doc), "ucp/link-not-https"));
    it("B16: an account that names no buyer is no-payable-option, with no fetch", () => unpayable(p, UNNAMED));
  });

  const confirmOnly: [string, Binding, V][] = [
    ["ucp/checkout/unsigned", unsigned, UCP.V2.expectCheckout],
    ["ucp/booking/unsigned", bookingUnsigned, UCP.V2b.expectBooking],
  ];
  describe.each(confirmOnly)("%s", (_id, binding, doc) => {
    const p: Pairing = { binding, doc, account: BUYER, answer: never };
    it("B6: confirm-only; build refuses V4's code, so no request, no payment, the signer never called", async () => {
      expect(await (binding as typeof unsigned).build({ checkout: doc }, F.H)).toEqual(UCP.V4.expectUnsignedBuild);
      await confirmsOnly(p, atr, F.H);
    });
    it("B10: an http link is offer-unreadable, ucp/link-not-https, with no fetch", () =>
      httpLink(p, ucpHttp(doc), "ucp/link-not-https"));
    it("B16: an account that names no buyer is no-payable-option, with no fetch", () => unpayable(p, UNNAMED));
  });
});

// ── ACP ──

describe("acp", () => {
  const F = ACP.fixed;
  const atr = enc.encode(F.A);
  const session = ACP.V2.expectSession;
  const { session: _s, ...values } = ACP.V4.choice;
  const acpHttp = {
    ...session,
    metadata: {
      ...session.metadata,
      legal_context: { ...session.metadata.legal_context, legal_context_url: F.L.replace("https://", "http://") },
    },
  };

  it("the session is advertise's", () => {
    const a = ACP.V2.advertise;
    expect(delegated.advertise(a.doc, a.h, a.link, a.offer)).toEqual(session);
  });

  describe("acp/checkout/delegated", () => {
    const p: Pairing = {
      binding: delegated,
      doc: session,
      account: BUYER,
      inputs: values,
      answer: async (r) => {
        expect(r).toEqual({ kind: "acp-allowance", allowance: ACP.V4.expectAllowance });
        if (r.kind !== "acp-allowance") throw new Error(r.kind);
        return { allowance: r.allowance };
      },
    };
    it("B6: the allowance is V4's, from the buyer's inputs; the signed request is bound to H", async () => {
      const signed = await signsOver(p, atr, F.H, () => undefined);
      expect(await delegated.bound(signed as never)).toBe(ACP.V4.expectBound);
    });
    it("a missing allowance input is no-payable-option, acp/input-missing, with no fetch", async () => {
      for (const k of Object.keys(values)) {
        const f = serving(atr);
        const { [k]: _gone, ...rest } = values;
        expect(await confirm(session, delegated, BUYER, f, rest)).toEqual({
          decline: { code: "no-payable-option", detail: "acp/input-missing" },
        });
        expect(f.calls).toBe(0);
      }
    });
    it("B10: an http link is offer-unreadable, acp/link-not-https, with no fetch", () =>
      httpLink(p, acpHttp, "acp/link-not-https"));
    it("B16: an account that names no buyer is no-payable-option, with no fetch", () => unpayable(p, UNNAMED));
  });

  describe("acp/checkout/undelegated", () => {
    const p: Pairing = { binding: undelegated, doc: ACP.V5.session, account: BUYER, answer: never };
    it("B6: confirm-only; build refuses V5's code, so no request, no payment, the signer never called", async () => {
      expect(await undelegated.build({} as never, F.H)).toEqual(ACP.V5.expectBuild);
      await confirmsOnly(p, atr, F.H);
    });
    it("B10: an http link is offer-unreadable, acp/link-not-https, with no fetch", () =>
      httpLink(p, acpHttp, "acp/link-not-https"));
    it("B16: an account that names no buyer is no-payable-option, with no fetch", () => unpayable(p, UNNAMED));
  });
});

// ── ACK ──

describe("ack/payment-request", () => {
  const O = ACK.fixed.O;
  const body = ACK.K2.body;
  const p: Pairing = { binding: paymentRequest, doc: body, account: `${O.network}:${BUYER.split(":")[2]}`, answer: never };
  const ackHttp = { ...body, legalContext: { ...body.legalContext, legalContextUrl: ACK.fixed.L.replace("https://", "http://") } };
  it("B6: confirm-only; the option on the account's network is K1's O; no request, no payment", async () => {
    expect(await paymentRequest.build({}, H)).toEqual(ACK.K5.expect);
    const chosen = await confirmsOnly(p, ABC, ACK.fixed.H);
    expect(chosen.choice).toEqual({ option: O });
  });
  it("B10: an http link is offer-unreadable, ack/legal-context-malformed (ack-payment-request.json's agreed refusal), with no fetch", async () => {
    const row = ACK.agreedRefusals.rows.find((r: V) => r.case === "read of a well-formed legalContext with an http link");
    expect(row.expect).toEqual({ refused: true, code: "ack/legal-context-malformed" });
    await httpLink(p, ackHttp, row.expect.code);
  });
  it("B16: an account on another network, or of another namespace, is no-payable-option, with no fetch", () =>
    unpayable(p, [`eip155:1:${BUYER.split(":")[2]}`, "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:x", ...UNNAMED]));
});

// ── The buyer rows the Python runners read ──

/** The vectors' `{"$repeat": [s, n]}` as s repeated n times, everywhere in v. */
function expand(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(expand);
  if (typeof v === "object" && v !== null) {
    const r = (v as { $repeat?: [string, number] }).$repeat;
    if (r !== undefined) return r[0].repeat(r[1]);
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, expand(x)]));
  }
  return v;
}

describe("the buyer halves over acp-checkout.json's agreedRefusals, ack-payment-request.json's reads and ucp.json's implementation rows", () => {
  const acpRows = (ACP.agreedRefusals.rows as V[]).filter((r) => !r.call.endsWith(".advertise"));
  it.each(acpRows.map((r) => [r.case, r] as const))("acp: %s", async (_case, row) => {
    const [name, fn] = row.call.split(".") as ["delegated" | "undelegated", "read" | "build" | "bound"];
    const out = await ({ delegated, undelegated }[name][fn] as (...a: unknown[]) => unknown)(...(expand(row.args) as unknown[]));
    const got = typeof out === "object" && out !== null && "allowance" in out && !("refused" in out) ? { allowance: out.allowance } : out;
    expect(got).toEqual(row.expect);
  });

  const ackRows = (ACK.agreedRefusals.rows as V[]).filter((r) => r.call === "paymentRequest.read");
  it.each(ackRows.map((r) => [r.case, r] as const))("ack: %s", (_case, row) => {
    expect(paymentRequest.read(expand(row.args[0]) as never)).toEqual(row.expect);
  });

  const byId: Record<string, V> = Object.fromEntries([ap2Mandate, bookingAp2Mandate, unsigned, bookingUnsigned].map((b) => [b.id, b]));
  const ucpRows = (UCP.implementation as V[]).filter((r) => r.fn !== "advertise");
  it.each(ucpRows.map((r) => [r.name, r] as const))("ucp: %s", async (_name, row) => {
    const given = expand(row.input) as V;
    const b = byId[row.pairing]!;
    if (row.fn === "read") {
      const r = b.read(given.doc) as V;
      expect("refused" in r ? r : { h: r.h, link: r.link }).toEqual(row.expect);
    } else {
      expect(row.fn).toBe("build");
      expect(await b.build({ checkout: given.checkout }, given.h)).toEqual(row.expect);
    }
  });
});

// ── A2A ──

describe("a2a", () => {
  it("is a carrier, not a pairing: its binding is the refusal a2a/no-signed-place, and the gate has no piece", async () => {
    expect(a2aBinding).toEqual({ refused: true, code: "a2a/no-signed-place" });
    expect([...PIECES.keys()].filter((k) => k.startsWith("a2a/"))).toEqual([]);
    const f = serving(ABC);
    expect(code(await confirm({}, a2aBinding as never, BUYER, f))).toBe("pairing-not-supported");
    expect(f.calls).toBe(0);
  });
});
