// The return after an agreement where the first response is MPP's, and the agreement resource's one 402 (terms'
// profile buyer-gate.md, rule 12; the protocol package's legal-context-return.md, rules 1 and 6, and mpp-charge.md,
// rule 6): that 402 carries x402's PAYMENT-REQUIRED and one WWW-Authenticate: Payment challenge per MPP agreement
// option. transact pays an x402 agreement option it finds there, and where the resource offers only MPP agreement
// challenges it returns them, signing nothing. Also the return of an x402 charge whose slot option lacks the invoice
// its read needs (x402/exact/lnbtc/payment-hash). Every input is a vector row of the protocol package: the agreement
// challenge is legal-context-return.json's serves row naming x402/0 and mpp/1 (mpp-challenge.json's C_E), its opaque
// naming mpp/1 alone, written by that file's recipe (base64url without padding of RFC 8785's form), since an ATR whose
// binding slot is mpp holds no x402/0 (lcp profile legal-context-return.md, rule 6); the charge
// mpp-charge-evm-transaction.json's B2 challenge as issued, placed as mpp-server-checks.json's place rows place them; the
// ATR buyer.json's A with mpp, listing the challenges, as its binding slot in place of x402; the link, agreement URL, its
// x402 payment request, receipt and payer key buyer.json's; the Lightning option and request x402-exact-lnbtc.json's,
// whose first response's agreement option, naming x402/0 alone, is that of legal-context-return.json's servesRefusals
// row refusing it against the file's card ATR, which holds no x402 slot; and the x402 agreement option buyer-gate.json's
// row "approved"'s.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it } from "vitest";
import type { TypedDataDefinition } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { BINDINGS } from "@integraledger/lcp";
import { place, tie as mppTie, type MppChallenge } from "@integraledger/lcp/mpp";
import { exactEip3009, requestCommitment, tie as x402Tie } from "@integraledger/lcp/x402";
import { transact, type Binding, type Fetch, type SigningRequest, type ToSign } from "../src/index.js";
import { counting, fromHex, vectors } from "./support.js";

// Vector files are read as loose JSON data; each use names the fields it reads.
type Loose = any;

const B: Loose = vectors("buyer.json");
const RET: Loose = vectors("legal-context-return.json");
const ET: Loose = vectors("mpp-charge-evm-transaction.json");
const LN: Loose = vectors("x402-exact-lnbtc.json");
const SC: Loose = vectors("mpp-server-checks.json");
const V: Loose = JSON.parse(readFileSync(new URL("../vectors/buyer-gate.json", import.meta.url), "utf8"));
const AG = B.fixed.agreement;
const LINK: string = B.fixed.link;
const payer = privateKeyToAccount(B.fixed.payerKey);
const APPROVED = (V.rows as Loose[]).find((r) => r.name === "approved");
const RESOURCE = { method: APPROVED.resourceRequest.method, target: APPROVED.resourceRequest.target, body: new TextEncoder().encode(APPROVED.resourceRequest.bodyUtf8) };

const bindingOf = (id: string): Binding => BINDINGS.find((b) => b.id === id) as unknown as Binding;
const sha256 = (b: Uint8Array): `0x${string}` => `0x${createHash("sha256").update(b).digest("hex")}`;
const realNow = Date.now;
afterEach(() => {
  Date.now = realNow;
});

/** A challenge as a WWW-Authenticate field value of the Payment scheme. */
const field = (c: MppChallenge): string =>
  "Payment " + Object.entries(c).map(([k, v]) => `${k}="${String(v)}"`).join(", ");

/**
 * The seller: the link serves `atr`; the agreement URL answers its unpaid request 402 with `required`, x402's payment
 * request for `h`, where given, and `challenges` as WWW-Authenticate, where given, and its paid request 200 with
 * buyer.json's receipt for `h`.
 */
function seller(atr: Uint8Array, h: string, required: unknown, challenges: MppChallenge[] | undefined): Fetch & { paid: number } {
  const f = (async (url: string, init: { headers?: Record<string, string> }) => {
    if (url === LINK) return new Response(new Uint8Array(atr), { status: 200 });
    if (url !== AG.url) return new Response(null, { status: 404 });
    if (init.headers?.["PAYMENT-SIGNATURE"] !== undefined) {
      f.paid++;
      return new Response(JSON.stringify({ ...AG.receipt, atrHash: h }), { status: 200 });
    }
    const headers = new Headers();
    if (required !== undefined) headers.set("payment-required", Buffer.from(JSON.stringify(required)).toString("base64"));
    for (const c of challenges ?? []) headers.append("www-authenticate", field(c));
    return new Response(null, { status: 402, headers });
  }) as unknown as Fetch & { paid: number };
  f.paid = 0;
  return f;
}

/** buyer.json's agreement payment request, advertising `h`. */
function requiredFor(h: string): Loose {
  const r = structuredClone(AG.required);
  r.extensions.legalContext.info.value = h;
  return r;
}

const C_E: MppChallenge = (RET.serves as Loose[]).find((r) => r.option.opaque !== undefined && r.expect?.includes("mpp/1")).option;
const MEMBERS: Record<string, string> = JSON.parse(Buffer.from(C_E.opaque as string, "base64url").toString("utf8"));
const AGREEMENT: MppChallenge = {
  ...C_E,
  opaque: Buffer.from(JSON.stringify(Object.fromEntries(Object.entries({ ...MEMBERS, legalContextServes: "mpp/1" }).sort(([a], [b]) => (a < b ? -1 : 1))))).toString("base64url"),
};
const { id: _id, opaque: _opaque, ...CHARGE } = (ET.buyer.rows as Loose[]).find((r) => r.name === "B2").input.doc[0];

/**
 * The ATR: buyer.json's A with mpp as its binding slot, the member after `atrVersion` and `id`, in place of x402, listing
 * `challenges`, as issued (the agreement challenge and the charge where none are given); and its H.
 */
function mppAtr(challenges: MppChallenge[] = [AGREEMENT, CHARGE as MppChallenge]): { bytes: Uint8Array; h: `0x${string}` } {
  const { atrVersion, id, x402: _x402, ...rest } = JSON.parse(new TextDecoder().decode(fromHex(B.fixed.A)));
  const bytes = new TextEncoder().encode(JSON.stringify({ atrVersion, id, mpp: mppTie(challenges)[1], ...rest }));
  return { bytes, h: sha256(bytes) };
}

/** `challenge` placed for `h` at `position` with buyer.json's link and agreement URL, for the act. */
function placed(challenge: MppChallenge, h: string, position: number, act: "payment" | "agreement"): MppChallenge {
  const out = place([challenge], h as never, LINK, challenge, position, act, AG.url);
  if (!Array.isArray(out)) throw new Error(JSON.stringify(out));
  return out[0]!;
}

async function run(doc: unknown, binding: Binding, fetch: Fetch, ceilings?: Record<string, "no-end">) {
  const signer = counting(B.fixed.account, async (r: SigningRequest) => payer.signTypedData((r as { typedData: unknown }).typedData as TypedDataDefinition));
  const asked: ToSign[] = [];
  const approver = (t: ToSign): boolean => {
    asked.push(t);
    return true;
  };
  const out = await transact(doc, binding, signer, fetch, {
    approver,
    resourceRequest: RESOURCE,
    ...(ceilings === undefined ? {} : { ceilings }),
  });
  return { out: out as Loose, asked: asked.map((a) => [a.act, a.pairing]), signed: signer.requests.length };
}

describe("an MPP first response offering the agreement alone", () => {
  const transaction = bindingOf("mpp/charge/evm/transaction");

  it("follows the agreement URL and pays the x402 agreement option there, returning the charge mpp/1", async () => {
    Date.now = () => B.fixed.now * 1000;
    const { bytes, h } = mppAtr();
    const agreement = placed(AGREEMENT, h, 0, "agreement");
    const fetch = seller(bytes, h, requiredFor(h), [agreement]);
    const { out, asked, signed } = await run([agreement], transaction, fetch);
    expect(out.decline).toBeUndefined();
    expect([out.charge, out.legalContext, out.agreement?.atrHash, out.agreementChallenges]).toEqual(["mpp/1", `lcp:sha256:${h}`, h, undefined]);
    expect([asked, signed, fetch.paid]).toEqual([[["agreement", "x402/exact/eip155/eip3009"]], 1, 1]);
  });

  it("returns the MPP agreement challenges where the agreement resource offers no x402 option, signing nothing", async () => {
    Date.now = () => B.fixed.now * 1000;
    const { bytes, h } = mppAtr();
    const agreement = placed(AGREEMENT, h, 0, "agreement");
    const fetch = seller(bytes, h, undefined, [agreement]);
    const { out, asked, signed } = await run([agreement], transaction, fetch);
    expect(out.decline).toBeUndefined();
    expect([out.charge, out.legalContext, out.agreement, out.agreementChallenges]).toEqual(["mpp/1", `lcp:sha256:${h}`, undefined, [agreement]]);
    expect([asked, signed, fetch.paid]).toEqual([[], 0, 0]);
  });
});

// The charge, an EIP-1559 transaction, signs no end: its ceiling is raised to "no-end" (the profile's rule 8), as its
// caller must to pay it at all.
describe("an MPP charge challenge naming the agreement URL", () => {
  it("returns the agreement resource's MPP agreement challenges where it offers no x402 option, signing nothing", async () => {
    Date.now = () => B.fixed.now * 1000;
    const bytes = fromHex(B.fixed.A);
    const h = sha256(bytes);
    const charge = placed(CHARGE as MppChallenge, h, 0, "payment");
    const agreement = placed(AGREEMENT, h, 1, "agreement");
    const fetch = seller(bytes, h, undefined, [agreement]);
    const { out, asked, signed } = await run([charge], bindingOf("mpp/charge/evm/transaction"), fetch, { "mpp/charge/evm/transaction": "no-end" });
    expect(out.decline).toBeUndefined();
    expect([out.agreementChallenges, out.h]).toEqual([[agreement], h]);
    expect([asked, signed, fetch.paid]).toEqual([[], 0, 0]);
  });
});

// lcp profile mpp-charge.md, rule 5: the ATR's mpp slot holds a Lightning charge as issued, without the invoice the
// seller's node writes after H, which the pairing's filter of a placed challenge requires. The charge is
// mpp-server-checks.json's Lightning challenge as issued, naming the network mainnet; the buyer's node is on
// x402-exact-lnbtc.json's mainnet network.
describe("an MPP Lightning charge whose slot challenge lacks the invoice the seller's node writes after H", () => {
  it("is chosen by the challenge's own checks on the account's network, and its agreement paid", async () => {
    Date.now = () => B.fixed.now * 1000;
    const issued: MppChallenge = (SC.unplaced.rows as Loose[]).find((r) => r.case.startsWith("mpp/charge/lightning:")).issued;
    const { bytes, h } = mppAtr([AGREEMENT, issued]);
    const agreement = placed(AGREEMENT, h, 0, "agreement");
    const fetch = seller(bytes, h, requiredFor(h), [agreement]);
    const node = counting(`${LN.fixed.offer.network}:${LN.fixed.payee}`, async () => {
      throw new Error("the node is not called before the charge is served");
    });
    const agreementSigner = counting(B.fixed.account, async (r: SigningRequest) => payer.signTypedData((r as { typedData: unknown }).typedData as TypedDataDefinition));
    const asked: ToSign[] = [];
    const out: Loose = await transact([agreement], bindingOf("mpp/charge/lightning"), node, fetch, {
      approver: (t) => (asked.push(t), true),
      resourceRequest: RESOURCE,
      agreementSigner,
    });
    expect(out.decline).toBeUndefined();
    expect([out.charge, out.legalContext, out.agreement?.atrHash]).toEqual(["mpp/1", `lcp:sha256:${h}`, h]);
    expect([asked.map((a) => [a.act, a.pairing]), node.requests.length, agreementSigner.requests.length, fetch.paid]).toEqual([
      [["agreement", "x402/exact/eip155/eip3009"]],
      0,
      1,
      1,
    ]);
  });
});

// lcp profile x402-exact-lnbtc.md, rule 3: the ATR's x402 slot holds the option without extra.invoice, which the
// seller's node writes after the agreement, and the pairing's read serves only an option with its invoice (rule 6).
describe("an x402 charge whose slot option lacks the invoice its read needs", () => {
  it("is chosen by the option's own checks, and its agreement asked of the approver", async () => {
    Date.now = () => LN.fixed.now * 1000;
    const commitment = await requestCommitment(RESOURCE);
    if ("refused" in commitment) throw new Error(commitment.code);
    const atr = JSON.parse(new TextDecoder().decode(fromHex(B.fixed.A)));
    atr.x402 = x402Tie([LN.fixed.offer], commitment)[1];
    const bytes = new TextEncoder().encode(JSON.stringify(atr));
    const h = sha256(bytes);
    const option = (RET.servesRefusals as Loose[]).find((r) => r.atr !== undefined && r.option?.extra?.legalContextServes?.join(" ") === "x402/0").option;
    const doc = exactEip3009.advertise({ x402Version: 2, resource: LN.fixed.resource, accepts: [option] } as never, h, LINK, option, AG.url);
    if ("refused" in doc) throw new Error(doc.code);
    const node = counting(`${LN.fixed.offer.network}:${LN.fixed.payee}`, async () => {
      throw new Error("the node is not called before the charge is served");
    });
    const agreementSigner = counting(B.fixed.account, async () => {
      throw new Error("the approver declines the agreement");
    });
    const asked: ToSign[] = [];
    const out = await transact(doc, bindingOf("x402/exact/lnbtc/payment-hash"), node, seller(bytes, h, undefined, undefined), {
      approver: (t) => (asked.push(t), false),
      resourceRequest: RESOURCE,
      agreementSigner,
    });
    expect("decline" in out && out.decline.code).toBe("not-approved");
    expect([asked.map((a) => [a.act, a.pairing]), node.requests.length, agreementSigner.requests.length]).toEqual([[["agreement", "x402/exact/eip155/eip3009"]], 0, 0]);
  });
});
