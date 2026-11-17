// B2, B6, B10 and B16 for MPP's charges on Solana, XRPL and NEAR Intents, and its session on XRPL. Expected requests,
// bytes, digests, signatures and credentials are the vector files'; the keys come from the seeds and keys those files
// publish as test values.
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import type { AtrHash } from "@integraledger/lcp";
import { describe, expect, it } from "vitest";
import {
  chargeNearIntents,
  chargeSolana,
  chargeXrpl,
  sessionXrpl,
  type MppChallenge,
  type MppCredential,
} from "@integraledger/lcp/mpp";
import { decodeSvmTx } from "@integraledger/lcp/svm";
import { check, confirm, openChannel, transact, within, type Binding, type SigningRequest } from "../src/index.js";
import {
  A as ATR_A,
  ABC,
  ABD,
  buildAndSign,
  code,
  counting,
  fromHex,
  H,
  HA,
  isDeclined,
  LINK,
  offered,
  piecePay,
  receiptFor,
  serving,
  toHex,
  vectors,
  type Pairing,
} from "./support.js";

import { CONFIRMING, GATE } from "./support.js";
// ── helpers ──────────────────────────────────────────────────────────────────────────────────────────────────────

// Vector files are read as loose JSON data; each row names the fields it uses.
type Loose = any;

const b64u = (s: string) => Buffer.from(s, "utf8").toString("base64url");
const request = (r: SigningRequest) => r as unknown as Record<string, Loose>;

/** The seller's challenges for one issued challenge, as the pairing's `advertise` places H and the link. */
function docOf(binding: Binding, c: MppChallenge, h: AtrHash = H): MppChallenge[] {
  const placed = (binding as unknown as { advertise(d: unknown, h: string, l: string, o: unknown, p: number): unknown }).advertise(
    [c],
    h,
    LINK,
    c,
    0,
  );
  if (!Array.isArray(placed)) throw new Error(JSON.stringify(placed));
  return placed as MppChallenge[];
}

/** The document with each challenge's legal-context link as `http://`. */
function httpDoc(doc: MppChallenge[]): MppChallenge[] {
  return doc.map((c) => {
    const map = JSON.parse(Buffer.from(c.opaque!, "base64url").toString("utf8")) as Record<string, string>;
    const http = { ...map, legalContextUrl: map["legalContextUrl"]!.replace("https://", "http://") };
    return { ...c, opaque: b64u(JSON.stringify(http)) };
  });
}

/** An Ed25519 key from its 32-byte seed. */
function ed25519(seed: Uint8Array) {
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seed)]);
  const privateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  const jwk = createPublicKey(privateKey).export({ format: "jwk" }) as { x: string };
  return {
    publicKey: Uint8Array.from(Buffer.from(jwk.x, "base64url")),
    sign: (m: Uint8Array) => Uint8Array.from(sign(null, m, privateKey)),
  };
}

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58(b: Uint8Array): string {
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  let s = "";
  while (n > 0n) {
    s = B58[Number(n % 58n)] + s;
    n /= 58n;
  }
  for (const x of b) {
    if (x !== 0) break;
    s = "1" + s;
  }
  return s;
}

/** A v0 message's fee payer and instructions: program, accounts with their signer and writable flags, and data. */
function decompile(message: Uint8Array) {
  const required = message[1]!;
  const wire = new Uint8Array(1 + 64 * required + message.length);
  wire[0] = required;
  wire.set(message, 1 + 64 * required);
  const tx = decodeSvmTx(wire);
  if ("refused" in tx) throw new Error(tx.code);
  const [signers, readonlySigned, readonlyUnsigned] = [message[1]!, message[2]!, message[3]!];
  const n = tx.keys.length;
  const flags = (i: number) => ({
    signer: i < signers,
    writable: i < signers ? i < signers - readonlySigned : i < n - readonlyUnsigned,
  });
  return {
    feePayer: base58(tx.keys[0]!),
    instructions: tx.instructions.map((ix) => ({
      program: base58(tx.keys[ix.program]!),
      accounts: ix.accounts.map((a) => ({ address: base58(tx.keys[a]!), ...flags(a) })),
      data: Buffer.from(ix.data).toString("hex"),
    })),
  };
}

/** B10 and B16 for a pairing: an http link is declined before any fetch; other accounts have no payable option. */
function refusals(p: Pairing, others: readonly string[]) {
  it("B10: an http link is offer-unreadable, mpp/link-not-https, before any fetch", async () => {
    const fetch = serving(ABC);
    const out = await confirm(httpDoc(p.doc as MppChallenge[]), p.binding, p.account, fetch, { ...CONFIRMING, inputs: p.inputs });
    expect(out).toEqual({ decline: { code: "offer-unreadable", detail: "mpp/link-not-https" } });
    expect(fetch.calls).toBe(0);
  });
  it("B16: an account of another namespace, and one on another network, have no payable option; nothing is fetched", async () => {
    for (const account of others) {
      const fetch = serving(ABC);
      expect(code(await confirm(p.doc, p.binding, account, fetch, { ...CONFIRMING, inputs: p.inputs }))).toBe("no-payable-option");
      expect(fetch.calls).toBe(0);
    }
  });
}

const EVM_ACCOUNT = "eip155:84532:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const SOLANA_DEVNET = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
const SOLANA_MAINNET = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";

// ── mpp/charge/solana ────────────────────────────────────────────────────────────────────────────────────────────

describe("mpp/charge/solana", () => {
  const V = vectors<Loose>("mpp-charge-solana.json");
  const X = vectors<Loose>("x402-exact-solana.json");
  const payer = ed25519(fromHex(X.fixed.payerSeed));
  const p: Pairing = {
    binding: chargeSolana,
    doc: docOf(chargeSolana, V.challenge),
    placed: (h) => docOf(chargeSolana, V.challenge, h),
    account: `${SOLANA_DEVNET}:${V.fixed.payer}`,
    inputs: { computeUnitLimit: V.build.computeUnitLimit, computeUnitPrice: V.build.computeUnitPrice },
    answer: async (r) => {
      if (r.kind !== "solana-message") throw new Error(r.kind);
      return toHex(payer.sign(r.message));
    },
  };

  it("the placed challenge is the vector's", () => {
    expect(p.doc).toEqual([V.place.expect]);
  });
  it("B6: the message is V1's, with the request's memo; the payer's signature completes a bound credential", async () => {
    const { signed } = await buildAndSign(p, (r) => {
      if (r.kind !== "solana-message") throw new Error(r.kind);
      const m = decompile(r.message);
      expect(m.feePayer).toBe(X.V1.feePayer);
      expect(m.instructions).toEqual(X.V1.instructions);
    });
    expect((signed as MppCredential).payload["type"]).toBe("transaction");
  });
  it("a request without the mint's decimals needs the buyer's; without them, no-payable-option before any fetch", async () => {
    const r = JSON.parse(Buffer.from(V.challenge.request, "base64url").toString("utf8"));
    delete r.methodDetails.decimals;
    const doc = docOf(chargeSolana, { ...V.challenge, request: b64u(JSON.stringify(r)) });
    const fetch = serving(ABC);
    const out = await confirm(doc, chargeSolana, p.account, fetch, { ...CONFIRMING, inputs: p.inputs });
    expect(out).toEqual({ decline: { code: "no-payable-option", detail: "mpp/input-missing" } });
    expect(fetch.calls).toBe(0);
  });
  refusals(p, [EVM_ACCOUNT, `${SOLANA_MAINNET}:${V.fixed.payer}`]);
});

// ── mpp/charge/xrpl ──────────────────────────────────────────────────────────────────────────────────────────────

describe("mpp/charge/xrpl", () => {
  const V = vectors<Loose>("mpp-charge-xrpl.json");
  const f = V.fixed;
  const p: Pairing = {
    binding: chargeXrpl,
    doc: docOf(chargeXrpl, V.challenge),
    account: `xrpl:1:${f.account}`,
    inputs: { fee: V.build.fee, sequence: V.build.sequence, lastLedgerSequence: V.build.lastLedgerSequence },
    answer: async (r) => {
      if (r.kind !== "xrpl-tx") throw new Error(r.kind);
      expect(r.txJson.InvoiceID).toBe(f.invoiceId);
      return V.V3.blob;
    },
  };

  it("the placed challenge is the vector's", () => {
    expect(p.doc).toEqual([V.place.expect]);
  });
  it("B6: the Payment carries V3's fields; the wallet's V3 blob completes a bound credential", async () => {
    const { signed } = await buildAndSign(p, (r) => {
      if (r.kind !== "xrpl-tx") throw new Error(r.kind);
      expect(r.txJson).toEqual({
        TransactionType: "Payment",
        Flags: 0,
        Account: f.account,
        Destination: f.request.recipient,
        Amount: f.request.amount,
        InvoiceID: f.invoiceId,
        Fee: V.build.fee,
        Sequence: V.build.sequence,
        LastLedgerSequence: V.build.lastLedgerSequence,
        SourceTag: V.build.defaultSourceTag,
      });
      expect(V.V3.blob).toContain(`5011${f.invoiceId}`);
    });
    expect((signed as MppCredential).payload).toEqual({ type: "transaction", blob: V.V3.blob });
  });
  it("a signed blob answered in 0x hex is declined signed-not-bound: the answer is hex digits without 0x", async () => {
    const out = await piecePay(p.doc, chargeXrpl, counting(p.account, async () => `0x${V.V3.blob}`), p.inputs!);
    expect(isDeclined(out) && [out.decline.code, out.decline.detail]).toEqual(["signed-not-bound", "xrpl/blob-malformed"]);
  });
  it("without the buyer's ledger reads, no-payable-option before any fetch", async () => {
    const fetch = serving(ABC);
    const out = await confirm(p.doc, p.binding, p.account, fetch, { ...CONFIRMING, inputs: { fee: "12" } });
    expect(out).toEqual({ decline: { code: "no-payable-option", detail: "mpp/input-missing" } });
    expect(fetch.calls).toBe(0);
  });
  refusals(p, [EVM_ACCOUNT, `xrpl:0:${f.account}`]);
});

// ── mpp/charge/nearintents ───────────────────────────────────────────────────────────────────────────────────────

describe("mpp/charge/nearintents (confirm only)", () => {
  const V = vectors<Loose>("mpp-charge-nearintents.json");
  const refundTo = V.fixed.request.methodDetails.refundTo;
  const p: Pairing = {
    binding: chargeNearIntents as unknown as Binding,
    // The quote's fixed members are held to the challenge the ATR names: unplaced.expect, as the vector file gives it.
    doc: chargeNearIntents.advertise([V.challenge], H, LINK, V.challenge, 0, "payment", undefined, V.unplaced.expect) as MppChallenge[],
    placed: (h) => chargeNearIntents.advertise([V.challenge], h, LINK, V.challenge, 0, "payment", undefined, V.unplaced.expect),
    account: `${V.fixed.request.methodDetails.originNetwork}:${refundTo}`,
    answer: async () => {
      throw new Error("nothing to sign");
    },
  };

  it("the placed challenge is the vector's", () => {
    expect(p.doc).toEqual([V.place.expect]);
  });
  it("B6: on a match nothing is handed to the signer; the vector's hash credential checks against abc, not abd", async () => {
    const confirmed = await confirm(p.placed!(HA), offered(p.binding), p.account, serving(ATR_A), CONFIRMING);
    if (isDeclined(confirmed)) throw new Error(confirmed.decline.detail);
    expect(confirmed.h).toBe(HA);
    expect(confirmed.request).toBeNull();
    const signer = counting(p.account, p.answer);
    const whole = await transact(p.placed!(HA), offered(p.binding), signer, serving(ATR_A), GATE);
    expect(whole).toEqual({ signed: null, bytes: ATR_A, h: HA, agreement: receiptFor(HA) });
    expect(signer.requests.length).toBe(0);
    const credential = { challenge: V.place.expect, payload: V.bound.payload };
    expect(await check(ABC, credential, p.binding)).toEqual({ h: V.bound.expect });
    expect(code(await check(ABD, credential, p.binding))).toBe("signed-not-bound");
  });
  refusals(p, [`near:mainnet:${V.fixed.request.methodDetails.destinationRecipient}`, `eip155:1:${refundTo}`]);
});

// ── mpp/session/xrpl ─────────────────────────────────────────────────────────────────────────────────────────────

describe("mpp/session/xrpl", () => {
  const V = vectors<Loose>("mpp-session-hedera-solana-xrpl.json");
  const s = V.XS2;
  // The XRPL vectors' payer: Ed25519 from entropy 01×16, whose private key is SHA-512Half of the entropy.
  const payer = ed25519(Uint8Array.from(createHash("sha512").update(Buffer.alloc(16, 1)).digest().subarray(0, 32)));
  const publicKey = `ED${Buffer.from(payer.publicKey).toString("hex").toUpperCase()}`;
  const memo = Buffer.from(`lcp:sha256:${H}`, "utf8").toString("hex").toUpperCase();
  const p: Pairing = {
    binding: sessionXrpl,
    doc: docOf(sessionXrpl, V.SS1.xrpl.challenge),
    account: `xrpl:1:${s.account}`,
    inputs: {
      deposit: s.deposit,
      xrpl: { publicKey: `0x${publicKey}`, settleDelay: s.settleDelay, fee: s.fee, sequence: s.sequence, lastLedgerSequence: s.lastLedgerSequence },
    },
    // The wallet answers as the XRP Ledger writes a signed blob and a claim's signature: hex digits without 0x.
    answer: async (r) => {
      const q = request(r);
      if (q["kind"] !== "xrpl-session-open") throw new Error(String(q["kind"]));
      return { signedBlob: s.blob, claimSignature: Buffer.from(payer.sign(q["claim"].bytes)).toString("hex") };
    },
  };

  it("the placed challenge is the vector's; XS2's blob carries the payer's key", () => {
    expect(p.doc).toEqual([V.SS1.xrpl.placed]);
    expect(s.blob).toContain(`7121${publicKey}`);
  });
  it("B6: XS2's PaymentChannelCreate with one LCP memo, and XS3's first claim; XS2's blob completes a bound opening", async () => {
    const { signed } = await buildAndSign(p, (r) => {
      const q = request(r);
      expect(q["kind"]).toBe("xrpl-session-open");
      expect(q["txJson"]).toEqual({
        TransactionType: "PaymentChannelCreate",
        Flags: 0,
        Account: s.account,
        Amount: s.deposit,
        Destination: "rpjfAeE3DeeHPFnN2PgGFW5YxnZFAjrEyN",
        SettleDelay: s.settleDelay,
        PublicKey: publicKey,
        Memos: [{ Memo: { MemoData: memo } }],
        Fee: s.fee,
        Sequence: s.sequence,
        LastLedgerSequence: s.lastLedgerSequence,
      });
      expect(s.blob).toContain(memo);
      expect(q["claim"].channelId).toBe(s.expectChannel);
      expect(q["claim"].drops).toBe(BigInt(V.XS3.drops));
      expect(Buffer.from(q["claim"].bytes).toString("hex").toUpperCase()).toBe(V.XS3.expect);
    });
    const c = signed as MppCredential;
    expect(c.source).toBe(`did:pkh:xrpl:1:${s.account}`);
    expect(c.payload["action"]).toBe("open");
    expect(c.payload["transaction"]).toBe(s.blob);
    expect(c.payload["amount"]).toBe(V.XS3.drops);
    const claim = Buffer.from(V.XS3.expect, "hex");
    const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(payer.publicKey).toString("base64url") }, format: "jwk" });
    expect(verify(null, claim, key, Buffer.from(String(c.payload["signature"]), "hex"))).toBe(true);
    expect(String(c.payload["signature"]).startsWith("c042fda5")).toBe(true);
    expect(String(c.payload["signature"]).endsWith("a03901")).toBe(true);
  });
  it("an opening answered in 0x hex is declined signed-not-bound: the answer takes one form, hex digits without 0x", async () => {
    const claimSignature = (r: SigningRequest) => toHex(payer.sign(request(r)["claim"].bytes));
    for (const prefixed of [
      async (r: SigningRequest) => ({ signedBlob: `0x${s.blob}`, claimSignature: claimSignature(r) }),
      async (r: SigningRequest) => ({ ...((await p.answer(r)) as Record<string, string>), signedBlob: `0x${s.blob}` }),
      async (r: SigningRequest) => ({ signedBlob: s.blob, claimSignature: claimSignature(r) }),
    ]) {
      const out = await piecePay(p.doc, sessionXrpl, counting(p.account, prefixed), p.inputs!);
      expect(isDeclined(out) && out.decline.code).toBe("signed-not-bound");
    }
  });

  // A later claim in the held channel: XS3's claim bytes, signed by the channel's key and answered in the opening's form.
  it("a claim within the held channel is answered as hex digits without 0x; one in 0x hex is declined signed-not-bound", async () => {
    const opened = await piecePay(p.doc, sessionXrpl, counting(p.account, p.answer), p.inputs!);
    if (isDeclined(opened) || "approve" in opened) throw new Error(JSON.stringify(opened));
    const hold = await openChannel(opened.bytes, opened.signed!, sessionXrpl);
    if (isDeclined(hold)) throw new Error(hold.decline.detail);
    expect(hold.channel).toBe(s.expectChannel);
    const own = [{ ...V.SS1.xrpl.challenge, id: "seller-own-id" }];
    const claim = (prefix: string) => async (r: SigningRequest) =>
      (r as unknown as { requests: { bytes: Uint8Array }[] }).requests.map((q) => prefix + Buffer.from(payer.sign(q.bytes)).toString("hex"));
    const signer = counting(p.account, claim(""));
    const paid = await within(own, hold, sessionXrpl, signer);
    if (isDeclined(paid)) throw new Error(paid.decline.detail);
    const handed = (signer.requests[0] as unknown as { requests: { kind: string; bytes: Uint8Array }[] }).requests;
    expect(handed.map((q) => q.kind)).toEqual(["xrpl-claim"]);
    expect(Buffer.from(handed[0]!.bytes).toString("hex").toUpperCase()).toBe(V.XS3.expect);
    const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(payer.publicKey).toString("base64url") }, format: "jwk" });
    const payload = (paid.signed as MppCredential).payload;
    expect([payload["action"], payload["channelId"], payload["amount"]]).toEqual(["voucher", s.expectChannel, V.XS3.drops]);
    expect(verify(null, Buffer.from(V.XS3.expect, "hex"), key, Buffer.from(String(payload["signature"]), "hex"))).toBe(true);
    const prefixed = await within(own, hold, sessionXrpl, counting(p.account, claim("0x")));
    expect(isDeclined(prefixed) && [prefixed.decline.code, prefixed.decline.detail]).toEqual(["signed-not-bound", "mpp/credential-malformed"]);
  });
  refusals(p, [EVM_ACCOUNT, `xrpl:0:${s.account}`]);
});
