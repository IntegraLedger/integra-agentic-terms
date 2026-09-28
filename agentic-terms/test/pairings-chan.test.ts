// B2, B6, B10 and B16 for the channel pairings: x402 batch-settlement on EVM, Solana and Cloudflare, MPP's sessions on
// EVM and Tempo, and MPP's Tempo subscription. Expected digests, signatures, messages, wires and channel ids are the
// vector files'; the keys and seeds are the published test keys the files name.
import { createHash, createPrivateKey, sign as edSign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { concat, hashTypedData, keccak256, toBytes, toHex, toRlp, type Hex, type TypedDataDefinition } from "viem";
import { privateKeyToAccount, sign } from "viem/accounts";
import { sessionEvm, sessionTempo, subscriptionTempo, type MppChallenge } from "@integraledger/lcp/mpp";
import { batchCloudflare, batchEvm, batchSvm } from "@integraledger/lcp/x402-batch-settlement";
import type { PaymentRequired, PaymentRequirements } from "@integraledger/lcp/x402";
import { check, confirm, finish, transact, type Binding, type Signature, type SigningRequest } from "../src/index.js";
import {
  ABC,
  ABD,
  buildAndSign,
  code,
  counting,
  H,
  isDeclined,
  LINK,
  offered,
  RECEIPT,
  serving,
  vectors,
  type Pairing,
} from "./support.js";

// ── shared helpers ────────────────────────────────────────────────────────────────────────────────────────────────

async function at<T>(now: number, run: () => Promise<T>): Promise<T> {
  const real = Date.now;
  Date.now = () => now * 1000;
  try {
    return await run();
  } finally {
    Date.now = real;
  }
}

const sha256 = (b: Uint8Array): string => `0x${createHash("sha256").update(b).digest("hex")}`;
const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
/** Base58 (Bitcoin alphabet) of the bytes. */
function base58(b: Uint8Array): string {
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  let s = "";
  while (n > 0n) {
    s = B58[Number(n % 58n)]! + s;
    n /= 58n;
  }
  for (const x of b) {
    if (x !== 0) break;
    s = "1" + s;
  }
  return s;
}

/** Raw Ed25519 over the message, with the key of a 32-byte seed. */
function ed25519(seedHex: string, message: Uint8Array): Uint8Array {
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seedHex, "hex")]);
  return new Uint8Array(edSign(null, message, createPrivateKey({ key: der, format: "der", type: "pkcs8" })));
}

const typedDataOf = (td: unknown) => td as TypedDataDefinition;

/** The x402 document for one option, as the pairing's `advertise` places H and `link`. */
function x402Doc(binding: Binding, option: PaymentRequirements, resource: { url: string }, link = LINK): PaymentRequired {
  const base = { x402Version: 2, resource, accepts: [option] } as PaymentRequired;
  const placed = (binding as unknown as { advertise(d: unknown, h: string, l: string, o: unknown): unknown }).advertise(
    base,
    H,
    link,
    option,
  );
  if (typeof placed === "object" && placed !== null && "refused" in placed) throw new Error(JSON.stringify(placed));
  return placed as PaymentRequired;
}

/** The same x402 document with its legal-context link written as `http://`. */
function withHttpLink(doc: PaymentRequired): PaymentRequired {
  const lc = (doc.extensions as unknown as { legalContext: { info: Record<string, unknown> } }).legalContext;
  const info = { ...lc.info, legalContextUrl: LINK.replace("https://", "http://") };
  return { ...doc, extensions: { ...doc.extensions, legalContext: { ...lc, info } } } as unknown as PaymentRequired;
}

/** B10: the document with an `http://` link is unreadable, detail `<ns>/link-not-https`, and nothing is fetched. */
async function b10(doc: unknown, binding: Binding, account: string, ns: string, inputs?: Pairing["inputs"]) {
  const fetch = serving(ABC);
  const out = await confirm(doc, binding, account, fetch, inputs);
  expect(code(out)).toBe("offer-unreadable");
  expect(isDeclined(out) && out.decline.detail).toBe(`${ns}/link-not-https`);
  expect(fetch.calls).toBe(0);
}

/** B16: each account is declined no-payable-option, and nothing is fetched. */
async function b16(doc: unknown, binding: Binding, accounts: string[], inputs?: Pairing["inputs"]) {
  const fetch = serving(ABC);
  for (const a of accounts) expect(code(await confirm(doc, binding, a, fetch, inputs))).toBe("no-payable-option");
  expect(fetch.calls).toBe(0);
}

// ── x402 batch-settlement ────────────────────────────────────────────────────────────────────────────────────────────

type BatchVectors = {
  fixed: {
    L: string;
    resource: { url: string };
    evm: {
      payer: Hex;
      payerKey: Hex;
      payerAuthorizer: Hex;
      payerAuthorizerKey: Hex;
      deposit: string;
      authSalt: Hex;
      now: number;
      validBefore: string;
      option: PaymentRequirements;
    };
    svm: {
      payer: string;
      payerSeed: string;
      salt: string;
      openSlot: string;
      deposit: string;
      blockhash: string;
      tokenProgram: string;
      option: PaymentRequirements;
    };
  };
  EB1: { channelId: string };
  EB2: { digest: string; signature: string };
  EB3: { depositNonce: string; digest: string; signature: string };
  EB6: { expectRef: { network: string; channel: string } };
  ES1: { channelPda: string };
  ES2: { openInstructionData: string; messageLength: number; wireLength: number };
  ES3: { message: string; signaturePrefix: string; signatureSuffix: string };
  ES4: { expectRef: { network: string; channel: string } };
  EC1: { payload: { accepted: PaymentRequirements; extensions: { legalContext: { info: unknown } } } };
};
const BV = vectors<BatchVectors>("x402-batch-settlement.json");

describe("x402/batch-settlement/eip155", () => {
  const f = BV.fixed.evm;
  const doc = x402Doc(batchEvm, f.option, BV.fixed.resource);
  const account = `eip155:84532:${f.payer}`;
  const inputs = { payerAuthorizer: f.payerAuthorizer, deposit: f.deposit, authSalt: f.authSalt };
  /** The payer signs the token authorization; the payer authorizer signs the voucher (EB3, EB2). */
  async function answer(r: SigningRequest): Promise<Signature> {
    if (r.kind !== "batch") throw new Error(`not batch: ${r.kind}`);
    const keys = [f.payerKey, f.payerAuthorizerKey];
    return Promise.all(
      r.requests.map((q, i) => {
        if (q.kind !== "eip712") throw new Error(q.kind);
        return privateKeyToAccount(keys[i]!).signTypedData(typedDataOf(q.typedData));
      }),
    );
  }
  const p: Pairing = { binding: batchEvm, doc, account, inputs, answer };
  it("B6: EB3's deposit authorization and EB2's voucher, signed in order; the opening is bound to H", () =>
    at(f.now, async () => {
      const { signed } = await buildAndSign(p, async (r) => {
        if (r.kind !== "batch") throw new Error(r.kind);
        const [auth, voucher] = r.requests;
        if (auth?.kind !== "eip712" || voucher?.kind !== "eip712") throw new Error("request kinds");
        expect(r.requests.length).toBe(2);
        expect(hashTypedData(typedDataOf(auth.typedData))).toBe(BV.EB3.digest);
        expect((auth.typedData as { message: { nonce: string } }).message.nonce).toBe(BV.EB3.depositNonce);
        expect(hashTypedData(typedDataOf(voucher.typedData))).toBe(BV.EB2.digest);
        expect(await answer(r)).toEqual([BV.EB3.signature, BV.EB2.signature]);
      });
      const payload = (signed as unknown as { payload: Record<string, any> }).payload;
      expect(payload["type"]).toBe("deposit");
      expect(payload["channelConfig"].salt).toBe(H);
      expect(payload["voucher"]).toEqual({ channelId: BV.EB1.channelId, maxClaimableAmount: "1000", signature: BV.EB2.signature });
      expect(payload["deposit"].authorization.erc3009Authorization).toEqual({
        validAfter: "0",
        validBefore: f.validBefore,
        salt: f.authSalt,
        signature: BV.EB3.signature,
      });
      expect(batchEvm.channel.kind(signed as never)).toBe("open");
      expect(await batchEvm.channel.ref(signed as never)).toEqual(BV.EB6.expectRef);
    }));
  it("B10: an http link is unreadable, detail x402/link-not-https; 0 fetches", () =>
    at(f.now, () => b10(withHttpLink(doc), batchEvm, account, "x402", inputs)));
  it("B16: another namespace, and another chain, are no-payable-option before any fetch", () =>
    at(f.now, () => b16(doc, batchEvm, ["solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:x", `eip155:1:${f.payer}`], inputs)));
  it("the deposit: extra.minDeposit when present, the buyer's maximum refused before any fetch; the payer authorizer required", () =>
    at(f.now, async () => {
      const fetch = serving(ABC);
      const over = await confirm(doc, batchEvm, account, fetch, { ...inputs, maxDeposit: "99999" });
      expect(code(over)).toBe("no-payable-option");
      expect(isDeclined(over) && over.decline.detail).toBe("x402/deposit-above-maximum");
      const noAuthorizer = await confirm(doc, batchEvm, account, fetch, { deposit: f.deposit });
      expect(isDeclined(noAuthorizer) && noAuthorizer.decline.detail).toBe("x402/input-missing");
      expect(fetch.calls).toBe(0);
      const withMin = x402Doc(batchEvm, { ...f.option, extra: { ...f.option.extra, minDeposit: "250000" } }, BV.fixed.resource);
      const confirmed = await confirm(withMin, batchEvm, account, serving(ABC), { ...inputs, deposit: "1" });
      if (isDeclined(confirmed)) throw new Error(confirmed.decline.code);
      expect((confirmed.chosen.choice as { deposit: string }).deposit).toBe("250000");
    }));
  it("an absent authorization salt is drawn once, kept in chosen, and finish rebuilds the same request", () =>
    at(f.now, async () => {
      const { authSalt: _, ...noSalt } = inputs;
      const confirmed = await confirm(doc, batchEvm, account, serving(ABC), noSalt);
      if (isDeclined(confirmed) || confirmed.request === null) throw new Error("declined");
      const salt = (confirmed.chosen.choice as { authSalt: string }).authSalt;
      expect(salt).toMatch(/^0x[0-9a-f]{64}$/);
      const chosen = JSON.parse(JSON.stringify(confirmed.chosen));
      const done = await finish(ABC, chosen, await answer(confirmed.request), batchEvm);
      if (isDeclined(done) || "next" in done) throw new Error("not finished");
      const erc3009 = (done.signed as unknown as { payload: { deposit: { authorization: { erc3009Authorization: { salt: string } } } } })
        .payload.deposit.authorization.erc3009Authorization;
      expect(erc3009.salt).toBe(salt);
    }));
});

describe("x402/batch-settlement/solana", () => {
  const f = BV.fixed.svm;
  const doc = x402Doc(batchSvm, f.option, BV.fixed.resource);
  const account = `solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1:${f.payer}`;
  const inputs = {
    payerAuthorizer: f.payer,
    deposit: f.deposit,
    openSlot: f.openSlot,
    tokenProgram: f.tokenProgram,
    recentBlockhash: f.blockhash,
    salt: f.salt,
  };
  /** The payer, who is also the payer authorizer, signs the transaction message and the voucher, each in base58. */
  async function answer(r: SigningRequest): Promise<Signature> {
    if (r.kind !== "batch") throw new Error(`not batch: ${r.kind}`);
    return r.requests.map((q) => {
      if (q.kind !== "solana-message" && q.kind !== "ed25519-raw") throw new Error(q.kind);
      return base58(ed25519(f.payerSeed, q.message));
    });
  }
  const p: Pairing = { binding: batchSvm, doc, account, inputs, answer };
  it("B6: ES2's opening message (its open data and memo) and ES3's voucher; the signed wire is bound to H", async () => {
    const { signed } = await buildAndSign(p, async (r) => {
      if (r.kind !== "batch") throw new Error(r.kind);
      const [tx, voucher] = r.requests;
      if (tx?.kind !== "solana-message" || voucher?.kind !== "ed25519-raw") throw new Error("request kinds");
      expect(tx.message.length).toBe(BV.ES2.messageLength);
      expect(hex(tx.message)).toContain(BV.ES2.openInstructionData);
      expect(hex(tx.message)).toContain(Buffer.from(BV.fixed.L, "utf8").toString("hex"));
      expect(hex(voucher.message)).toBe(BV.ES3.message);
      expect(voucher.signer).toBe(f.payer);
      const vs = hex(ed25519(f.payerSeed, voucher.message));
      expect(vs.startsWith(BV.ES3.signaturePrefix) && vs.endsWith(BV.ES3.signatureSuffix)).toBe(true);
    });
    const payload = (signed as unknown as { payload: Record<string, any> }).payload;
    expect(Buffer.from(payload["deposit"].transaction, "base64").length).toBe(BV.ES2.wireLength);
    expect(payload["voucher"].channelId).toBe(BV.ES1.channelPda);
    expect(batchSvm.channel.kind(signed as never)).toBe("open");
    expect(await batchSvm.channel.ref(signed as never)).toEqual(BV.ES4.expectRef);
  });
  it("B10: an http link is unreadable, detail x402/link-not-https; 0 fetches", () =>
    b10(withHttpLink(doc), batchSvm, account, "x402", inputs));
  it("B16: another namespace, and another cluster, are no-payable-option before any fetch", () =>
    b16(doc, batchSvm, [`eip155:84532:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`, `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:${f.payer}`], inputs));
  it("the recent blockhash is the offer's extra.recentBlockhash when present", async () => {
    const offered = x402Doc(batchSvm, { ...f.option, extra: { ...f.option.extra, recentBlockhash: f.blockhash } }, BV.fixed.resource);
    const { recentBlockhash: _, ...rest } = inputs;
    const confirmed = await confirm(offered, batchSvm, account, serving(ABC), rest);
    if (isDeclined(confirmed)) throw new Error(confirmed.decline.code);
    expect((confirmed.chosen.choice as { recentBlockhash: string }).recentBlockhash).toBe(f.blockhash);
  });
});

describe("x402/batch-settlement/cloudflare", () => {
  const option = BV.EC1.payload.accepted;
  const doc = x402Doc(batchCloudflare, option, BV.fixed.resource);
  const account = "cloudflare:402:agent.example";
  const never = async (): Promise<Signature> => {
    throw new Error("no signer is called");
  };

  it("B6: the build is the payment; EC1's echoed legal context; no signer call; check against abc and abd", async () => {
    const confirmed = await confirm(doc, offered(batchCloudflare), account, serving(ABC));
    if (isDeclined(confirmed)) throw new Error(confirmed.decline.code);
    expect(confirmed.request).toBeNull();
    const done = await finish(ABC, JSON.parse(JSON.stringify(confirmed.chosen)), null, batchCloudflare);
    if (isDeclined(done) || "next" in done) throw new Error("not finished");
    const signed = done.signed as unknown as { payload: unknown; accepted: unknown; extensions: { legalContext: { info: unknown } } };
    expect(signed.payload).toEqual({ amount: "5", asset: "USD" });
    expect(signed.accepted).toEqual(option);
    expect(signed.extensions.legalContext.info).toEqual(BV.EC1.payload.extensions.legalContext.info);
    const signer = counting(account, never);
    const whole = await transact(doc, offered(batchCloudflare), signer, serving(ABC));
    if (isDeclined(whole)) throw new Error(whole.decline.code);
    if ("approve" in whole) throw new Error("an agreement payment to approve");
    expect(whole.agreement).toEqual(RECEIPT);
    expect(signer.requests.length).toBe(0);
    expect(await check(ABC, done.signed, batchCloudflare)).toEqual({ h: H });
    expect(code(await check(ABD, done.signed, batchCloudflare))).toBe("signed-not-bound");
  });
  it("B10: an http link is unreadable, detail x402/link-not-https; 0 fetches", () =>
    b10(withHttpLink(doc), batchCloudflare, account, "x402"));
  it("B16: another namespace, and another network, are no-payable-option before any fetch", () =>
    b16(doc, batchCloudflare, ["eip155:84532:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "cloudflare:403:agent.example"]));
});

// ── MPP sessions and subscription ────────────────────────────────────────────────────────────────────────────────────

const MC = vectors<{ fixed: { realm: string; expires: string } }>("mpp-challenge.json");
const b64u = (s: string) => Buffer.from(s, "utf8").toString("base64url");
const issued = (method: string, intent: string, request: string): MppChallenge =>
  ({ realm: MC.fixed.realm, method, intent, request: b64u(request), expires: MC.fixed.expires }) as MppChallenge;

/** The seller's 402 challenges for one issued challenge, as the pairing's `advertise` places H and `link`. */
function mppDoc(binding: Binding, c: MppChallenge, link = LINK): MppChallenge[] {
  const placed = (binding as unknown as { advertise(d: unknown, h: string, l: string, o: unknown): unknown }).advertise([c], H, link, c);
  if (!Array.isArray(placed)) throw new Error(JSON.stringify(placed));
  return placed as MppChallenge[];
}

/** The same challenges with the legal-context link in `opaque` written as `http://`. */
function mppHttpLink(doc: MppChallenge[]): MppChallenge[] {
  return doc.map((c) => {
    const map = JSON.parse(Buffer.from(c.opaque!, "base64url").toString("utf8"));
    return { ...c, opaque: b64u(JSON.stringify({ ...map, legalContextUrl: LINK.replace("https://", "http://") })) };
  });
}

const affix = (v: string, e: { prefix: string; suffix: string }) => {
  expect(v.startsWith(e.prefix), `${v} starts ${e.prefix}`).toBe(true);
  expect(v.endsWith(e.suffix), `${v} ends ${e.suffix}`).toBe(true);
};

type Fixed = { payerKey: Hex; payer: Hex; now: number };

describe("mpp/session/evm", () => {
  const E = vectors<{
    fixed: Fixed & { request: string; deposit: string; tokenDomain: { name: string; version: string } };
    ES1: { expectChannelId: string };
    ES2: { expectOpenLength: number; expectOpenSelector: string; expectHOccurrences: number };
    ES3: { expectNonce: string };
    ES4: { expectDigest: string; expectSignature: { prefix: string; suffix: string } };
    ES5: { expectVoucherDigest: string };
  }>("mpp-session-evm.json");
  const f = E.fixed;
  const doc = mppDoc(sessionEvm, issued("evm", "session", f.request));
  const account = `eip155:84532:${f.payer}`;
  const payer = privateKeyToAccount(f.payerKey);
  const seen: SigningRequest[] = [];
  /** Test value for the hash form's broadcast open: the signer answers a transaction hash. */
  const TX_HASH = `0x${"ab".repeat(32)}` as const;
  async function answer(r: SigningRequest): Promise<Signature> {
    seen.push(r);
    if (r.kind === "evm-calls") return TX_HASH;
    if (r.kind !== "eip712") throw new Error(`not eip712: ${r.kind}`);
    return payer.signTypedData(typedDataOf(r.typedData));
  }
  const authorization: Pairing = {
    binding: sessionEvm,
    doc,
    account,
    inputs: { deposit: f.deposit, credentialType: "authorization", tokenDomain: f.tokenDomain },
    answer,
  };
  it("B6 (authorization): ES4's funding digest and signature, then ES5's voucher; the credential is bound to H", () =>
    at(f.now, async () => {
      seen.length = 0;
      const { signed } = await buildAndSign(authorization, async (r) => {
        if (r.kind !== "eip712") throw new Error(r.kind);
        expect(hashTypedData(typedDataOf(r.typedData))).toBe(E.ES4.expectDigest);
        expect((r.typedData as { message: { nonce: string } }).message.nonce).toBe(E.ES3.expectNonce);
        affix(await payer.signTypedData(typedDataOf(r.typedData)), E.ES4.expectSignature);
      });
      const voucher = seen[1];
      if (voucher?.kind !== "eip712") throw new Error("no voucher request");
      expect(hashTypedData(typedDataOf(voucher.typedData))).toBe(E.ES5.expectVoucherDigest);
      const payload = (signed as unknown as { payload: Record<string, unknown> }).payload;
      expect(payload["channelId"]).toBe(E.ES1.expectChannelId);
      expect(payload["salt"]).toBe(H);
      expect(sessionEvm.channel.kind(signed as never)).toBe("open");
    }));
  it("B6 (hash): ES2's open call, broadcast by the signer, then the voucher; bound to H", () =>
    at(f.now, async () => {
      await buildAndSign({ ...authorization, inputs: { deposit: f.deposit, credentialType: "hash" } }, (r) => {
        if (r.kind !== "evm-calls") throw new Error(r.kind);
        expect(r.broadcast).toBe(true);
        const open = r.calls[1]!;
        expect(toBytes(open.data).length).toBe(E.ES2.expectOpenLength);
        expect(open.data.slice(0, 10)).toBe(E.ES2.expectOpenSelector);
        expect(open.data.split(H.slice(2)).length - 1).toBe(E.ES2.expectHOccurrences);
      });
    }));
  it("B10: an http link is unreadable, detail mpp/link-not-https; 0 fetches", () =>
    at(f.now, () => b10(mppHttpLink(doc), sessionEvm, account, "mpp", authorization.inputs)));
  it("B16: another namespace, and another chain, are no-payable-option before any fetch", () =>
    at(f.now, () =>
      b16(doc, sessionEvm, ["solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:x", `eip155:1:${f.payer}`], authorization.inputs)));
});

/** A 65-byte secp256k1 signature, r ‖ s ‖ v with v 27 or 28. */
async function sig65(hash: Hex, key: Hex): Promise<Hex> {
  const s = await sign({ hash, privateKey: key });
  return concat([s.r, s.s, toHex(Number(s.v), { size: 1 })]);
}
const num = (n: number | bigint): Hex => (BigInt(n) === 0n ? "0x" : toHex(BigInt(n)));

describe("mpp/session/tempo", () => {
  const T = vectors<{
    fixed: Fixed & { requestV2: string; deposit: string; escrowV2: Hex; pathUSD: Hex };
    TS1: { expectLength: number; expectSelector: string };
    TS2: { expectSha256: string };
    TS3: { expectChannelId: string };
    TS4: { expectVoucher0: string };
  }>("mpp-session-tempo.json");
  const f = T.fixed;
  const doc = mppDoc(sessionTempo, issued("tempo", "session", f.requestV2));
  const account = `eip155:42431:${f.payer}`;
  const payer = privateKeyToAccount(f.payerKey);
  const seen: SigningRequest[] = [];
  /** TS2's wire: the open call in a `0x76` transaction, signed by the payer over keccak256(0x76 ‖ rlp(fields)). */
  async function openWire(r: SigningRequest): Promise<Hex> {
    if (r.kind !== "tempo-call") throw new Error(r.kind);
    const fields = [
      num(r.chainId),
      num(1),
      num(2),
      num(200000),
      [[r.call.to, "0x", r.call.data]],
      [],
      toHex((1n << 256n) - 1n),
      "0x",
      num(r.validBefore),
      "0x",
      f.pathUSD,
      "0x",
      [],
    ] as const;
    const signature = await sig65(keccak256(concat(["0x76", toRlp(fields as never)])), f.payerKey);
    return concat(["0x76", toRlp([...fields, signature] as never)]);
  }
  async function answer(r: SigningRequest): Promise<Signature> {
    seen.push(r);
    if (r.kind === "tempo-call") return openWire(r);
    if (r.kind !== "eip712") throw new Error(`not eip712: ${r.kind}`);
    // A wallet signs an EIP-712 address by its value; viem refuses the vectors' escrow `0x4D505…`, whose case is not
    // EIP-55's, so this test wallet writes it in lower case before signing. The digest is the same.
    const td = typedDataOf(r.typedData) as TypedDataDefinition & { domain: { verifyingContract?: Hex } };
    const vc = td.domain.verifyingContract;
    return payer.signTypedData(vc === undefined ? td : ({ ...td, domain: { ...td.domain, verifyingContract: vc.toLowerCase() as Hex } } as TypedDataDefinition));
  }
  const p: Pairing = { binding: sessionTempo, doc, account, inputs: { deposit: f.deposit }, answer };
  it("B6: TS1's open call and TS2's wire, then TS4's voucher over TS3's channel; bound to H", () =>
    at(f.now, async () => {
      seen.length = 0;
      const { signed } = await buildAndSign(p, async (r) => {
        if (r.kind !== "tempo-call") throw new Error(r.kind);
        expect(r.broadcast).toBe(false);
        expect(r.call.to).toBe(f.escrowV2);
        expect(toBytes(r.call.data).length).toBe(T.TS1.expectLength);
        expect(r.call.data.slice(0, 10)).toBe(T.TS1.expectSelector);
        expect(sha256(toBytes(await openWire(r)))).toBe(T.TS2.expectSha256);
      });
      const voucher = seen[1];
      if (voucher?.kind !== "eip712") throw new Error("no voucher request");
      const td = typedDataOf(voucher.typedData) as TypedDataDefinition & { domain: { verifyingContract: Hex } };
      expect(td.domain.verifyingContract).toBe(f.escrowV2);
      const lower = { ...td, domain: { ...td.domain, verifyingContract: td.domain.verifyingContract.toLowerCase() as Hex } };
      expect(hashTypedData(lower as TypedDataDefinition)).toBe(T.TS4.expectVoucher0);
      const payload = (signed as unknown as { payload: Record<string, unknown> }).payload;
      expect(payload["channelId"]).toBe(T.TS3.expectChannelId);
      expect(sessionTempo.channel.kind(signed as never)).toBe("open");
      expect(await sessionTempo.channel.boundWithin(signed as never)).toBe(H);
    }));
  it("B10: an http link is unreadable, detail mpp/link-not-https; 0 fetches", () =>
    at(f.now, () => b10(mppHttpLink(doc), sessionTempo, account, "mpp", p.inputs)));
  it("B16: another namespace, and another chain, are no-payable-option before any fetch", () =>
    at(f.now, () => b16(doc, sessionTempo, ["solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:x", `eip155:1:${f.payer}`], p.inputs)));
  it("a v1 session naming no chainId pays on 4217, the Tempo session's default, and not on 42431", () =>
    at(f.now, async () => {
      const R = JSON.parse((f as unknown as { requestV1: string }).requestV1);
      delete R.methodDetails.chainId;
      const v1 = mppDoc(sessionTempo, issued("tempo", "session", JSON.stringify(R)));
      const out = await confirm(v1, sessionTempo, `eip155:4217:${f.payer}`, serving(ABC), p.inputs);
      if (isDeclined(out)) throw new Error(out.decline.detail);
      if (out.request?.kind !== "tempo-call") throw new Error("not tempo-call");
      expect(out.request.chainId).toBe(4217);
      await b16(v1, sessionTempo, [`eip155:42431:${f.payer}`], p.inputs);
    }));
});

describe("mpp/subscription/tempo", () => {
  const U = vectors<{
    fixed: Fixed & { request: string };
    SUB1: { expectDigest: Hex; expectSignedLength: number };
    SUB2: { expectRefChannel: string };
  }>("mpp-subscription-tempo.json");
  const f = U.fixed;
  const doc = mppDoc(subscriptionTempo, issued("tempo", "subscription", f.request));
  const account = `eip155:42431:${f.payer}`;
  async function answer(r: SigningRequest): Promise<Signature> {
    if (r.kind !== "tempo-key-authorization") throw new Error(`not a key authorization: ${r.kind}`);
    return sig65(r.digest, f.payerKey);
  }
  const p: Pairing = { binding: subscriptionTempo, doc, account, answer };
  it("B6: SUB1's digest with witness H, signed by the root key; the credential is bound to H", () =>
    at(f.now, async () => {
      const { signed } = await buildAndSign(p, (r) => {
        if (r.kind !== "tempo-key-authorization") throw new Error(r.kind);
        expect(r.digest).toBe(U.SUB1.expectDigest);
        expect(r.authorization.witness).toBe(H);
      });
      const payload = (signed as unknown as { payload: { signature: Hex } }).payload;
      expect(toBytes(payload.signature).length).toBe(U.SUB1.expectSignedLength);
      expect(await subscriptionTempo.channel.ref(signed as never)).toEqual({
        network: "eip155:42431",
        channel: U.SUB2.expectRefChannel,
      });
    }));
  it("B10: an http link is unreadable, detail mpp/link-not-https; 0 fetches", () =>
    at(f.now, () => b10(mppHttpLink(doc), subscriptionTempo, account, "mpp")));
  it("B16: another namespace, and another chain, are no-payable-option before any fetch", () =>
    at(f.now, () => b16(doc, subscriptionTempo, ["solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:x", `eip155:1:${f.payer}`])));
});
