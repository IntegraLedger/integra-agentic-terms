// B2, B6, B10 and B16 for the x402 pairings on NEAR, Tron, TON, Starknet, Polkadot, Sui, Aptos and Cardano. Every
// expected value is the pairing's vector file's. Keys are the vector files' published test seeds and the published
// Anvil key, or generated here at test time.
import { createHash, createPrivateKey, generateKeyPairSync, sign as ed25519Sign, type KeyObject } from "node:crypto";
import { describe, expect, it } from "vitest";
import { recoverAddress } from "viem";
import { sign as secp256k1Sign } from "viem/accounts";
import { exactAptos } from "@integraledger/lcp/aptos";
import { exactCardano } from "@integraledger/lcp/cardano";
import { exactNear } from "@integraledger/lcp/near";
import { exactPolkadotRemark, ss58Decode } from "@integraledger/lcp/polkadot";
import { exactStarknet } from "@integraledger/lcp/starknet";
import { exactSui } from "@integraledger/lcp/sui";
import { exactTronMemo } from "@integraledger/lcp/tron";
import { exactTvm } from "@integraledger/lcp/tvm";
import type { PaymentRequired, PaymentRequirements } from "@integraledger/lcp/x402";
import { confirm, transact, type Binding, type Presented, type SigningRequest } from "../src/index.js";
import {
  buildAndSign,
  code,
  counting,
  H,
  LINK,
  offered,
  serving,
  toHex,
  vectors,
  type Pairing,
} from "./support.js";

type Doc = PaymentRequired & { extensions: { legalContext: { info: { legalContextUrl: string } } } };

/** The seller's document for the option, as the pairing's `advertise` places H and the link. */
function docOf(binding: Binding, option: PaymentRequirements, resource: { url: string }): Doc {
  const base = { x402Version: 2, resource, accepts: [option] } as PaymentRequired;
  const placed = (binding as unknown as { advertise(d: PaymentRequired, h: string, l: string, o: unknown): unknown })
    .advertise(base, H, LINK, option);
  if (typeof placed === "object" && placed !== null && "refused" in placed) throw new Error(JSON.stringify(placed));
  return placed as Doc;
}

/** The same document with its legal-context link written as `http://`. */
function httpDoc(doc: Doc): Doc {
  const d = structuredClone(doc);
  d.extensions.legalContext.info.legalContextUrl = LINK.replace("https://", "http://");
  return d;
}

/** Freezes the clock at `now` seconds, and restores it. */
async function at<T>(now: number, run: () => Promise<T>): Promise<T> {
  const real = Date.now;
  Date.now = () => now * 1000;
  try {
    return await run();
  } finally {
    Date.now = real;
  }
}

/** An Ed25519 private key from a 32-byte seed (RFC 8410's PKCS#8 form). */
function ed25519Key(seedHex: string): KeyObject {
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seedHex, "hex")]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

const sha256Hex = (b: Uint8Array | Buffer): string => createHash("sha256").update(b).digest("hex");

interface Row {
  id: string;
  p: Pairing;
  now: number;
  inspect: (r: SigningRequest) => void | Promise<void>;
  after: (signed: Presented) => void | Promise<void>;
  /** An account of this namespace on a network the document does not offer. */
  otherNetwork: string;
}

// ── x402/exact/near

const NEAR = vectors<{
  fixed: {
    H: string;
    seedHex: string;
    payer: string;
    publicKey: string;
    O: PaymentRequirements;
    accessKeyNonce: string;
    finalHeight: string;
    resource: { url: string };
  };
  V1: { expectRequestHash: string; expectSignature: { prefix: string; suffix: string } };
  V2: { expectSignedDelegateAction: string; expectReference: unknown };
}>("x402-exact-near.json");

const nearRow: Row = (() => {
  const f = NEAR.fixed;
  const key = ed25519Key(f.seedHex);
  return {
    id: "x402/exact/near",
    now: 1790000000,
    p: {
      binding: exactNear,
      doc: docOf(exactNear, f.O, f.resource),
      account: `${f.O.network}:${f.payer}`,
      inputs: { publicKey: f.publicKey, accessKeyNonce: f.accessKeyNonce, finalHeight: f.finalHeight },
      answer: async (r) => {
        if (r.kind !== "near-delegate") throw new Error(r.kind);
        return { keyType: 0, bytes: toHex(ed25519Sign(null, r.hash, key)) };
      },
    },
    inspect: (r) => {
      if (r.kind !== "near-delegate") throw new Error(r.kind);
      expect(toHex(r.hash).slice(2)).toBe(NEAR.V1.expectRequestHash);
      const sig = ed25519Sign(null, r.hash, key).toString("hex");
      expect(sig.startsWith(NEAR.V1.expectSignature.prefix) && sig.endsWith(NEAR.V1.expectSignature.suffix)).toBe(true);
    },
    after: async (signed) => {
      const s = signed as unknown as { payload: { signedDelegateAction: string } };
      expect(s.payload.signedDelegateAction).toBe(NEAR.V2.expectSignedDelegateAction);
      expect(await exactNear.reference(signed)).toEqual(NEAR.V2.expectReference);
    },
    otherNetwork: `near:mainnet:${f.payer}`,
  };
})();

// ── x402/exact/tron/lcp-trc20-memo

const TRON = vectors<{
  fixed: {
    O: PaymentRequirements;
    payerKey: `0x${string}`;
    payer: string;
    payerBytes: string;
    refBlock: { number: number; id: string };
    now: number;
    feeLimit: number;
    resource: { url: string };
  };
  V2: {
    expectTxid: string;
    expectSignature: string;
    expectTransactionHex: string;
  };
  V3: { expectReference: unknown };
}>("x402-exact-tron-lcp-trc20-memo.json");

/** The Anvil key's secp256k1 signature over the id as `r ‖ s ‖ v`, with v the recovery bit. */
async function tronSign(txid: Uint8Array): Promise<`0x${string}`> {
  const s = await secp256k1Sign({ hash: toHex(txid), privateKey: TRON.fixed.payerKey });
  return `0x${s.r.slice(2).padStart(64, "0")}${s.s.slice(2).padStart(64, "0")}0${s.yParity}`;
}

const tronRow: Row = (() => {
  const f = TRON.fixed;
  return {
    id: "x402/exact/tron/lcp-trc20-memo",
    now: f.now / 1000,
    p: {
      binding: exactTronMemo,
      doc: docOf(exactTronMemo, f.O, f.resource),
      account: `${f.O.network}:${f.payer}`,
      inputs: { refBlock: { number: String(f.refBlock.number), id: f.refBlock.id }, feeLimit: String(f.feeLimit) },
      answer: async (r) => {
        if (r.kind !== "tron-txid") throw new Error(r.kind);
        return tronSign(r.txid);
      },
    },
    inspect: async (r) => {
      if (r.kind !== "tron-txid") throw new Error(r.kind);
      expect(toHex(r.txid)).toBe(TRON.V2.expectTxid);
      const sig = await tronSign(r.txid);
      expect(sig.slice(2)).toBe(TRON.V2.expectSignature);
      expect((await recoverAddress({ hash: toHex(r.txid), signature: sig })).toLowerCase()).toBe(
        `0x${f.payerBytes.slice(2)}`,
      );
    },
    after: async (signed) => {
      const s = signed as unknown as { payload: { transaction: string } };
      expect(s.payload.transaction).toBe(TRON.V2.expectTransactionHex);
      expect(await exactTronMemo.reference(signed)).toEqual(TRON.V3.expectReference);
    },
    otherNetwork: `tron:3448148188:${f.payer}`,
  };
})();

// ── x402/exact/tvm

const TVM = vectors<{
  fixed: {
    seedHex: string;
    O: PaymentRequirements;
    placed: PaymentRequirements;
    wallet: string;
    walletId: number;
    seqno: number;
    jettonWallet: string;
    attachNanotons: number;
    now: number;
    resource: { url: string };
  };
  V2: { expectRequestHash: string; expectSignature: { prefix: string; suffix: string } };
  V2b: { stateInit: string; wallet: string; seqno: number; expectRequestHash: string; expectSignature: string; expectTransferBodyHash: string };
  V3: { expectReference: unknown };
}>("x402-exact-tvm.json");

const tvmRow: Row = (() => {
  const f = TVM.fixed;
  const key = ed25519Key(f.seedHex);
  const doc = docOf(exactTvm, f.O, f.resource);
  expect(doc.accepts[0]).toEqual(f.placed);
  return {
    id: "x402/exact/tvm",
    now: f.now,
    p: {
      binding: exactTvm,
      doc,
      // CAIP-10 writes the raw address's colon as %3A.
      account: `${f.O.network}:${f.wallet.replace(":", "%3A")}`,
      inputs: {
        walletId: f.walletId,
        seqno: f.seqno,
        jettonWallet: f.jettonWallet,
        attachNanotons: String(f.attachNanotons),
      },
      answer: async (r) => {
        if (r.kind !== "ton-w5") throw new Error(r.kind);
        return toHex(ed25519Sign(null, r.hash, key));
      },
    },
    inspect: (r) => {
      if (r.kind !== "ton-w5") throw new Error(r.kind);
      expect(toHex(r.hash).slice(2)).toBe(TVM.V2.expectRequestHash);
      const sig = ed25519Sign(null, r.hash, key).toString("hex");
      expect(sig.startsWith(TVM.V2.expectSignature.prefix) && sig.endsWith(TVM.V2.expectSignature.suffix)).toBe(true);
    },
    after: async (signed) => {
      expect(await exactTvm.reference(signed)).toEqual(TVM.V3.expectReference);
    },
    otherNetwork: `tvm:-3:${f.wallet.replace(":", "%3A")}`,
  };
})();

/** V2b: an undeployed wallet passes its state init, as a base64 BoC, among its inputs. */
const tvmUndeployedRow: Row = (() => {
  const f = TVM.fixed;
  const W = TVM.V2b;
  const key = ed25519Key(f.seedHex);
  return {
    id: "x402/exact/tvm (undeployed wallet)",
    now: f.now,
    p: {
      ...tvmRow.p,
      account: `${f.O.network}:${W.wallet.replace(":", "%3A")}`,
      inputs: { ...tvmRow.p.inputs, seqno: W.seqno, stateInit: W.stateInit },
    },
    inspect: (r) => {
      if (r.kind !== "ton-w5") throw new Error(r.kind);
      expect(toHex(r.hash).slice(2)).toBe(W.expectRequestHash);
      expect(ed25519Sign(null, r.hash, key).toString("hex")).toBe(W.expectSignature);
    },
    after: async (signed) => {
      const ref = await exactTvm.reference(signed as never);
      if ("refused" in ref) throw new Error(ref.code);
      expect(ref.transferBodyHash).toBe(`0x${W.expectTransferBodyHash}`);
      // The message carries the state init: its code cell's 32 bits, 0xdeadbeef, are in the BoC.
      const boc = Buffer.from((signed as unknown as { payload: { settlementBoc: string } }).payload.settlementBoc, "base64");
      expect(boc.includes(Buffer.from("deadbeef", "hex"))).toBe(true);
    },
    otherNetwork: `tvm:-3:${W.wallet.replace(":", "%3A")}`,
  };
})();

// ── x402/exact/starknet

const SN = vectors<{
  fixed: { O: PaymentRequirements; from: string; now: number; resource: { url: string } };
  S2: { expectNonce: string };
  S3: { expectExecuteBefore: string; expectChainId: string; expectCalldata: string[]; signature: string[] };
  S4: { expectReference: unknown };
}>("x402-exact-starknet.json");

const starknetRow: Row = (() => {
  const f = SN.fixed;
  /** The typed data's members the vectors fix, compared as numbers where they are felts. */
  function checkRequest(r: SigningRequest): void {
    if (r.kind !== "starknet-snip12") throw new Error(r.kind);
    expect(BigInt(r.account)).toBe(BigInt(f.from));
    const td = r.typedData as unknown as {
      domain: { chainId: string };
      message: { Nonce: string; "Execute Before": string; Calls: { Calldata: string[] }[] };
    };
    expect(BigInt(td.domain.chainId)).toBe(BigInt(SN.S3.expectChainId));
    expect(BigInt(td.message.Nonce)).toBe(BigInt(SN.S2.expectNonce));
    expect(td.message["Execute Before"]).toBe(SN.S3.expectExecuteBefore);
    expect(td.message.Calls.length).toBe(1);
    expect(td.message.Calls[0]!.Calldata.map((x) => BigInt(x))).toEqual(SN.S3.expectCalldata.map((x) => BigInt(x)));
  }
  return {
    id: "x402/exact/starknet",
    now: f.now,
    p: {
      binding: exactStarknet,
      doc: docOf(exactStarknet, f.O, f.resource),
      account: `${f.O.network}:${f.from}`,
      // No Stark-curve signer is available to these tests: the signer checks the request is the vectors' and answers
      // with the vector file's signature.
      answer: async (r) => {
        checkRequest(r);
        return SN.S3.signature;
      },
    },
    inspect: checkRequest,
    after: async (signed) => {
      expect(await exactStarknet.reference(signed)).toEqual(SN.S4.expectReference);
    },
    otherNetwork: `starknet:SN_MAIN:${f.from}`,
  };
})();

// ── x402/exact/polkadot/lcp-assets-remark

const DOT = vectors<{
  fixed: { O: PaymentRequirements; resource: { url: string } };
  V2: { expectCall: string };
  V3: { extrinsic: string; expectReference: unknown };
}>("x402-exact-polkadot-lcp-assets-remark.json");
/** The payer of V3's extrinsic: SS58 of the public key its signature preamble names. */
const DOT_PAYER = "16SYiSu5tWgdV4sWiaxir7GYEiFfTc9GYnRd34PDGCUMgkmP";

const polkadotRow: Row = (() => {
  const f = DOT.fixed;
  function checkRequest(r: SigningRequest): void {
    if (r.kind !== "substrate-call") throw new Error(r.kind);
    expect(r.network).toBe(f.O.network);
    expect(toHex(r.call)).toBe(DOT.V2.expectCall);
  }
  return {
    id: "x402/exact/polkadot/lcp-assets-remark",
    now: 1790000000,
    p: {
      binding: exactPolkadotRemark,
      doc: docOf(exactPolkadotRemark, f.O, f.resource),
      account: `${f.O.network}:${DOT_PAYER}`,
      // The signing payload's era and genesis hashes are chain data: the wallet checks the call is the vectors' and
      // answers with V3, the extrinsic the chain accepted.
      answer: async (r) => {
        checkRequest(r);
        return DOT.V3.extrinsic;
      },
    },
    inspect: (r) => {
      checkRequest(r);
      // V3's signer (bytes 4..36 after the length prefix and 0x84 0x00) is the payer's account.
      expect(toHex(ss58Decode(DOT_PAYER) as Uint8Array)).toBe(`0x${DOT.V3.extrinsic.slice(10, 74)}`);
    },
    after: async (signed) => {
      expect(await exactPolkadotRemark.reference(signed as never)).toEqual(DOT.V3.expectReference);
    },
    otherNetwork: `polkadot:67f9723393ef76214df0118c34bbbd3d:${DOT_PAYER}`,
  };
})();

// ── x402/exact/sui

const SUI = vectors<{
  fixed: { H: string; sender: string; O: PaymentRequirements; resource: { url: string } };
  V2: { tx: { transactionBase64: string }; expectReference: unknown };
}>("x402-exact-sui.json");

const suiRow: Row = (() => {
  const f = SUI.fixed;
  function checkRequest(r: SigningRequest): void {
    if (r.kind !== "sui-transaction") throw new Error(r.kind);
    expect(r.accepted).toEqual(f.O);
    expect(toHex(r.pureInput)).toBe(f.H);
    expect(r.expiration).toBe("epoch-bounded");
  }
  return {
    id: "x402/exact/sui",
    now: 1790000000,
    p: {
      binding: exactSui,
      doc: docOf(exactSui, f.O, f.resource),
      account: `${f.O.network}:${f.sender}`,
      // The wallet answers V2, the vectors' transaction carrying H as its one unused Pure input. The pairing reads the
      // carrier from the transaction and never verifies the signature, so the signature is 97 zero bytes.
      answer: async (r) => {
        checkRequest(r);
        return { signature: Buffer.alloc(97).toString("base64"), transaction: SUI.V2.tx.transactionBase64 };
      },
    },
    inspect: checkRequest,
    after: async (signed) => {
      expect(JSON.parse(JSON.stringify(await exactSui.reference(signed)))).toEqual(SUI.V2.expectReference);
    },
    otherNetwork: `sui:mainnet:${f.sender}`,
  };
})();

// ── x402/exact/aptos

const APT = vectors<{
  fixed: {
    O: PaymentRequirements;
    resource: { url: string };
    fixtureF: {
      sender: string;
      sequenceNumber: number;
      maxGasAmount: number;
      gasUnitPrice: number;
      expiresAt: number;
      chainId: number;
      metadata: string;
      recipient: string;
      amount: number;
      rawTransactionBytes: number;
      rawTransactionSha256: string;
    };
  };
  V2: { expectReference: unknown };
}>("x402-exact-aptos.json");

const uleb = (n: number): Buffer => {
  const out: number[] = [];
  do {
    let b = n & 0x7f;
    n >>>= 7;
    if (n !== 0) b |= 0x80;
    out.push(b);
  } while (n !== 0);
  return Buffer.from(out);
};
const u64 = (n: number | bigint): Buffer => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(n));
  return b;
};
const bcsStr = (s: string): Buffer => Buffer.concat([uleb(Buffer.byteLength(s)), Buffer.from(s)]);
const addr32 = (a: string): Buffer => Buffer.from(a.slice(2).padStart(64, "0"), "hex");
const bcsBytes = (b: Buffer): Buffer => Buffer.concat([uleb(b.length), b]);

/** Fixture F's RawTransaction in BCS: `0x1::primary_fungible_store::transfer<0x1::fungible_asset::Metadata>`. */
function aptosRaw(): Buffer {
  const F = APT.fixed.fixtureF;
  return Buffer.concat([
    addr32(F.sender),
    u64(F.sequenceNumber),
    uleb(2), // TransactionPayload::EntryFunction
    addr32("0x1"),
    bcsStr("primary_fungible_store"),
    bcsStr("transfer"),
    uleb(1),
    uleb(7), // TypeTag::Struct
    addr32("0x1"),
    bcsStr("fungible_asset"),
    bcsStr("Metadata"),
    uleb(0),
    uleb(3),
    bcsBytes(addr32(F.metadata)),
    bcsBytes(addr32(F.recipient)),
    bcsBytes(u64(F.amount)),
    u64(F.maxGasAmount),
    u64(F.gasUnitPrice),
    u64(F.expiresAt),
    Buffer.from([F.chainId]),
  ]);
}

/** The wallet's SignedTransaction: the raw transaction and an Ed25519 authenticator from a key generated here. */
function aptosSigned(raw: Buffer): string {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const prefix = createHash("sha3-256").update("APTOS::RawTransaction").digest();
  const signature = ed25519Sign(null, Buffer.concat([prefix, raw]), privateKey);
  const pk = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  return Buffer.concat([raw, uleb(0), bcsBytes(pk), bcsBytes(signature)]).toString("base64");
}

const aptosRow: Row = (() => {
  const f = APT.fixed;
  function checkRequest(r: SigningRequest): void {
    if (r.kind !== "aptos-transaction") throw new Error(r.kind);
    expect(r.accepted).toEqual(f.O);
  }
  return {
    id: "x402/exact/aptos",
    now: 1790000000,
    p: {
      binding: exactAptos,
      doc: docOf(exactAptos, f.O, f.resource),
      account: `${f.O.network}:${f.fixtureF.sender}`,
      answer: async (r) => {
        checkRequest(r);
        return { transaction: aptosSigned(aptosRaw()) };
      },
    },
    inspect: (r) => {
      checkRequest(r);
      const raw = aptosRaw();
      expect(raw.length).toBe(f.fixtureF.rawTransactionBytes);
      expect(`0x${sha256Hex(raw)}`).toBe(f.fixtureF.rawTransactionSha256);
    },
    after: async (signed) => {
      expect(JSON.parse(JSON.stringify(await exactAptos.reference(signed)))).toEqual(APT.V2.expectReference);
    },
    otherNetwork: `aptos:2:${f.fixtureF.sender}`,
  };
})();

// ── x402/exact/cardano

const ADA = vectors<{
  fixed: { O: PaymentRequirements; nonce: string; resource: { url: string } };
  V1: { auxiliaryDataHex: string };
  V2: { transactionBase64: string; expectReference: unknown };
}>("x402-exact-cardano.json");

const cardanoRow: Row = (() => {
  const f = ADA.fixed;
  function checkRequest(r: SigningRequest): void {
    if (r.kind !== "cardano-transaction") throw new Error(r.kind);
    expect(r.accepted).toEqual(f.O);
    expect(toHex(r.auxiliaryData).slice(2)).toBe(ADA.V1.auxiliaryDataHex);
  }
  // The pairing never reads the payer's address; the account reuses the vectors' one preprod address, with CAIP-10's
  // escape for the underscore.
  const address = f.O.payTo.replace("_", "%5F");
  return {
    id: "x402/exact/cardano",
    now: 1790000000,
    p: {
      binding: exactCardano,
      doc: docOf(exactCardano, f.O, f.resource),
      account: `${f.O.network}:${address}`,
      // The wallet answers V2, the vectors' transaction whose body commits to V1's auxiliary data.
      answer: async (r) => {
        checkRequest(r);
        return { transaction: ADA.V2.transactionBase64, nonce: f.nonce };
      },
    },
    inspect: checkRequest,
    after: async (signed) => {
      expect(JSON.parse(JSON.stringify(await exactCardano.reference(signed)))).toEqual(ADA.V2.expectReference);
    },
    otherNetwork: `cardano:mainnet:${address}`,
  };
})();

const rows: Row[] = [nearRow, tronRow, tvmRow, tvmUndeployedRow, starknetRow, polkadotRow, suiRow, aptosRow, cardanoRow];

describe.each(rows.map((r) => [r.id, r] as const))("%s", (_id, row) => {
  const { p, now } = row;

  it("B6: the request is the vectors'; the signer's answer completes a payment bound to H", () =>
    at(now, async () => {
      const { signed } = await buildAndSign(p, row.inspect);
      await row.after(signed);
    }));

  it("B6 · payment identifier: appended to the echoed extension where the challenge advertises it", () =>
    at(now, async () => {
      const doc = structuredClone(p.doc) as Doc & { extensions: Record<string, unknown> };
      doc.extensions["payment-identifier"] = { info: {}, schema: {} };
      const out = await transact(doc, offered(p.binding), counting(p.account, p.answer), serving(new TextEncoder().encode("abc")), { inputs: p.inputs ?? {} });
      if ("decline" in out) throw new Error(`${out.decline.code}: ${out.decline.detail}`);
      if ("approve" in out) throw new Error("an agreement payment to approve");
      const ext = (out.signed as unknown as { extensions: Record<string, { info: { id?: string } }> }).extensions;
      expect(ext["payment-identifier"]!.info.id).toMatch(/^[A-Za-z0-9_-]{32}$/);
    }));

  it("B10: an http:// link is offer-unreadable, x402/link-not-https, with no fetch", () =>
    at(now, async () => {
      const fetch = serving(new TextEncoder().encode("abc"));
      const out = await confirm(httpDoc(p.doc as Doc), p.binding, p.account, fetch, p.inputs);
      expect(out).toEqual({ decline: { code: "offer-unreadable", detail: "x402/link-not-https" } });
      expect(fetch.calls).toBe(0);
    }));

  it("B16: an account of another namespace, then one on another network, is no-payable-option with no fetch", () =>
    at(now, async () => {
      for (const account of ["eip155:84532:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", row.otherNetwork]) {
        const fetch = serving(new TextEncoder().encode("abc"));
        const out = await confirm(p.doc, p.binding, account, fetch, p.inputs);
        expect(code(out)).toBe("no-payable-option");
        expect(fetch.calls).toBe(0);
      }
    }));
});

describe("inputs", () => {
  it("a missing or malformed input is no-payable-option with the pairing's input-missing, before any fetch", () =>
    at(nearRow.now, async () => {
      const cases: [Row, Record<string, unknown>, string][] = [
        [nearRow, { publicKey: NEAR.fixed.publicKey, accessKeyNonce: "100" }, "x402/input-missing"],
        [nearRow, { publicKey: NEAR.fixed.publicKey, accessKeyNonce: 100, finalHeight: "200000000" }, "x402/input-missing"],
        [tronRow, { refBlock: { number: "86542765", id: "0x00" }, feeLimit: "100000000" }, "x402/input-missing"],
        [tvmRow, { walletId: 2147483409, seqno: 5, jettonWallet: TVM.fixed.jettonWallet }, "x402/input-missing"],
      ];
      for (const [row, inputs, detail] of cases) {
        const fetch = serving(new TextEncoder().encode("abc"));
        const out = await confirm(row.p.doc, row.p.binding, row.p.account, fetch, inputs as never);
        expect(out).toEqual({ decline: { code: "no-payable-option", detail } });
        expect(fetch.calls).toBe(0);
      }
    }));
});

describe("hash", () => {
  it("H is SHA-256 of abc, as the vector files state", () => {
    expect(`0x${sha256Hex(Buffer.from("abc"))}`).toBe(H);
  });
});
