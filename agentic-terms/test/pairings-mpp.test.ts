// B2 and B6 for MPP's charge pairings. Expected values are the vector files': the challenges
// C_E and C_T, the digests and signatures of the published Anvil key #0, the Tempo calldata and wire, and the landed
// receipt of the push form.
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { concat, hashTypedData, toBytes, toHex as viemHex, toRlp, type Hex, type TypedDataDefinition } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  evmAuthorization,
  evmHash,
  evmPermit2,
  evmTransaction,
  place,
  tempoMemo,
  tempoPush,
  type MppChallenge,
  type MppCredential,
} from "@integraledger/lcp/mpp";
import { Account as TempoAccount, Transaction as TempoTransaction } from "viem/tempo";
import { exactEip3009, type PaymentRequirements } from "@integraledger/lcp/x402";
import { check, confirm, finish, transact, type Binding, type Fetch, type SigningRequest } from "../src/index.js";
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
  serving,
  vectors,
  type Pairing,
} from "./support.js";

type Challenge = { fixed: { realm: string; expires: string; R_E: string; R_T: string } };
const V = vectors<Challenge>("mpp-challenge.json");
const b64u = (s: string) => Buffer.from(s, "utf8").toString("base64url");
const issued = (method: string, request: string): MppChallenge =>
  ({ realm: V.fixed.realm, method, intent: "charge", request: b64u(request), expires: V.fixed.expires }) as MppChallenge;

/** The seller's 402 challenges for one issued challenge, as the pairing's `advertise` places H and the link. */
function docOf(binding: Binding, c: MppChallenge): MppChallenge[] {
  const placed = (binding as unknown as { advertise(d: unknown, h: string, l: string, o: unknown): unknown }).advertise(
    [c],
    H,
    LINK,
    c,
  );
  if (!Array.isArray(placed)) throw new Error(JSON.stringify(placed));
  return placed as MppChallenge[];
}

type Fixed = { payerKey: Hex; payer: Hex; now: number };
const account = (chain: number, f: Fixed) => `eip155:${chain}:${f.payer}`;
const typedDataOf = (r: SigningRequest) => {
  if (r.kind !== "eip712") throw new Error(`not eip712: ${r.kind}`);
  return r.typedData as unknown as TypedDataDefinition;
};
const eip712 = (f: Fixed) => (r: SigningRequest) => privateKeyToAccount(f.payerKey).signTypedData(typedDataOf(r));

async function at<T>(now: number, run: () => Promise<T>): Promise<T> {
  const real = Date.now;
  Date.now = () => now * 1000;
  try {
    return await run();
  } finally {
    Date.now = real;
  }
}

describe("mpp/charge/evm/authorization", () => {
  const A = vectors<{ fixed: Fixed & { tokenDomain: { name: string; version: string } }; MV5: { expectDigest: string; expectSignature: string; expectNonce: string } }>(
    "mpp-charge-evm-authorization.json",
  );
  const p: Pairing = {
    binding: evmAuthorization,
    doc: docOf(evmAuthorization, issued("evm", V.fixed.R_E)),
    account: account(84532, A.fixed),
    inputs: { tokenDomain: A.fixed.tokenDomain },
    answer: eip712(A.fixed),
  };
  it("B6: MV5's digest and signature; the credential is bound to H", () =>
    at(A.fixed.now, async () => {
      await buildAndSign(p, async (r) => {
        const td = typedDataOf(r);
        expect(hashTypedData(td)).toBe(A.MV5.expectDigest);
        expect((td.message as { nonce: string }).nonce).toBe(A.MV5.expectNonce);
        expect(await eip712(A.fixed)(r)).toBe(A.MV5.expectSignature);
      });
    }));
  it("B16: without the token's EIP-712 domain, no-payable-option before any fetch", () =>
    at(A.fixed.now, async () => {
      const fetch = serving(ABC);
      expect(code(await confirm(p.doc, p.binding, p.account, fetch))).toBe("no-payable-option");
      expect(code(await confirm(p.doc, p.binding, account(1, A.fixed), fetch, p.inputs))).toBe("no-payable-option");
      expect(code(await confirm(p.doc, p.binding, "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:x", fetch))).toBe(
        "no-payable-option",
      );
      expect(fetch.calls).toBe(0);
    }));
});

describe("mpp/charge/evm/permit2", () => {
  const P = vectors<{ fixed: Fixed & { spender: Hex }; MV6: { expectDigest: string; expectSignature: string } }>(
    "mpp-charge-evm-permit2.json",
  );
  const p: Pairing = {
    binding: evmPermit2,
    doc: docOf(evmPermit2, issued("evm", V.fixed.R_E)),
    account: account(84532, P.fixed),
    inputs: { spender: P.fixed.spender },
    answer: eip712(P.fixed),
  };
  it("B6: MV6's digest and signature; the credential is bound to H", () =>
    at(P.fixed.now, async () => {
      await buildAndSign(p, async (r) => {
        expect(hashTypedData(typedDataOf(r))).toBe(P.MV6.expectDigest);
        expect(await eip712(P.fixed)(r)).toBe(P.MV6.expectSignature);
      });
    }));
});

/** A Tempo signer's `0x76` transaction around the request's call, as MV7's wire: the vectors' fields and signature. */
function tempoWire(r: SigningRequest): Hex {
  if (r.kind !== "tempo-call") throw new Error(`not tempo-call: ${r.kind}`);
  const n = (v: number): Hex => (v === 0 ? "0x" : viemHex(v));
  const body = toRlp([
    n(r.chainId),
    n(1),
    n(2),
    n(100000),
    [[r.call.to, n(0), r.call.data]],
    [],
    n(0),
    n(0),
    n(r.validBefore),
    "0x",
    r.call.to,
    "0x",
    [],
    `0x${"11".repeat(65)}`,
  ]);
  return concat(["0x76", body]);
}
const sha256 = (h: Hex) => `0x${createHash("sha256").update(toBytes(h)).digest("hex")}`;

describe("mpp/charge/tempo/memo", () => {
  const M = vectors<{ fixed: Fixed; MV7: { expectCalldata: string; expectWireSha256: string } }>("mpp-charge-tempo-memo.json");
  const p: Pairing = {
    binding: tempoMemo,
    doc: docOf(tempoMemo, issued("tempo", V.fixed.R_T)),
    account: account(42431, M.fixed),
    answer: async (r) => tempoWire(r),
  };
  it("B6: the call carries MV7's attribution-memo calldata; the signed wire is bound to H", () =>
    at(M.fixed.now, async () => {
      await buildAndSign(p, (r) => {
        if (r.kind !== "tempo-call") throw new Error(r.kind);
        expect(r.call.data).toBe(M.MV7.expectCalldata);
        expect(r.broadcast).toBe(false);
        expect(sha256(tempoWire(r))).toBe(M.MV7.expectWireSha256);
      });
    }));
});

type Splits = {
  splits: {
    request: string;
    expectCalls: { to: Hex; data: Hex }[];
    agreedRefusals: { rows: { case: string; splits: unknown[]; expect: string }[] };
  };
};
const S = vectors<Splits & { fixed: Fixed }>("mpp-charge-tempo-memo.json");

/** The payer's `0x76` transaction around a `tempo-calls` request, signed and serialised by viem's Tempo encoder. */
async function tempoCallsWire(r: SigningRequest, key: Hex): Promise<Hex> {
  if (r.kind !== "tempo-calls") throw new Error(`not tempo-calls: ${r.kind}`);
  return TempoAccount.fromSecp256k1(key).signTransaction({
    type: "tempo",
    chainId: r.chainId,
    nonce: 1,
    gas: 300000n,
    maxFeePerGas: 2n,
    maxPriorityFeePerGas: 1n,
    validBefore: r.validBefore,
    feeToken: r.calls[0]!.to,
    calls: r.calls.map((c) => ({ to: c.to, data: c.data })),
  } as never) as Promise<Hex>;
}

describe("mpp/charge/tempo/memo and push with splits", () => {
  const f = S.fixed;
  const rows: [Binding, boolean][] = [
    [tempoMemo, false],
    [tempoPush, true],
  ];
  it.each(rows)("%#: the primary for amount less the splits, carrying the attribution memo, then each split in order", async (binding, broadcast) =>
    at(f.now, async () => {
      const R = JSON.parse(S.splits.request);
      if (broadcast) delete R.methodDetails.supportedModes;
      const doc = docOf(binding, issued("tempo", JSON.stringify(R)));
      const fetch = serving(ABC);
      const out = await confirm(doc, binding, account(42431, f), fetch);
      if (isDeclined(out)) throw new Error(`${out.decline.code}: ${out.decline.detail}`);
      const r = out.request!;
      if (r.kind !== "tempo-calls") throw new Error(r.kind);
      expect(r.calls).toEqual(S.splits.expectCalls);
      expect(r.broadcast).toBe(broadcast);
      expect(r.chainId).toBe(42431);
      // viem's Tempo encoder carries exactly these calls in the payer's signed 0x76 transaction.
      const wire = await tempoCallsWire(r, f.payerKey);
      expect(wire.slice(0, 4)).toBe("0x76");
      const decoded = TempoTransaction.deserialize(wire as `0x76${string}`) as unknown as { calls: { to: Hex; data: Hex }[] };
      expect(decoded.calls.map((c) => ({ to: c.to.toLowerCase(), data: c.data }))).toEqual(
        S.splits.expectCalls.map((c) => ({ to: c.to.toLowerCase(), data: c.data })),
      );
      if (!broadcast) {
        const done = await finish(ABC, out.chosen, wire, binding);
        if (isDeclined(done)) throw new Error(`${done.decline.code}: ${done.decline.detail}`);
        if (!("signed" in done)) throw new Error("next");
        expect(done.h).toBe(H);
        expect(await check(ABC, done.signed, binding)).toEqual({ h: H });
      }
    }));
  it.each(S.splits.agreedRefusals.rows.map((row) => [row.case, row] as const))(
    "%s: no-payable-option before any fetch, with the row's refusal",
    (_case, row) =>
      at(f.now, async () => {
        const R = JSON.parse(S.splits.request);
        const doc = docOf(tempoMemo, issued("tempo", JSON.stringify({ ...R, methodDetails: { ...R.methodDetails, splits: row.splits } })));
        const fetch = serving(ABC);
        const out = await confirm(doc, tempoMemo, account(42431, f), fetch);
        expect(code(out)).toBe("no-payable-option");
        expect(isDeclined(out) && out.decline.detail).toBe(row.expect);
        expect(fetch.calls).toBe(0);
      }),
  );
});

describe("mpp/charge/tempo/push", () => {
  const T = vectors<{
    fixed: Fixed & { R_TNoModes: string };
    MV13: { T_P: Hex; receipt: { blockNumber: string; logs: unknown[] } };
  }>("mpp-charge-tempo-push.json");
  const p: Pairing = {
    binding: tempoPush,
    doc: docOf(tempoPush, issued("tempo", T.fixed.R_TNoModes)),
    account: account(42431, T.fixed),
    answer: async () => ({
      hash: T.MV13.T_P,
      landed: { transaction: T.MV13.T_P, blockNumber: T.MV13.receipt.blockNumber, logs: T.MV13.receipt.logs as never },
    }),
  };
  it("B6: the call is broadcast by the signer; the landed receipt's memo binds it to H; the payment sent has no landed receipt", () =>
    at(T.fixed.now, async () => {
      const confirmed = await confirm(p.doc, p.binding, p.account, serving(ABC));
      if (isDeclined(confirmed)) throw new Error(confirmed.decline.code);
      const r = confirmed.request!;
      if (r.kind !== "tempo-call") throw new Error(r.kind);
      expect(r.broadcast).toBe(true);
      const answer = await p.answer(r);
      const done = await finish(ABC, confirmed.chosen, answer, p.binding);
      if (isDeclined(done)) throw new Error(`${done.decline.code}: ${done.decline.detail}`);
      if (!("signed" in done)) throw new Error("next");
      expect(done.h).toBe(H);
      expect(done.signed).not.toHaveProperty("landed");
      expect((done.signed as MppCredential).payload).toEqual({ type: "hash", hash: T.MV13.T_P });
      // The landed receipt comes back beside the payment as JSON, MV13's receipt as the vector writes it (its block
      // number a decimal string), and `check` reads the payment with it.
      const landed = { transaction: T.MV13.T_P, blockNumber: T.MV13.receipt.blockNumber, logs: T.MV13.receipt.logs };
      expect(done.landed).toEqual(landed);
      expect(await check(ABC, { ...(done.signed as MppCredential), landed: done.landed }, p.binding)).toEqual({ h: H });
      expect(code(await check(ABD, { ...(done.signed as MppCredential), landed: done.landed }, p.binding))).toBe("signed-not-bound");
      expect(code(await check(ABC, done.signed, p.binding))).toBe("signed-not-bound");
      const signer = counting(p.account, p.answer);
      const whole = await transact(p.doc, p.binding, signer, serving(ABC));
      if (isDeclined(whole)) throw new Error(whole.decline.code);
      expect(signer.requests.length).toBe(1);
      expect(whole.signed).toEqual(done.signed);
      expect(whole.landed).toEqual(landed);
    }));
});

describe("mpp/charge/evm/transaction and mpp/charge/evm/hash (publicProof false)", () => {
  const X = vectors<{
    fixed: Fixed & { R_ENoTypes: string };
    MV11: {
      expectCalldata: string;
      transaction: { chainId: number; nonce: number; maxPriorityFeePerGas: string; maxFeePerGas: string; gas: number; to: Hex };
      expectRawSha256: string;
      expectTxHash: Hex;
    };
  }>("mpp-charge-evm-transaction.json");
  const t = X.MV11.transaction;
  async function signedTx(r: SigningRequest): Promise<Hex> {
    if (r.kind !== "evm-call") throw new Error(r.kind);
    return privateKeyToAccount(X.fixed.payerKey).signTransaction({
      type: "eip1559",
      chainId: t.chainId,
      nonce: t.nonce,
      maxPriorityFeePerGas: BigInt(t.maxPriorityFeePerGas),
      maxFeePerGas: BigInt(t.maxFeePerGas),
      gas: BigInt(t.gas),
      to: r.call.to,
      data: r.call.data,
    });
  }
  const rows: [Binding, boolean, (r: SigningRequest) => Promise<Hex>][] = [
    [evmTransaction, false, signedTx],
    [evmHash, true, async () => X.MV11.expectTxHash],
  ];
  // For a pairing whose proof is the agreement (the gate relies on the agreement transaction instead), `finish` returns
  // the completed payment without reading `bound`; the credential is `{challenge, source, payload: {type:
  // "transaction", signature}}` or `{…, payload: {type: "hash", hash}}`.
  it.each(rows)("%#: B6's request is MV11's call; finish completes the payment, whose proof is the agreement", async (binding, broadcast, answer) =>
    at(X.fixed.now, async () => {
      const doc = docOf(binding, issued("evm", X.fixed.R_ENoTypes));
      const acct = account(84532, X.fixed);
      const confirmed = await confirm(doc, offered(binding), acct, serving(ABC));
      if (isDeclined(confirmed)) throw new Error(confirmed.decline.code);
      const r = confirmed.request!;
      if (r.kind !== "evm-call") throw new Error(r.kind);
      expect(r.call.data).toBe(X.MV11.expectCalldata);
      expect(r.broadcast).toBe(broadcast);
      if (!broadcast) expect(sha256(await signedTx(r))).toBe(X.MV11.expectRawSha256);
      const answered = await answer(r);
      const done = await finish(ABC, confirmed.chosen, answered, binding);
      if (isDeclined(done) || "next" in done) throw new Error(JSON.stringify(done));
      expect(done.h).toBe(H);
      expect(done.signed).toMatchObject({ payload: broadcast ? { type: "hash", hash: answered } : { type: "transaction", signature: answered } });
    }));
});

describe("mpp/charge/evm/transaction and mpp/charge/evm/hash complete once the agreement is recorded", () => {
  // Nothing the payer signs carries H, `bound` refuses `mpp/no-signed-place`, and the gate relies on the agreement
  // transaction instead, calling the signer only after the agreement's 200. `complete`
  // gives `{challenge, source, payload: {type: "transaction", signature}}` or `{…, payload: {type: "hash", hash}}`.
  const X = vectors<{
    fixed: Fixed & { R_ENoTypes: string };
    MV11: { transaction: { chainId: number; nonce: number; maxPriorityFeePerGas: string; maxFeePerGas: string; gas: number }; expectTxHash: Hex };
  }>("mpp-charge-evm-transaction.json");
  const AGREEMENT_URL = `https://seller.example/agreement/${H}`;
  // The x402 EVM vectors' option O, paying the nominal agreement amount, 1.
  const O: PaymentRequirements = {
    scheme: "exact",
    network: "eip155:84532",
    amount: "1",
    asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    payTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
    maxTimeoutSeconds: 60,
    extra: { name: "USDC", version: "2" },
  };
  // The agreement resource's receipt `{atrHash, agreed: true, network, transaction}`.
  const RECEIPT = { atrHash: H, agreed: true, network: "eip155:84532", transaction: `0x${"ab".repeat(32)}` };
  const signedTx = async (r: SigningRequest): Promise<Hex> => {
    if (r.kind !== "evm-call") throw new Error(r.kind);
    const t = X.MV11.transaction;
    return privateKeyToAccount(X.fixed.payerKey).signTransaction({
      type: "eip1559",
      chainId: t.chainId,
      nonce: t.nonce,
      maxPriorityFeePerGas: BigInt(t.maxPriorityFeePerGas),
      maxFeePerGas: BigInt(t.maxFeePerGas),
      gas: BigInt(t.gas),
      to: r.call.to,
      data: r.call.data,
    });
  };
  /** Serves ABC at the link; the agreement URL answers 402 with the EIP-3009 agreement option, then 200 with RECEIPT. */
  function seller(): Fetch & { paid: number } {
    const required = exactEip3009.advertise({ x402Version: 2, resource: { url: AGREEMENT_URL }, accepts: [O] }, H, LINK, O);
    if ("refused" in required) throw new Error(required.code);
    const f = (async (url: string, init: Parameters<Fetch>[1]) => {
      if (url === LINK) return new Response(new Uint8Array(ABC), { status: 200 });
      if (url !== AGREEMENT_URL) return new Response(null, { status: 404 });
      if (init.headers?.["PAYMENT-SIGNATURE"] === undefined) {
        return new Response(null, { status: 402, headers: { "payment-required": Buffer.from(JSON.stringify(required)).toString("base64") } });
      }
      f.paid++;
      return new Response(JSON.stringify(RECEIPT), { status: 200, headers: { "content-type": "application/json" } });
    }) as Fetch & { paid: number };
    f.paid = 0;
    return f;
  }
  const rows: [string, Binding, (r: SigningRequest) => Promise<Hex>, string, string][] = [
    ["transaction", evmTransaction, signedTx, "transaction", "signature"],
    ["hash", evmHash, async () => X.MV11.expectTxHash, "hash", "hash"],
  ];
  it.each(rows)("%s: the agreement is paid first, then the payment completes with the signer's answer", async (_n, binding, answer, type, member) =>
    at(X.fixed.now, async () => {
      const doc = place([issued("evm", X.fixed.R_ENoTypes)], H, LINK, issued("evm", X.fixed.R_ENoTypes), AGREEMENT_URL);
      if (!Array.isArray(doc)) throw new Error(JSON.stringify(doc));
      const acct = account(84532, X.fixed);
      const signer = counting(acct, async (r) => (r.kind === "eip712" ? privateKeyToAccount(X.fixed.payerKey).signTypedData(typedDataOf(r)) : answer(r)));
      const stub = seller();
      const t = await transact(doc, binding, signer, stub);
      if (isDeclined(t)) throw new Error(`${t.decline.code}: ${t.decline.detail}`);
      expect(stub.paid).toBe(1);
      expect(t.agreement).toEqual(RECEIPT);
      expect(signer.requests.map((r) => r.kind)).toEqual(["eip712", "evm-call"]);
      const expected = await answer(signer.requests[1]!);
      expect(t.signed).toMatchObject({ challenge: { id: doc[0]!.id }, payload: { type, [member]: expected } });
      expect(t.h).toBe(H);
    }),
  );
  // A pairing whose payment is not a public proof, offered with no agreement URL, is declined
  // `agreement-not-offered` before the signer is called.
  it.each(rows)("%s: no agreement URL in the challenge: agreement-not-offered, and the signer is never called", async (_n, binding, answer) =>
    at(X.fixed.now, async () => {
      const doc = docOf(binding, issued("evm", X.fixed.R_ENoTypes));
      const signer = counting(account(84532, X.fixed), answer);
      expect(code(await transact(doc, binding, signer, serving(ABC)))).toBe("agreement-not-offered");
      expect(signer.requests.length).toBe(0);
    }),
  );
});
