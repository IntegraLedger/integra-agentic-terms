// A binding from another copy of the protocol package, as a bundler or a nested install loads one beside the gate's
// own. That copy's refusals are not members of the gate's copy's, so the gate reads what a binding's members answer by
// the protocol package's refusal form, `{ refused: true, code }`, and reads everything else (a signer's answer, a
// seller's document) by membership only. The other copy is the installed package's pairing entry points bundled by
// esbuild into one module and imported from a temporary folder. Each expected outcome is the same pairing's through the
// gate's own copy, checked beside it: ACP's currency is three lowercase letters (acp-checkout.json V4's choice carries
// "usd"), so "USD" is acp/choice-malformed; a session whose legal context is not in its metadata is acp/no-legal-context
// (acp-checkout.json V6); card/seller-reference is confirm-only (card.json C2); the two EVM pairings whose proof is the
// agreement return the credential with the agreement's receipt (mpp-charge-evm-transaction.json MV11,
// mpp-charge-evm-hash.json MV12), and `0x`, which holds no signed transaction, completes no credential
// (mpp/credential-malformed); batch-settlement Solana's first voucher is x402-batch-settlement.json's ES3.
import { createPrivateKey, sign as edSign } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { build } from "esbuild";
import { privateKeyToAccount } from "viem/accounts";
import type { TypedDataDefinition } from "viem";
import { afterAll, describe, expect, it } from "vitest";
import { isRefusal, type AtrHash } from "@integraledger/lcp";
import { delegated } from "@integraledger/lcp/acp";
import { sellerReference } from "@integraledger/lcp/card";
import { evmHash, evmTransaction, type MppChallenge } from "@integraledger/lcp/mpp";
import { batchSvm } from "@integraledger/lcp/x402-batch-settlement";
import { exactEip3009, type PaymentRequired, type PaymentRequirements } from "@integraledger/lcp/x402";
import {
  confirm,
  openChannel,
  transact,
  within,
  type Binding,
  type Declined,
  type Fetch,
  type Signature,
  type SigningRequest,
  type ToApprove,
} from "../src/index.js";
import { ABC, AGREEMENT_URL, H, LINK, offered, receiptFor, serving, transactApproved, vectors } from "./support.js";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const dir = mkdtempSync(join(tmpdir(), "terms-binding-copies-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

type Other = { delegated: Binding; sellerReference: Binding; evmTransaction: Binding; evmHash: Binding; batchSvm: Binding };

/** The pairing entry points of the installed protocol package, bundled into one module: a second copy of the package. */
async function otherCopy(): Promise<Other> {
  const contents = [
    'export { delegated } from "@integraledger/lcp/acp";',
    'export { sellerReference } from "@integraledger/lcp/card";',
    'export { evmHash, evmTransaction } from "@integraledger/lcp/mpp";',
    'export { batchSvm } from "@integraledger/lcp/x402-batch-settlement";',
  ].join("\n");
  const out = await build({
    stdin: { contents, resolveDir: ROOT, loader: "js" },
    bundle: true,
    write: false,
    format: "esm",
    platform: "node",
    logLevel: "silent",
  });
  const file = join(dir, "other-copy.mjs");
  writeFileSync(file, out.outputFiles[0]!.text);
  return (await import(pathToFileURL(file).href)) as Other;
}
const other = await otherCopy();

type AcpVectors = {
  fixed: { A: string; H: AtrHash };
  V2: { expectSession: unknown };
  V4: { choice: Record<string, unknown> };
  V6: { doc: unknown; expect: { refused: true; code: string } };
};
const ACP = vectors<AcpVectors>("acp-checkout.json");
const CARD = vectors<{ C2: { build: { doc: unknown } } }>("card.json");
const X = vectors<{
  fixed: { payerKey: `0x${string}`; payer: `0x${string}`; now: number; R_ENoTypes: string };
  MV11: { transaction: { chainId: number; nonce: number; maxPriorityFeePerGas: string; maxFeePerGas: string; gas: number } };
}>("mpp-charge-evm-transaction.json");
const MV12 = vectors<{ MV12: { hash: `0x${string}` } }>("mpp-charge-evm-hash.json").MV12;
const MC = vectors<{ fixed: { realm: string; expires: string } }>("mpp-challenge.json");
const AG = vectors<{ fixed: { agreement: { option: PaymentRequirements } } }>("buyer.json").fixed.agreement;
const BV = vectors<{
  fixed: {
    resource: { url: string };
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
  ES1: { channelPda: string };
  ES3: { message: string };
  ES4: { expectRef: { network: string; channel: string } };
}>("x402-batch-settlement.json");

const ACCOUNT = `eip155:84532:${X.fixed.payer}`;
const payer = privateKeyToAccount(X.fixed.payerKey);

/**
 * The seller: `atr` at every link but the agreement URL, which answers 402 with the agreement option placed for `h` until
 * a payment is sent, then 200 with the receipt for `h`. `agreementCalls` counts the agreement URL's requests.
 */
function seller(atr: Uint8Array, h: AtrHash): Fetch & { agreementCalls: number } {
  const required = exactEip3009.advertise(
    { x402Version: 2, resource: { url: AGREEMENT_URL }, accepts: [AG.option] },
    h,
    LINK,
    AG.option,
  );
  const header = Buffer.from(JSON.stringify(required), "utf8").toString("base64");
  const f = (async (url: string, init: Parameters<Fetch>[1]) => {
    if (url !== AGREEMENT_URL) return new Response(new Uint8Array(atr), { status: 200 });
    f.agreementCalls++;
    if (init.headers?.["PAYMENT-SIGNATURE"] === undefined) {
      return new Response(null, { status: 402, headers: { "payment-required": header } });
    }
    return new Response(JSON.stringify(receiptFor(h)), { status: 200 });
  }) as Fetch & { agreementCalls: number };
  f.agreementCalls = 0;
  return f;
}

/** A signer that signs the agreement's EIP-712 request with the vectors' payer key and answers anything else with `rest`. */
function signer(rest: (r: SigningRequest) => Promise<Signature>) {
  const kinds: string[] = [];
  return {
    account: ACCOUNT,
    kinds,
    async sign(r: SigningRequest): Promise<Signature> {
      kinds.push(r.kind);
      if (r.kind === "eip712") return payer.signTypedData(r.typedData as unknown as TypedDataDefinition);
      return rest(r);
    },
  };
}

const never = async (): Promise<never> => {
  throw new Error("the signer was asked for the payment");
};

async function at<T>(now: number, run: () => Promise<T>): Promise<T> {
  const real = Date.now;
  Date.now = () => now * 1000;
  try {
    return await run();
  } finally {
    Date.now = real;
  }
}

describe("the other copy is a second copy of the protocol package", () => {
  it("its refusal has the protocol package's form and is not one the gate's copy made", async () => {
    const choice = { ...ACP.V4.choice, currency: "USD" };
    const own = await delegated.build(choice as never, ACP.fixed.H);
    const theirs = await (other.delegated as unknown as typeof delegated).build(choice as never, ACP.fixed.H);
    expect(own).toEqual({ refused: true, code: "acp/choice-malformed" });
    expect(theirs).toEqual(own);
    expect(isRefusal(own)).toBe(true);
    expect(isRefusal(theirs)).toBe(false);
  });
});

describe("a binding from another copy: its read's refusal runs the gate's declines", () => {
  it("acp/checkout/delegated with no legal context in the session's metadata: offer-unreadable, no fetch, no signer call", async () => {
    expect(ACP.V6.expect).toEqual({ refused: true, code: "acp/no-legal-context" });
    for (const binding of [delegated as Binding, other.delegated]) {
      const f = serving(ABC);
      const s = signer(never);
      const out = await transact(ACP.V6.doc, offered(binding), s, f);
      expect(out).toEqual({ decline: { code: "offer-unreadable", detail: ACP.V6.expect.code } });
      expect(f.calls).toBe(0);
      expect(s.kinds).toEqual([]);
    }
  });
});

describe("a binding from another copy: its build's refusal runs the gate's declines", () => {
  it("acp/checkout/delegated with currency USD: offer-unreadable acp/choice-malformed, no agreement, no signer call", async () => {
    const { session: _s, ...values } = ACP.V4.choice;
    const inputs = { ...values, currency: "USD" };
    const atr = new TextEncoder().encode(ACP.fixed.A);
    for (const binding of [delegated as Binding, other.delegated]) {
      const f = seller(atr, ACP.fixed.H);
      const s = signer(never);
      const out = await transactApproved(ACP.V2.expectSession, offered(binding), s, f, { inputs });
      expect(out).toEqual({ decline: { code: "offer-unreadable", detail: "acp/choice-malformed" } });
      expect(f.agreementCalls).toBe(0);
      expect(s.kinds).toEqual([]);
    }
  });

  it("card/seller-reference: confirm-only, with no request, no payment and no signer call", async () => {
    const doc = CARD.C2.build.doc;
    for (const binding of [sellerReference as Binding, other.sellerReference]) {
      const confirmed = await confirm(doc, offered(binding), ACCOUNT, serving(ABC));
      expect(confirmed).toMatchObject({ request: null, h: H });
      const s = signer(never);
      expect(await transact(doc, offered(binding), s, serving(ABC))).toEqual({
        signed: null,
        bytes: ABC,
        h: H,
        agreement: receiptFor(H),
      });
      expect(s.kinds).toEqual([]);
    }
  });
});

describe("a binding from another copy: a bound that finds no signed place runs the agreement's proof", () => {
  const challenge = {
    realm: MC.fixed.realm,
    method: "evm",
    intent: "charge",
    request: Buffer.from(X.fixed.R_ENoTypes, "utf8").toString("base64url"),
    expires: MC.fixed.expires,
  } as MppChallenge;

  async function signedTx(r: SigningRequest): Promise<`0x${string}`> {
    if (r.kind !== "evm-call") throw new Error(r.kind);
    const t = X.MV11.transaction;
    return payer.signTransaction({
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

  const rows: [string, Binding, Binding, (r: SigningRequest) => Promise<`0x${string}`>, (raw: `0x${string}`) => object][] = [
    ["mpp/charge/evm/transaction", evmTransaction as Binding, other.evmTransaction, signedTx, (raw) => ({ type: "transaction", signature: raw })],
    ["mpp/charge/evm/hash", evmHash as Binding, other.evmHash, async () => MV12.hash, () => ({ type: "hash", hash: MV12.hash })],
  ];

  const docOf = (binding: Binding): unknown =>
    (binding as unknown as { advertise(d: unknown, h: string, l: string, o: unknown, a: string): unknown }).advertise(
      [challenge],
      H,
      LINK,
      challenge,
      AGREEMENT_URL,
    );

  it.each(rows)("%s: the credential the signer completed is returned with the agreement's receipt", (_id, own, theirs, answer, payload) =>
    at(X.fixed.now, async () => {
      for (const binding of [own, theirs]) {
        const answers: `0x${string}`[] = [];
        const s = signer(async (r) => {
          const a = await answer(r);
          answers.push(a);
          return a;
        });
        const out = await transactApproved(docOf(binding), binding, s, seller(ABC, H));
        expect(s.kinds).toEqual(["eip712", "evm-call"]);
        expect(out).toMatchObject({ agreement: receiptFor(H), h: H });
        expect((out as { signed: { payload: unknown } }).signed.payload).toEqual(payload(answers[0]!));
      }
    }),
  );

  it("mpp/charge/evm/transaction: a signer answering 0x completes no credential, signed-not-bound mpp/credential-malformed", () =>
    at(X.fixed.now, async () => {
      for (const binding of [evmTransaction as Binding, other.evmTransaction]) {
        const s = signer(async () => "0x");
        const out = await transactApproved(docOf(binding), binding, s, seller(ABC, H));
        expect(s.kinds).toEqual(["eip712", "evm-call"]);
        expect((out as Declined).decline).toEqual({ code: "signed-not-bound", detail: "mpp/credential-malformed" });
        expect(out).not.toHaveProperty("signed");
      }
    }),
  );

  it.each(rows)("%s: a signer answering a refusal-shaped object is never read as a refusal", (_id, own, theirs) =>
    at(X.fixed.now, async () => {
      for (const binding of [own, theirs]) {
        const s = signer(async () => ({ refused: true, code: "mpp/no-signed-place" }) as unknown as Signature);
        const out = await transactApproved(docOf(binding), binding, s, seller(ABC, H));
        expect((out as Declined).decline).toEqual({ code: "signed-not-bound", detail: "mpp/credential-malformed" });
        expect(out).not.toHaveProperty("signed");
      }
    }),
  );
});

describe("a binding from another copy: a channel's members are read the same way", () => {
  const S = BV.fixed.svm;
  const account = `solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1:${S.payer}`;
  const inputs = {
    payerAuthorizer: S.payer,
    deposit: S.deposit,
    openSlot: S.openSlot,
    tokenProgram: S.tokenProgram,
    recentBlockhash: S.blockhash,
    salt: S.salt,
  };
  const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
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
  function ed25519(seedHex: string, message: Uint8Array): Uint8Array {
    const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seedHex, "hex")]);
    return new Uint8Array(edSign(null, message, createPrivateKey({ key: der, format: "der", type: "pkcs8" })));
  }
  const requests: SigningRequest[] = [];
  const solana = {
    account,
    async sign(r: SigningRequest): Promise<Signature> {
      requests.push(r);
      if (r.kind !== "batch") throw new Error(r.kind);
      return r.requests.map((q) => base58(ed25519(S.payerSeed, (q as { message: Uint8Array }).message)));
    },
  };
  function unwrap<T extends object>(v: T): Exclude<T, Declined | ToApprove> {
    if ("decline" in v) throw new Error(`${(v as Declined).decline.code}: ${(v as Declined).decline.detail}`);
    if ("approve" in v) throw new Error("an agreement payment to approve");
    return v as Exclude<T, Declined | ToApprove>;
  }

  it("x402/batch-settlement/solana: the opening is held and ES3's voucher is returned, its boundWithin refusing not-bound-within", async () => {
    for (const binding of [batchSvm as Binding, other.batchSvm]) {
      const base = { x402Version: 2, resource: BV.fixed.resource, accepts: [S.option] } as PaymentRequired;
      const doc = (binding as unknown as { advertise(d: unknown, h: string, l: string, o: unknown): unknown }).advertise(
        base,
        H,
        LINK,
        S.option,
      );
      const opened = unwrap(await transact(doc, binding, solana, serving(ABC), { inputs }));
      const hold = unwrap(await openChannel(opened.bytes, opened.signed!, binding));
      expect(hold).toMatchObject({ network: BV.ES4.expectRef.network, channel: BV.ES1.channelPda, h: H, charged: "0" });
      requests.length = 0;
      const out = unwrap(await within(doc, JSON.parse(JSON.stringify(hold)), binding, solana));
      expect(requests.length).toBe(1);
      const r = requests[0]!;
      if (r.kind !== "batch" || r.requests[0]!.kind !== "ed25519-raw") throw new Error("request");
      expect(Buffer.from(r.requests[0]!.message).toString("hex")).toBe(BV.ES3.message);
      expect(out.hold.channel).toBe(BV.ES1.channelPda);
    }
  });
});
