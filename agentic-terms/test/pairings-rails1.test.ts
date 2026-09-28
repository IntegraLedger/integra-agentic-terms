// B2, B6, B10 and B16 for the x402 pairings on Solana (exact, upto), Stellar, XRPL, Hedera (exact, transfer-executor)
// and Algorand. Expected messages, bytes, signatures and payments are the vector files'; the Ed25519 keys come from
// the seeds those files publish as test values.
import { createPrivateKey, createPublicKey, createHash, sign, verify } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { Json } from "@integraledger/lcp";
import { exactAvm } from "@integraledger/lcp/avm";
import { exactHedera, exactHederaExecutor } from "@integraledger/lcp/hedera";
import { decodeSvmTx } from "@integraledger/lcp/svm";
import type { PaymentRequired, PaymentRequirements } from "@integraledger/lcp/x402";
import { exactSvm } from "@integraledger/lcp/x402-exact-solana";
import { exactStellar } from "@integraledger/lcp/x402-exact-stellar";
import { exactXrpl } from "@integraledger/lcp/x402-exact-xrpl";
import { uptoSvm } from "@integraledger/lcp/x402-upto-solana";
import { confirm, finish, type Binding, type Signature, type SigningRequest } from "../src/index.js";
import {
  ABC,
  buildAndSign,
  code,
  H,
  isDeclined,
  LINK,
  serving,
  toHex,
  fromHex,
  vectors,
  type Pairing,
} from "./support.js";

// ── helpers ──────────────────────────────────────────────────────────────────────────────────────────────────────

/** The seller's document for the fixed option, as the pairing's `advertise` places H and the link. */
function docOf(binding: Binding, option: PaymentRequirements, resource: { url: string }): PaymentRequired {
  const base = { x402Version: 2, resource, accepts: [option] } as PaymentRequired;
  const placed = (binding as unknown as { advertise(d: PaymentRequired, h: string, l: string, o: unknown): unknown })
    .advertise(base, H, LINK, option);
  if (typeof placed === "object" && placed !== null && "refused" in placed) throw new Error(JSON.stringify(placed));
  return placed as PaymentRequired;
}

/** The document with its legal context's link as `http://`. */
function httpDoc(doc: PaymentRequired): PaymentRequired {
  const lc = doc.extensions!["legalContext"] as { info: Record<string, Json>; schema: Json };
  const info = { ...lc.info, legalContextUrl: String(lc.info["legalContextUrl"]).replace("https://", "http://") };
  return { ...doc, extensions: { ...doc.extensions, legalContext: { ...lc, info } } } as PaymentRequired;
}

/** The document also advertising the payment-identifier extension. */
function withIdentifier(doc: PaymentRequired): PaymentRequired {
  return { ...doc, extensions: { ...doc.extensions, "payment-identifier": { info: {}, schema: {} } } } as PaymentRequired;
}

/** An Ed25519 key from its 32-byte seed. */
function ed25519(seedHex: string) {
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seedHex, "hex")]);
  const privateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  const jwk = createPublicKey(privateKey).export({ format: "jwk" }) as { x: string };
  return {
    publicKey: Uint8Array.from(Buffer.from(jwk.x, "base64url")),
    sign: (m: Uint8Array) => Uint8Array.from(sign(null, m, privateKey)),
    verify: (m: Uint8Array, s: Uint8Array) => verify(null, m, createPublicKey(privateKey), s),
  };
}

const sha256 = (b: Uint8Array): string => createHash("sha256").update(b).digest("hex");

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

/** Freezes the clock at `now`, and restores it. */
async function at<T>(now: number, run: () => Promise<T>): Promise<T> {
  const real = Date.now;
  Date.now = () => now * 1000;
  try {
    return await run();
  } finally {
    Date.now = real;
  }
}

/** A v0 message's instructions: program, accounts with their signer and writable flags, and data, as addresses. */
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
    blockhash: base58(tx.blockhash),
    instructions: tx.instructions.map((ix) => ({
      program: base58(tx.keys[ix.program]!),
      accounts: ix.accounts.map((a) => ({ address: base58(tx.keys[a]!), ...flags(a) })),
      data: Buffer.from(ix.data).toString("hex"),
    })),
  };
}

/** B10 and B16 for a pairing: an http link is declined before any fetch; other accounts have no payable option. */
function refusals(p: Pairing, others: readonly string[]) {
  it("B10: an http link is offer-unreadable, x402/link-not-https, before any fetch", async () => {
    const fetch = serving(ABC);
    const out = await confirm(httpDoc(p.doc as PaymentRequired), p.binding, p.account, fetch, p.inputs);
    expect(code(out)).toBe("offer-unreadable");
    expect(isDeclined(out) && out.decline.detail).toBe("x402/link-not-https");
    expect(fetch.calls).toBe(0);
  });
  it("B16: an account of another namespace, and one on another network, have no payable option; nothing is fetched", async () => {
    for (const account of others) {
      const fetch = serving(ABC);
      expect(code(await confirm(p.doc, p.binding, account, fetch, p.inputs))).toBe("no-payable-option");
      expect(fetch.calls).toBe(0);
    }
  });
}

const EVM_ACCOUNT = "eip155:84532:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

type Option = PaymentRequirements;
const answering = (f: (r: SigningRequest) => Signature | Promise<Signature>) => async (r: SigningRequest) => f(r);

// ── x402/exact/solana ────────────────────────────────────────────────────────────────────────────────────────────

describe("x402/exact/solana", () => {
  type Ix = { program: string; accounts: { address: string; signer: boolean; writable: boolean }[]; data: string };
  const S = vectors<{
    fixed: { payer: string; payerSeed: string; feePayer: string; blockhash: string; decimals: number;
      tokenProgram: string; option: Option; resource: { url: string } };
    V1: { feePayer: string; blockhash: string; instructions: Ix[]; messageLength: number; messageFirstByte: number };
    defaultComputeBudget: { instructions: Ix[] };
  }>("x402-exact-solana.json");
  const f = S.fixed;
  const payer = ed25519(f.payerSeed);
  const answer = answering((r) => {
    if (r.kind !== "solana-message") throw new Error(r.kind);
    return toHex(payer.sign(r.message));
  });
  const p: Pairing = {
    binding: exactSvm,
    doc: docOf(exactSvm, f.option, f.resource),
    account: `${f.option.network}:${f.payer}`,
    inputs: { decimals: f.decimals, tokenProgram: f.tokenProgram, recentBlockhash: f.blockhash },
    answer,
  };

  it("the payer's key is the vector's payer", () => expect(base58(payer.publicKey)).toBe(f.payer));
  it("B6: the message decompiles to V1's instructions; the payer's signature completes a payment bound to H", async () => {
    let message: Uint8Array = new Uint8Array();
    const { signed } = await buildAndSign(p, (r) => {
      if (r.kind !== "solana-message") throw new Error(r.kind);
      message = r.message;
      expect(message.length).toBe(S.V1.messageLength);
      expect(message[0]).toBe(S.V1.messageFirstByte);
      const m = decompile(message);
      expect(m.feePayer).toBe(S.V1.feePayer);
      expect(m.blockhash).toBe(S.V1.blockhash);
      // Built with no computeUnitLimit or computeUnitPrice input: the Compute Budget prefix is the vector's default.
      expect(m.instructions).toEqual([...S.defaultComputeBudget.instructions, ...S.V1.instructions.slice(2)]);
    });
    const wire = Buffer.from((signed as { payload: { transaction: string } }).payload.transaction, "base64");
    const tx = decodeSvmTx(new Uint8Array(wire));
    if ("refused" in tx) throw new Error(tx.code);
    expect(toHex(tx.message)).toBe(toHex(message));
    const slot = tx.keys.findIndex((k) => base58(k) === f.payer);
    expect(payer.verify(message, tx.signatures[slot]!)).toBe(true);
    expect(tx.signatures[0]!.every((b) => b === 0)).toBe(true);
  });
  it("the offer's extra.recentBlockhash is the build's when the option names one", async () => {
    const option = { ...f.option, extra: { ...f.option.extra, recentBlockhash: f.blockhash } } as Option;
    const doc = docOf(exactSvm, option, f.resource);
    const out = await confirm(doc, exactSvm, p.account, serving(ABC), { decimals: f.decimals, tokenProgram: f.tokenProgram });
    if (isDeclined(out) || out.request === null || out.request.kind !== "solana-message") throw new Error("no request");
    expect(decompile(out.request.message).blockhash).toBe(S.V1.blockhash);
  });
  it("a missing input is declined before any fetch", async () => {
    const fetch = serving(ABC);
    const out = await confirm(p.doc, exactSvm, p.account, fetch, { decimals: f.decimals, recentBlockhash: f.blockhash });
    expect(code(out)).toBe("no-payable-option");
    expect(isDeclined(out) && out.decline.detail).toBe("x402/input-missing");
    expect(fetch.calls).toBe(0);
  });
  refusals(p, [EVM_ACCOUNT, `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:${f.payer}`]);
});

// ── x402/upto/solana ─────────────────────────────────────────────────────────────────────────────────────────────

describe("x402/upto/solana", () => {
  const U = vectors<{
    fixed: { payer: string; payerSeed: string; receiverAuthorizer: string; blockhash: string; nonce: string;
      openSlot: string; now: number; tokenProgram: string; option: Option; resource: { url: string } };
    EU1: { channelPda: string };
    EU2: { openInstructionData: string };
    EU3: { messageLength: number; feePayer: string; blockhash: string;
      instructions: { program: string; accounts: [string, boolean, boolean][]; data: string }[] };
  }>("x402-upto-solana.json");
  const f = U.fixed;
  const payer = ed25519(f.payerSeed);
  const inputs = { nonce: f.nonce, openSlot: f.openSlot, tokenProgram: f.tokenProgram, recentBlockhash: f.blockhash };
  const p: Pairing = {
    binding: uptoSvm,
    doc: docOf(uptoSvm, f.option, f.resource),
    account: `${f.option.network}:${f.payer}`,
    inputs,
    answer: answering((r) => {
      if (r.kind !== "solana-message") throw new Error(r.kind);
      return toHex(payer.sign(r.message));
    }),
  };
  const expected = U.EU3.instructions.map((ix) => ({
    program: ix.program,
    accounts: ix.accounts.map(([address, signer, writable]) => ({ address, signer, writable })),
    data: ix.data,
  }));
  it("B6: the open message decompiles to EU3's instructions; the signed payment opens EU1's channel bound to H", () =>
    at(f.now, async () => {
      let message: Uint8Array = new Uint8Array();
      const { signed } = await buildAndSign(p, (r) => {
        if (r.kind !== "solana-message") throw new Error(r.kind);
        message = r.message;
        expect(message.length).toBe(U.EU3.messageLength);
        const m = decompile(message);
        expect(m.feePayer).toBe(U.EU3.feePayer);
        expect(m.blockhash).toBe(U.EU3.blockhash);
        expect(m.instructions).toEqual(expected);
        expect(m.instructions[2]!.data).toBe(U.EU2.openInstructionData);
      });
      const payload = (signed as { payload: Record<string, unknown> }).payload;
      expect(payload).toMatchObject({
        from: f.payer,
        maxAmount: f.option.amount,
        deposit: f.option.amount,
        expiresAt: f.now + f.option.maxTimeoutSeconds,
        validAfter: f.now,
        nonce: f.nonce,
        openSlot: Number(f.openSlot),
        channelId: U.EU1.channelPda,
        authorizedSigner: f.receiverAuthorizer,
      });
      const tx = decodeSvmTx(new Uint8Array(Buffer.from(payload["openTransaction"] as string, "base64")));
      if ("refused" in tx) throw new Error(tx.code);
      const slot = tx.keys.findIndex((k) => base58(k) === f.payer);
      expect(payer.verify(message, tx.signatures[slot]!)).toBe(true);
    }));
  it("without a nonce input, the choice carries a fresh random u64 nonce", () =>
    at(f.now, async () => {
      const { nonce: _given, ...rest } = inputs;
      const nonces = [];
      for (let i = 0; i < 2; i++) {
        const out = await confirm(p.doc, uptoSvm, p.account, serving(ABC), rest);
        if (isDeclined(out)) throw new Error(out.decline.code);
        const n = (out.chosen.choice as { nonce: string }).nonce;
        expect(n).toMatch(/^[0-9]{1,20}$/);
        expect(BigInt(n) < 1n << 64n).toBe(true);
        nonces.push(n);
      }
      expect(nonces[0]).not.toBe(nonces[1]);
    }));
  refusals(p, [EVM_ACCOUNT, `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:${f.payer}`]);
});

// ── x402/exact/stellar ───────────────────────────────────────────────────────────────────────────────────────────

describe("x402/exact/stellar", () => {
  const T = vectors<{
    fixed: { payer: string; payerSeed: string; option: Option; resource: { url: string } };
    V1: { M: string };
    V2: { simulatedXdr: string; currentLedger: number; expectPreimageLength: number; expectPreimageSha256: string;
      expectSignaturePrefix: string; expectSignatureSuffix: string; expectEnvelope: string };
  }>("x402-exact-stellar.json");
  const f = T.fixed;
  const payer = ed25519(f.payerSeed);
  const p: Pairing = {
    binding: exactStellar,
    doc: docOf(exactStellar, f.option, f.resource),
    account: `${f.option.network}:${f.payer}`,
    inputs: { simulatedXdr: T.V2.simulatedXdr, currentLedger: T.V2.currentLedger },
    answer: answering((r) => {
      if (r.kind !== "stellar-auth") throw new Error(r.kind);
      return toHex(payer.sign(fromHex(sha256(r.preimage))));
    }),
  };
  it("B6: the preimage is V2's; the payer's signature completes V2's envelope as payload.transaction", async () => {
    expect((p.doc as PaymentRequired).accepts[0]!.payTo).toBe(T.V1.M);
    const { signed } = await buildAndSign(p, async (r) => {
      if (r.kind !== "stellar-auth") throw new Error(r.kind);
      expect(r.preimage.length).toBe(T.V2.expectPreimageLength);
      expect(sha256(r.preimage)).toBe(T.V2.expectPreimageSha256);
      const s = (await p.answer(r)) as string;
      expect(s.startsWith(`0x${T.V2.expectSignaturePrefix}`)).toBe(true);
      expect(s.endsWith(T.V2.expectSignatureSuffix)).toBe(true);
    });
    expect(signed).toMatchObject({
      x402Version: 2,
      resource: f.resource,
      accepted: (p.doc as PaymentRequired).accepts[0],
      payload: { transaction: T.V2.expectEnvelope },
      extensions: (p.doc as PaymentRequired).extensions,
    });
  });
  it("the payment identifier is appended to the echoed extension where the challenge advertises it", async () => {
    const q = { ...p, doc: withIdentifier(p.doc as PaymentRequired) };
    const { signed } = await buildAndSign(q, () => undefined);
    const ext = (signed as { extensions: Record<string, { info: { id?: string } }> }).extensions;
    expect(ext["payment-identifier"]!.info.id).toMatch(/^[A-Za-z0-9_-]{32}$/);
  });
  refusals(p, [EVM_ACCOUNT, `stellar:pubnet:${f.payer}`]);
  // x402 v2's PaymentRequirements carries `network` as a string, a CAIP-2 network id; the Python gate declines the same
  // documents with the same code.
  it.each([[], {}, [["x"]], 1, null, true])("an option whose network is %j has no payable option; nothing is fetched", async (network) => {
    const doc = p.doc as PaymentRequired;
    const odd = { ...doc, accepts: [{ ...doc.accepts[0]!, network }] } as unknown as PaymentRequired;
    let fetched = 0;
    const fetch = async () => (fetched++, new Response("abc"));
    const out = await confirm(odd, exactStellar, p.account, fetch, p.inputs);
    expect(out).toEqual({ decline: { code: "offer-unreadable", detail: "x402/no-payable-option" } });
    expect(fetched).toBe(0);
  });
});

// ── x402/exact/xrpl ──────────────────────────────────────────────────────────────────────────────────────────────

describe("x402/exact/xrpl", () => {
  const X = vectors<{
    fixed: { payer: string; option: Option; resource: { url: string } };
    V2: { blob: string; build: { fee: string; sequence: number; lastLedgerSequence: number };
      expectTxJson: Record<string, unknown> };
  }>("x402-exact-xrpl.json");
  const f = X.fixed;
  // The vector publishes the signed blob, not the payer's key: the wallet stub checks the request is V2's Payment and
  // answers with V2's blob.
  const p: Pairing = {
    binding: exactXrpl,
    doc: docOf(exactXrpl, f.option, f.resource),
    account: `${f.option.network}:${f.payer}`,
    inputs: X.V2.build,
    answer: answering((r) => {
      if (r.kind !== "xrpl-tx") throw new Error(r.kind);
      expect(r.txJson).toEqual(X.V2.expectTxJson);
      return `0x${X.V2.blob}`;
    }),
  };
  it("B6: the Payment is V2's; V2's signed blob completes a payment bound to H", async () => {
    const { signed } = await buildAndSign(p, (r) => {
      if (r.kind !== "xrpl-tx") throw new Error(r.kind);
      expect(r.txJson).toEqual(X.V2.expectTxJson);
    });
    expect((signed as { payload: unknown }).payload).toEqual({ signedTxBlob: X.V2.blob });
  });
  it("a ticketSequence option takes ticketSequence, not sequence", async () => {
    const option = { ...f.option, extra: { ...f.option.extra, assetTransferMethod: "ticketSequence" } } as Option;
    const doc = docOf(exactXrpl, option, f.resource);
    const { sequence: _s, ...rest } = X.V2.build;
    const out = await confirm(doc, exactXrpl, p.account, serving(ABC), { ...rest, ticketSequence: 9 });
    if (isDeclined(out) || out.request === null || out.request.kind !== "xrpl-tx") throw new Error("no request");
    expect(out.request.txJson).toMatchObject({ Sequence: 0, TicketSequence: 9 });
  });
  refusals(p, [EVM_ACCOUNT, `xrpl:0:${f.payer}`]);
});

// ── x402/exact/hedera ────────────────────────────────────────────────────────────────────────────────────────────

describe("x402/exact/hedera", () => {
  const E = vectors<{
    fixed: { O: Option; resource: { url: string }; payer: string; node: string;
      validStart: { seconds: string; nanos: number }; maxFee: string; publicKey: string; signature: string };
    V2: { expectBodyBytes: string; expectTransactionBase64: string };
  }>("x402-exact-hedera.json");
  const f = E.fixed;
  // The payer key is Ed25519 seed 03×32, as the Hedera vectors name it.
  const payer = ed25519("03".repeat(32));
  const p: Pairing = {
    binding: exactHedera,
    doc: docOf(exactHedera, f.O, f.resource),
    account: `${f.O.network}:${f.payer}`,
    inputs: { node: f.node, validStart: f.validStart, maxFee: f.maxFee },
    answer: answering((r) => {
      if (r.kind !== "hedera-body") throw new Error(r.kind);
      return { publicKey: toHex(payer.publicKey), signature: toHex(payer.sign(r.bodyBytes)), type: "ed25519" };
    }),
  };

  it("the payer's key is the vector's public key", () => expect(toHex(payer.publicKey)).toBe(`0x${f.publicKey}`));
  it("B6: the body is V2's 131 bytes; the payer's signature completes V2's transaction as payload.transaction", async () => {
    const { signed } = await buildAndSign(p, async (r) => {
      if (r.kind !== "hedera-body") throw new Error(r.kind);
      expect(toHex(r.bodyBytes)).toBe(`0x${E.V2.expectBodyBytes}`);
      expect(((await p.answer(r)) as { signature: string }).signature).toBe(`0x${f.signature}`);
    });
    expect(signed).toMatchObject({
      x402Version: 2,
      resource: f.resource,
      accepted: f.O,
      payload: { transaction: E.V2.expectTransactionBase64 },
    });
  });
  it("the payment identifier is appended to the echoed extension where the challenge advertises it", async () => {
    const q = { ...p, doc: withIdentifier(p.doc as PaymentRequired) };
    const { signed } = await buildAndSign(q, () => undefined);
    const ext = (signed as { extensions: Record<string, { info: { id?: string } }> }).extensions;
    expect(ext["payment-identifier"]!.info.id).toMatch(/^[A-Za-z0-9_-]{32}$/);
  });
  refusals(p, [EVM_ACCOUNT, `hedera:mainnet:${f.payer}`]);
});

// ── x402/exact/hedera/transfer-executor ──────────────────────────────────────────────────────────────────────────

describe("x402/exact/hedera/transfer-executor", () => {
  const V = vectors<{
    fixed: { O: Option; payload: { payer: string; executor: string; authorization: string };
      resource: { url: string }; now: number };
    build: { expectRequest: Record<string, unknown> };
  }>("x402-exact-hedera-transfer-executor.json");
  const f = V.fixed;
  const p: Pairing = {
    binding: exactHederaExecutor,
    doc: docOf(exactHederaExecutor, f.O, f.resource),
    account: `${f.O.network}:${f.payload.payer}`,
    answer: answering((r) => {
      if (r.kind !== "hedera-executor") throw new Error(r.kind);
      return f.payload;
    }),
  };
  it("B6: the request is the vector's; the wallet's authorization completes a payment whose echoed extension is H", () =>
    at(f.now, async () => {
      const { signed } = await buildAndSign(p, (r) => expect(r).toEqual(V.build.expectRequest));
      expect(signed).toMatchObject({ x402Version: 2, accepted: f.O, payload: f.payload });
    }));
  refusals(p, [EVM_ACCOUNT, `hedera:mainnet:${f.payload.payer}`]);
});

// ── x402/exact/algorand ──────────────────────────────────────────────────────────────────────────────────────────

describe("x402/exact/algorand", () => {
  const A = vectors<{
    fixed: { O: Option; payer: string; resource: { url: string }; params: Record<string, string>; signature: string };
    V2: { expectBytesToSign: string; expectPaymentGroup: string[]; expectPaymentIndex: number };
  }>("x402-exact-algorand.json");
  const f = A.fixed;
  // The payer key is Ed25519 seed 01×32, as the Algorand vectors name it.
  const payer = ed25519("01".repeat(32));
  const p: Pairing = {
    binding: exactAvm,
    doc: docOf(exactAvm, f.O, f.resource),
    account: `${f.O.network}:${f.payer}`,
    inputs: { params: f.params },
    answer: answering((r) => {
      if (r.kind !== "algorand-txn") throw new Error(r.kind);
      return toHex(payer.sign(r.bytes));
    }),
  };
  it("B6: the bytes to sign are V2's; the payer's signature completes V2's payment group", async () => {
    const { signed } = await buildAndSign(p, async (r) => {
      if (r.kind !== "algorand-txn") throw new Error(r.kind);
      expect(toHex(r.bytes)).toBe(`0x${A.V2.expectBytesToSign}`);
      expect(await p.answer(r)).toBe(`0x${f.signature}`);
    });
    expect((signed as { payload: unknown }).payload).toEqual({
      paymentIndex: A.V2.expectPaymentIndex,
      paymentGroup: A.V2.expectPaymentGroup,
    });
  });
  refusals(p, [EVM_ACCOUNT, `algorand:wGHE2Pwdvd7S12BL5FaOP20EGYesN73k:${f.payer}`]);
});

// ── the answer's form ────────────────────────────────────────────────────────────────────────────────────────────

describe("a signer's answer in another form is not bound", () => {
  it("a Solana signature that is not 64 bytes of 0x hex is signed-not-bound", async () => {
    const S = vectors<{ fixed: { payer: string; decimals: number; tokenProgram: string; blockhash: string;
      option: Option; resource: { url: string } } }>("x402-exact-solana.json");
    const f = S.fixed;
    const doc = docOf(exactSvm, f.option, f.resource);
    const account = `${f.option.network}:${f.payer}`;
    const out = await confirm(doc, exactSvm, account, serving(ABC), {
      decimals: f.decimals, tokenProgram: f.tokenProgram, recentBlockhash: f.blockhash,
    });
    if (isDeclined(out)) throw new Error(out.decline.code);
    expect(code(await finish(ABC, out.chosen, "0x1234", exactSvm))).toBe("signed-not-bound");
  });
});
