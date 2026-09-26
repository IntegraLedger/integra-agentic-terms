// B2, B6, B10 and B16 for MPP's charges on Hedera, Solana, Stellar, XRPL and NEAR Intents, and its sessions on Hedera,
// Solana and XRPL. Expected requests, bytes, digests, signatures and credentials are the vector files'; the keys come
// from the seeds and keys those files publish as test values.
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { describe, expect, it } from "vitest";
import { hashTypedData, type Hex, type TypedDataDefinition } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  chargeHedera,
  chargeNearIntents,
  chargeSolana,
  chargeStellar,
  chargeXrpl,
  sessionHedera,
  sessionSolana,
  sessionXrpl,
  type MppChallenge,
  type MppCredential,
} from "@integraledger/lcp/mpp";
import { decodeSvmTx } from "@integraledger/lcp/svm";
import { check, confirm, transact, type Binding, type SigningRequest, type Presented } from "../src/index.js";
import { mppChargeHedera } from "../src/pairings/mpp-charge-hedera.js";
import {
  ABC,
  ABD,
  buildAndSign,
  code,
  counting,
  fromHex,
  H,
  isDeclined,
  LINK,
  offered,
  RECEIPT,
  plant,
  serving,
  toHex,
  vectors,
  type Pairing,
} from "./support.js";

// ── helpers ──────────────────────────────────────────────────────────────────────────────────────────────────────

// Vector files are read as loose JSON data; each row names the fields it uses.
type Loose = any;

const b64u = (s: string) => Buffer.from(s, "utf8").toString("base64url");
const sha256 = (b: Uint8Array): string => createHash("sha256").update(b).digest("hex");
const request = (r: SigningRequest) => r as unknown as Record<string, Loose>;

/** The seller's challenges for one issued challenge, as the pairing's `advertise` places H and the link. */
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
    const out = await confirm(httpDoc(p.doc as MppChallenge[]), p.binding, p.account, fetch, p.inputs);
    expect(out).toEqual({ decline: { code: "offer-unreadable", detail: "mpp/link-not-https" } });
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
const SOLANA_DEVNET = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
const SOLANA_MAINNET = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";

// ── mpp/charge/hedera ────────────────────────────────────────────────────────────────────────────────────────────

describe("mpp/charge/hedera", () => {
  const V = vectors<Loose>("mpp-charge-hedera.json");
  const f = V.fixed;
  const issued = {
    realm: f.realm,
    method: "hedera",
    intent: "charge",
    request: b64u(JSON.stringify(f.request)),
    expires: f.expires,
  } as MppChallenge;
  const p: Pairing = {
    binding: chargeHedera,
    doc: docOf(chargeHedera, issued),
    account: `hedera:testnet:${f.payer}`,
    inputs: { node: f.node, validStart: f.validStart, maxFee: f.maxFee },
    answer: async (r) => {
      if (r.kind !== "hedera-body") throw new Error(r.kind);
      expect(toHex(r.bodyBytes)).toBe(`0x${V.build.expectBodyBytes}`);
      return { publicKey: `0x${f.publicKey}`, signature: `0x${f.signature}`, type: "ed25519" };
    },
  };
  // The binding's build takes the challenge, its request and the payer's values; the piece's `build` calls it so.
  const built: Binding = chargeHedera as unknown as Binding;

  it("the placed challenge's id is the vector's", () => {
    expect((p.doc as MppChallenge[])[0]!.id).toBe(f.challengeId);
  });
  it("B6: the body is the vector's, and its signature completes the vector's transaction as a bound credential", async () => {
    const { signed } = await buildAndSign({ ...p, binding: built }, (r) => {
      if (r.kind !== "hedera-body") throw new Error(r.kind);
      expect(toHex(r.bodyBytes)).toBe(`0x${V.build.expectBodyBytes}`);
      const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(f.publicKey, "hex").toString("base64url") }, format: "jwk" });
      expect(verify(null, r.bodyBytes, key, Buffer.from(f.signature, "hex"))).toBe(true);
    });
    expect((signed as MppCredential).payload).toEqual({ type: "transaction", transaction: V.build.expectTransactionBase64 });
    expect((signed as MppCredential).challenge).toEqual((p.doc as MppChallenge[])[0]);
  });
  refusals(p, [EVM_ACCOUNT, `hedera:mainnet:${f.payer}`]);

  // The push form (draft-hedera-charge-00: "Two payload types are defined: "hash" (default) and "transaction" (pull
  // mode)"): the wallet signs and broadcasts the compared body and answers its transaction id.
  const push: Pairing = {
    ...p,
    inputs: { ...p.inputs, credentialType: "hash" },
    answer: async (r) => {
      if (r.kind !== "hedera-body") throw new Error(r.kind);
      return { transactionId: V.push.transactionId };
    },
  };
  it("push B2 · plant: hash-mismatch, and the signer is never called", () => plant(push));
  it("push B6: the vector's body with broadcast; the credential is the hash form, and its landed memo gives H and the vector's reference", async () => {
    const { signed } = await buildAndSign({ ...push, binding: built }, (r) => {
      if (r.kind !== "hedera-body") throw new Error(r.kind);
      expect(toHex(r.bodyBytes)).toBe(`0x${V.build.expectBodyBytes}`);
      expect((r as { broadcast?: unknown }).broadcast).toBe(true);
    });
    expect((signed as MppCredential).payload).toEqual({ type: "hash", transactionId: V.push.transactionId });
    expect(signed).not.toHaveProperty("landed");
    const whole = await transact(push.doc, offered(built), counting(push.account, push.answer), serving(ABC), { inputs: push.inputs! });
    if (isDeclined(whole)) throw new Error(whole.decline.code);
    expect(whole.landed).toEqual(V.fetchPresented.expectLanded);
    expect(await chargeHedera.bound(signed)).toEqual({ refused: true, code: V.push.expectWithout });
    expect(await chargeHedera.reference({ ...(signed as object), landed: whole.landed })).toEqual(V.push.expectReference);
  });
  it("push: the build itself is the protocol package's push request, the vector's body with broadcast true", async () => {
    const choice = {
      challenge: (p.doc as MppChallenge[])[0]!,
      payer: f.payer,
      node: f.node,
      validStart: { seconds: BigInt(f.validStart.seconds), nanos: f.validStart.nanos },
      maxFee: BigInt(f.maxFee),
    };
    const at = async (credentialType?: string) => {
      const u = (await mppChargeHedera.build({ ...choice, ...(credentialType ? { credentialType } : {}) }, H)) as {
        request: { bodyBytes: Uint8Array };
      };
      return { ...u.request, bodyBytes: toHex(u.request.bodyBytes).slice(2) };
    };
    expect(await at("hash")).toEqual(V.build.push.expectRequest);
    expect(await at("transaction")).toEqual(V.build.push.expectPullRequest);
    expect(await at()).toEqual(V.build.push.expectPullRequest);
  });
  it("push: an answer naming another payer or valid start is signed-not-bound, and the moved payment is kept", async () => {
    for (const transactionId of ["0.0.5556@1700000000.000000000", "0.0.5555@1700000001.000000000", "0.0.5555@1700000000.000000001"]) {
      const signer = counting(push.account, async () => ({ transactionId }));
      const out = await transact(push.doc, offered(built), signer, serving(ABC), { inputs: push.inputs! });
      expect(code(out)).toBe("signed-not-bound");
      expect(isDeclined(out) && out.moved).toEqual({ signed: { transactionId }, bytes: ABC, h: H });
      expect(signer.requests.length).toBe(1);
    }
  });
  it("a credentialType other than transaction or hash is no-payable-option before any fetch", async () => {
    const fetch = serving(ABC);
    const out = await confirm(p.doc, built, p.account, fetch, { ...p.inputs, credentialType: "push" });
    expect(out).toEqual({ decline: { code: "no-payable-option", detail: "mpp/input-malformed" } });
    expect(fetch.calls).toBe(0);
  });
});

// ── mpp/charge/solana ────────────────────────────────────────────────────────────────────────────────────────────

describe("mpp/charge/solana", () => {
  const V = vectors<Loose>("mpp-charge-solana.json");
  const X = vectors<Loose>("x402-exact-solana.json");
  const payer = ed25519(fromHex(X.fixed.payerSeed));
  const p: Pairing = {
    binding: chargeSolana,
    doc: docOf(chargeSolana, V.challenge),
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
    const out = await confirm(doc, chargeSolana, p.account, fetch, p.inputs);
    expect(out).toEqual({ decline: { code: "no-payable-option", detail: "mpp/input-missing" } });
    expect(fetch.calls).toBe(0);
  });
  refusals(p, [EVM_ACCOUNT, `${SOLANA_MAINNET}:${V.fixed.payer}`]);
});

// ── mpp/charge/stellar ───────────────────────────────────────────────────────────────────────────────────────────

describe("mpp/charge/stellar", () => {
  const V = vectors<Loose>("mpp-charge-stellar.json");
  const X = vectors<Loose>("x402-exact-stellar.json");
  const payer = ed25519(fromHex(X.fixed.payerSeed));
  // The entry's expiration is currentLedger + ceil((expires − now) / 5): 988 + 12 = V2's expiration 1000.
  const now = Date.parse(V.fixed.expires) / 1000 - 60;
  const p: Pairing = {
    binding: chargeStellar,
    doc: docOf(chargeStellar, V.challenge),
    account: `stellar:testnet:${X.fixed.payer}`,
    inputs: { simulatedXdr: X.V2.simulatedXdr, currentLedger: X.V2.currentLedger },
    answer: async (r) => {
      if (r.kind !== "stellar-auth") throw new Error(r.kind);
      return toHex(payer.sign(fromHex(sha256(r.preimage))));
    },
  };

  it("the placed challenge is the vector's", () => {
    expect(p.doc).toEqual([V.place.expect]);
    expect(X.V2.expectExpiration).toBe(X.V2.currentLedger + 12);
  });
  it("B6: the preimage is V3's authorization digest; the payer's signature completes V3's envelope", () =>
    at(now, async () => {
      const { signed } = await buildAndSign(p, (r) => {
        if (r.kind !== "stellar-auth") throw new Error(r.kind);
        expect(`0x${sha256(r.preimage)}`).toBe(V.V3.expectReference.authDigest);
      });
      expect((signed as MppCredential).payload).toEqual({ type: "transaction", transaction: V.V3.envelope });
    }));
  refusals(p, [EVM_ACCOUNT, `stellar:pubnet:${X.fixed.payer}`]);
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
      return `0x${V.V3.blob}`;
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
      });
      expect(V.V3.blob).toContain(`5011${f.invoiceId}`);
    });
    expect((signed as MppCredential).payload).toEqual({ type: "transaction", blob: V.V3.blob });
  });
  it("without the buyer's ledger reads, no-payable-option before any fetch", async () => {
    const fetch = serving(ABC);
    const out = await confirm(p.doc, p.binding, p.account, fetch, { fee: "12" });
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
    doc: docOf(chargeNearIntents as unknown as Binding, V.challenge),
    account: `${V.fixed.request.methodDetails.originNetwork}:${refundTo}`,
    answer: async () => {
      throw new Error("nothing to sign");
    },
  };

  it("the placed challenge is the vector's", () => {
    expect(p.doc).toEqual([V.place.expect]);
  });
  it("B6: on a match nothing is handed to the signer; the vector's hash credential checks against abc, not abd", async () => {
    const confirmed = await confirm(p.doc, offered(p.binding), p.account, serving(ABC));
    if (isDeclined(confirmed)) throw new Error(confirmed.decline.detail);
    expect(confirmed.h).toBe(H);
    expect(confirmed.request).toBeNull();
    const signer = counting(p.account, p.answer);
    const whole = await transact(p.doc, offered(p.binding), signer, serving(ABC));
    expect(whole).toEqual({ signed: null, bytes: ABC, h: H, agreement: RECEIPT });
    expect(signer.requests.length).toBe(0);
    const credential = { challenge: V.place.expect, payload: V.bound.payload };
    expect(await check(ABC, credential, p.binding)).toEqual({ h: V.bound.expect });
    expect(code(await check(ABD, credential, p.binding))).toBe("signed-not-bound");
  });
  refusals(p, [`near:mainnet:${V.fixed.request.methodDetails.destinationRecipient}`, `eip155:1:${refundTo}`]);
});

// ── mpp/session/hedera ───────────────────────────────────────────────────────────────────────────────────────────

describe("mpp/session/hedera", () => {
  const V = vectors<Loose>("mpp-session-hedera-solana-xrpl.json");
  const f = V.fixed;
  // The published Anvil key #0, whose address is the vectors' payer.
  const anvil = privateKeyToAccount("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
  const p: Pairing = {
    binding: sessionHedera,
    doc: docOf(sessionHedera, V.SS1.hedera.challenge),
    account: `hedera:testnet:${f.payer}`,
    inputs: { deposit: V.HS2.deposit },
    answer: async (r) => {
      const q = request(r);
      if (q["kind"] !== "hedera-session-open") throw new Error(String(q["kind"]));
      return {
        openTx: V.HS3.txHash,
        signature: await anvil.signTypedData(q["voucher"] as TypedDataDefinition),
        // The landed receipt of the opening: HS3's escrow log. The block number is a fixture value `bound` does not read.
        landed: { transaction: V.HS3.txHash, blockNumber: "1", logs: [V.HS3.log] },
      };
    },
  };

  it("the placed challenge is the vector's, and the payer is Anvil #0", () => {
    expect(p.doc).toEqual([V.SS1.hedera.placed]);
    expect(anvil.address).toBe(f.payer);
  });
  it("B6: HS2's approve, open with H as the salt, and voucher digest; HS3's landed log binds the opening to H", async () => {
    const { signed } = await buildAndSign(p, (r) => {
      const q = request(r);
      expect(q["kind"]).toBe("hedera-session-open");
      expect(q["chainId"]).toBe(296);
      const [approve, open] = q["calls"] as { to: Hex; data: Hex }[];
      expect(approve!.to).toBe(f.token);
      expect((approve!.data.length - 2) / 2).toBe(V.HS2.expectApproveLength);
      expect(approve!.data.startsWith(V.HS2.expectApprovePrefix)).toBe(true);
      expect(approve!.data.endsWith(V.HS2.expectApproveSuffix)).toBe(true);
      expect(approve!.data).toContain(V.HS2.expectApproveContains);
      expect(open!.to).toBe(f.escrow.toLowerCase());
      expect((open!.data.length - 2) / 2).toBe(V.HS2.expectOpenLength);
      expect(open!.data.startsWith(V.HS2.expectOpenSelector)).toBe(true);
      const [from, to] = V.HS2.expectOpenSaltBytes as [number, number];
      expect(`0x${open!.data.slice(2 + 2 * from, 2 + 2 * to)}`).toBe(H);
      expect(hashTypedData(q["voucher"] as TypedDataDefinition)).toBe(V.HS2.expectVoucherDigest);
    });
    expect(signed).not.toHaveProperty("landed");
    const payload = (signed as MppCredential).payload;
    expect(payload["action"]).toBe("open");
    expect(payload["channelId"]).toBe(V.HS1.expectChannelId);
    expect(payload["txHash"]).toBe(V.HS3.txHash);
    expect(payload["cumulativeAmount"]).toBe("0");
  });
  refusals(p, [EVM_ACCOUNT, `hedera:mainnet:${f.payer}`]);
});

// ── mpp/session/solana ───────────────────────────────────────────────────────────────────────────────────────────

describe("mpp/session/solana", () => {
  const V = vectors<Loose>("mpp-session-hedera-solana-xrpl.json");
  const X = vectors<Loose>("x402-exact-solana.json");
  const details = JSON.parse(Buffer.from(V.SS1.solana.challenge.request, "base64url").toString("utf8")).methodDetails;
  const payer = ed25519(fromHex(X.fixed.payerSeed));
  const p: Pairing = {
    binding: sessionSolana,
    doc: docOf(sessionSolana, V.SS1.solana.challenge),
    account: `${SOLANA_DEVNET}:${V.SV3.payer}`,
    answer: async (r) => {
      const q = request(r);
      if (q["kind"] !== "solana-session-open") throw new Error(String(q["kind"]));
      // The channel client's open: the vectors' SV2 wire, composed from these values and signed by the payer.
      return { action: "open", channelId: V.SV2.channel, transaction: V.SV2.wireBase64 };
    },
  };

  it("the placed challenge is the vector's; SV2's wire carries the payer's signature over its message", () => {
    expect(p.doc).toEqual([V.SS1.solana.placed]);
    const wire = Uint8Array.from(Buffer.from(V.SV2.wireBase64, "base64"));
    expect(wire.length).toBe(V.SV2.wireLength);
    const message = wire.subarray(1 + 64 * wire[0]!);
    expect(`0x${sha256(message)}`).toBe(V.SV2.expectMessageSha256);
    expect(Buffer.from(message).toString("hex")).toContain(V.SV2.expectOpenData);
    expect(base58(payer.publicKey)).toBe(V.SV3.payer);
    const slots = Array.from({ length: wire[0]! }, (_, i) => toHex(wire.subarray(1 + 64 * i, 65 + 64 * i)));
    expect(slots).toContain(toHex(payer.sign(message)));
  });
  it("B6: the salt is SV1's; the composed open is SV2's and is bound to H", async () => {
    const { signed } = await buildAndSign(p, (r) => {
      const q = request(r);
      expect(q).toEqual({
        kind: "solana-session-open",
        salt: BigInt(V.SV1.expectSalt),
        channelProgram: details.channelProgram,
        network: SOLANA_DEVNET,
        recentBlockhash: details.recentBlockhash,
        recentSlot: BigInt(details.recentSlot),
      });
    });
    expect((signed as MppCredential).payload).toEqual({ action: "open", channelId: V.SV2.channel, transaction: V.SV2.wireBase64 });
  });
  it("the plant's open, salted with H₂'s 8 bytes, is not bound", async () => {
    const confirmed = await confirm(p.doc, p.binding, p.account, serving(ABC));
    if (isDeclined(confirmed)) throw new Error(confirmed.decline.detail);
    const { finish } = await import("../src/index.js");
    const out = await finish(ABC, confirmed.chosen, { action: "open", channelId: V.plants.solana.channel, transaction: V.plants.solana.wireBase64 }, p.binding);
    expect(out).toEqual({ decline: { code: "signed-not-bound", detail: V.plants.solana.expect } });
  });
  describe("SV5 · operator mode", () => {
    const issued = JSON.parse(Buffer.from(V.SS1.solana.challenge.request, "base64url").toString("utf8"));
    const operatorRequest = { ...issued, methodDetails: { ...issued.methodDetails, ...V.SV5.methodDetails } };
    const doc = docOf(sessionSolana, { ...V.SS1.solana.challenge, request: b64u(JSON.stringify(operatorRequest)) });
    const proofText = new TextEncoder().encode(V.SV3.expectProofText);
    const operatorSigner = (kinds: string[]) => ({
      account: p.account,
      async sign(r: SigningRequest) {
        const q = request(r);
        kinds.push(q["kind"]);
        if (q["kind"] === "solana-session-open") return { action: "open", channelId: V.SV2.channel, transaction: V.SV2.wireBase64 };
        if (q["kind"] === "ed25519-raw") return base58(payer.sign(q["message"] as Uint8Array));
        throw new Error(String(q["kind"]));
      },
    });

    it("the payer signs SV3's session proof after the open, and the open carries it as authentication", async () => {
      expect(sha256(proofText).startsWith(V.SV3.expectProofSha256Prefix)).toBe(true);
      expect(sha256(proofText).endsWith(V.SV3.expectProofSha256Suffix)).toBe(true);
      const proofSignature = payer.sign(proofText);
      expect(toHex(proofSignature).slice(2).startsWith(V.SV3.expectProofSignaturePrefix)).toBe(true);
      expect(toHex(proofSignature).endsWith(V.SV3.expectProofSignatureSuffix)).toBe(true);

      const kinds: string[] = [];
      const seen: Record<string, Loose>[] = [];
      const signer = operatorSigner(kinds);
      const out = await transact(doc, sessionSolana, { ...signer, sign: (r) => (seen.push(request(r)), signer.sign(r)) }, serving(ABC));
      if (isDeclined(out)) throw new Error(out.decline.detail);
      expect(kinds).toEqual(V.SV5.expectRequestKinds);
      expect(Buffer.from(seen[1]!["message"] as Uint8Array).toString("utf8")).toBe(V.SV3.expectProofText);
      expect(seen[1]!["signer"]).toBe(V.SV3.payer);
      const payload = (out.signed as MppCredential).payload as Record<string, Loose>;
      expect(Object.keys(payload["authentication"])).toEqual(V.SV5.expectAuthenticationKeys);
      expect(payload["authentication"]).toEqual({ ...V.SV5.expectAuthentication, signature: base58(proofSignature) });
      expect(payload).toMatchObject({ action: "open", channelId: V.SV2.channel, transaction: V.SV2.wireBase64 });
      expect(await sessionSolana.bound(out.signed)).toBe(H);
      const use = { ...(out.signed as MppCredential), payload: { ...payload, action: "use" } };
      expect(await sessionSolana.channel.boundWithin(use as never)).toBe(H);
    });

    it("without operator mode the open alone completes the credential, with no authentication", async () => {
      const kinds: string[] = [];
      const out = await transact(p.doc, sessionSolana, operatorSigner(kinds), serving(ABC));
      if (isDeclined(out)) throw new Error(out.decline.detail);
      expect(kinds).toEqual([V.SV5.expectRequestKinds[0]]);
      expect((out.signed as MppCredential).payload).not.toHaveProperty("authentication");
    });
  });
  refusals(p, [EVM_ACCOUNT, `${SOLANA_MAINNET}:${V.SV3.payer}`]);
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
    answer: async (r) => {
      const q = request(r);
      if (q["kind"] !== "xrpl-session-open") throw new Error(String(q["kind"]));
      return { signedBlob: `0x${s.blob}`, claimSignature: toHex(payer.sign(q["claim"].bytes)) };
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
  refusals(p, [EVM_ACCOUNT, `xrpl:0:${s.account}`]);
});
