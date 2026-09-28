// B2 and B6 for MPP's `card`, `stripe` and `usdc` pairings. Expected values are the lcp vector files' (M1-M5); keys are the published Anvil key #0 and the Solana vectors' test seed, and the Stacks
// transaction is M4's bytes, signed there by the key whose scalar is 1.
import { createPrivateKey, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { hashTypedData, type TypedDataDefinition } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  chargeCard,
  chargeStripe,
  chargeUsdcEvm,
  chargeUsdcGateway,
  chargeUsdcSolana,
  chargeUsdcStacks,
  subscriptionStripe,
  usdcGatewaySalt,
  type MppChallenge,
  type MppCredential,
} from "@integraledger/lcp/mpp";
import { confirm, transact, type Binding, type SigningRequest } from "../src/index.js";
import { ABC, buildAndSign, counting, fromHex, H, isDeclined, LINK, offered, RECEIPT, serving, toHex, vectors, type Pairing } from "./support.js";

// Vector files are read as loose JSON data; each row names the fields it uses.
type Loose = any;

const b64u = (s: string) => Buffer.from(s, "utf8").toString("base64url");
const AGREEMENT = `https://pay.seller.example/agreement/${H}`;
const ANVIL = privateKeyToAccount("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

function issued(method: string, intent: string, request: unknown, realm: string, expires: string): MppChallenge {
  return { realm, method, intent, request: b64u(typeof request === "string" ? request : JSON.stringify(request)), expires };
}

/** The seller's challenges for one issued challenge, as the pairing's `advertise` places H, the link and, when given, the agreement URL. */
function docOf(binding: unknown, c: MppChallenge, agreementUrl?: string): MppChallenge[] {
  const placed = (binding as { advertise(d: unknown, h: string, l: string, o: unknown, a?: string): unknown }).advertise(
    [c],
    H,
    LINK,
    c,
    ...(agreementUrl === undefined ? [] : [agreementUrl]),
  );
  if (!Array.isArray(placed)) throw new Error(JSON.stringify(placed));
  return placed as MppChallenge[];
}

/** An Ed25519 key from its 32-byte seed. */
function ed25519(seed: Uint8Array) {
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seed)]);
  const privateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  return { sign: (m: Uint8Array) => Uint8Array.from(sign(null, m, privateKey)) };
}

// ── card and Stripe: confirm only ────────────────────────────────────────────────────────────────────────────────

const CARD = vectors<Loose>("mpp-charge-card.json");
const STRIPE = vectors<Loose>("mpp-charge-stripe.json");
const SUB = vectors<Loose>("mpp-subscription-stripe.json");

const confirmOnly: [string, unknown, MppChallenge][] = [
  ["mpp/charge/card", chargeCard, issued("card", "charge", CARD.M1.request, CARD.fixed.realm, CARD.fixed.expires)],
  ["mpp/charge/stripe", chargeStripe, issued("stripe", "charge", STRIPE.M2.request, CARD.fixed.realm, CARD.fixed.expires)],
  ["mpp/subscription/stripe", subscriptionStripe, issued("stripe", "subscription", SUB.S1.request, CARD.fixed.realm, CARD.fixed.expires)],
];

describe.each(confirmOnly)("%s (confirm only)", (_id, binding, challenge) => {
  const p: Pairing = {
    binding: binding as Binding,
    doc: docOf(binding, challenge),
    account: "eip155:84532:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    answer: async () => {
      throw new Error("nothing to sign");
    },
  };

  it("B6: on a match nothing is handed to the signer", async () => {
    const confirmed = await confirm(p.doc, offered(p.binding), p.account, serving(ABC));
    if (isDeclined(confirmed)) throw new Error(confirmed.decline.detail);
    expect(confirmed.h).toBe(H);
    expect(confirmed.request).toBeNull();
    const signer = counting(p.account, p.answer);
    expect(await transact(p.doc, offered(p.binding), signer, serving(ABC))).toEqual({ signed: null, bytes: ABC, h: H, agreement: RECEIPT });
    expect(signer.requests.length).toBe(0);
  });

  it("the offer's agreement URL reaches the buyer, who pays it before the payment", async () => {
    const confirmed = await confirm(docOf(binding, challenge, AGREEMENT), p.binding, p.account, serving(ABC));
    if (isDeclined(confirmed)) throw new Error(confirmed.decline.detail);
    expect(confirmed).toMatchObject({ chosen: { agreement: AGREEMENT }, request: null, h: H });
  });
});

// ── usdc/evm ─────────────────────────────────────────────────────────────────────────────────────────────────────

describe("mpp/charge/usdc/evm", () => {
  const V = vectors<Loose>("mpp-charge-usdc-evm.json");
  const f = V.fixed;
  const p: Pairing = {
    binding: chargeUsdcEvm as unknown as Binding,
    doc: docOf(chargeUsdcEvm, issued("usdc", "charge", V.M3.requestJson, f.realm, f.expires)),
    account: `eip155:84532:${f.payer}`,
    inputs: { tokenDomain: f.tokenDomain },
    answer: async (r) => {
      if (r.kind !== "eip712") throw new Error(r.kind);
      return ANVIL.signTypedData(r.typedData as unknown as TypedDataDefinition);
    },
  };
  it("B6: the authorization's nonce and digest are M3's, and the signed credential is bound to H", async () => {
    await buildAndSign(p, (r) => {
      if (r.kind !== "eip712") throw new Error(r.kind);
      expect((r.typedData.message as { nonce: string }).nonce).toBe(V.M3.expectNonce);
      expect(hashTypedData(r.typedData as unknown as TypedDataDefinition)).toBe(V.M3.expectDigest);
    });
  });
});

// ── usdc/solana ──────────────────────────────────────────────────────────────────────────────────────────────────

describe("mpp/charge/usdc/solana", () => {
  const V = vectors<Loose>("mpp-charge-usdc-solana.json");
  const S = vectors<Loose>("mpp-charge-solana.json");
  const X = vectors<Loose>("x402-exact-solana.json");
  const payer = ed25519(fromHex(X.fixed.payerSeed));
  const p: Pairing = {
    binding: chargeUsdcSolana as unknown as Binding,
    doc: docOf(chargeUsdcSolana, issued("usdc", "charge", V.fixed.request, V.fixed.realm, V.fixed.expires)),
    account: `${V.V2.expectReference.network}:${S.fixed.payer}`,
    inputs: { computeUnitLimit: S.build.computeUnitLimit, computeUnitPrice: S.build.computeUnitPrice },
    answer: async (r) => {
      if (r.kind !== "solana-message") throw new Error(r.kind);
      return toHex(payer.sign(r.message));
    },
  };
  it("B6: the payer's signature over the message completes a credential bound to H", async () => {
    const { signed } = await buildAndSign(p, (r) => expect(r.kind).toBe("solana-message"));
    expect((signed as MppCredential).payload["type"]).toBe("transaction");
  });
});

// ── usdc/stacks ──────────────────────────────────────────────────────────────────────────────────────────────────

describe("mpp/charge/usdc/stacks", () => {
  const V = vectors<Loose>("mpp-charge-usdc-stacks.json");
  const f = V.fixed;
  const p: Pairing = {
    binding: chargeUsdcStacks as unknown as Binding,
    doc: docOf(chargeUsdcStacks, issued("usdc", "charge", f.request, f.realm, f.expires)),
    account: `${f.network}:${f.sender}`,
    answer: async (r) => {
      if (r.kind !== "stacks-contract-call") throw new Error(r.kind);
      return V.M4.wireHex;
    },
  };
  it("B6: the wallet is handed M4's transfer, and its signed transaction is bound to H", async () => {
    const { signed } = await buildAndSign(p, (r: SigningRequest) => {
      expect(r).toEqual({
        kind: "stacks-contract-call",
        contract: f.contract,
        functionName: "transfer",
        args: { amount: f.amount, sender: f.sender, recipient: f.recipient, memo: H },
        postCondition: "SentEq",
        postConditionMode: "deny",
        anchorMode: "onChainOnly",
      });
    });
    expect((signed as MppCredential).source).toBe(p.account);
  });
});

// ── usdc/gateway ─────────────────────────────────────────────────────────────────────────────────────────────────

describe("mpp/charge/usdc/gateway", () => {
  const V = vectors<Loose>("mpp-charge-usdc-gateway.json");
  const f = V.fixed;
  const own = V.M5.saltInput;
  const p: Pairing = {
    binding: chargeUsdcGateway as unknown as Binding,
    doc: docOf(chargeUsdcGateway, issued("usdc", "charge", V.M5.requestJson, f.realm, f.expires)),
    account: V.M5.source,
    answer: async (r) => {
      if (r.kind !== "gateway-burn-intent") throw new Error(r.kind);
      const { recipient: _r, ...inputs } = own;
      const salt = usdcGatewaySalt({ ...r.preimage, ...inputs });
      if (typeof salt !== "string") throw new Error(salt.code);
      const burnIntent = structuredClone(V.M5.payload.authorization.transfer.burnIntent);
      burnIntent.spec.salt = salt;
      const signature = await ANVIL.signTypedData(burnIntentTypedData(burnIntent));
      const { authorization: _a, type: _t, ...routes } = V.M5.payload;
      return { source: V.M5.source, ...routes, burnIntent, signature };
    },
  };
  it("B6: the client's salt is M5's, and the signed burn intent is bound to H", async () => {
    await buildAndSign(p, (r) => {
      if (r.kind !== "gateway-burn-intent") throw new Error(r.kind);
      const { recipient: _r, ...inputs } = own;
      expect(JSON.parse(JSON.stringify(r))).toEqual(r);
      expect(usdcGatewaySalt({ ...r.preimage, ...inputs })).toBe(V.M5.expectSalt);
    });
  });
});

/** The Gateway burn intent as EIP-712 typed data: domain `{GatewayWallet, 1}` only, as Circle Gateway's burn intent defines it. */
function burnIntentTypedData(b: { maxBlockHeight: string; maxFee: string; spec: Record<string, unknown> }): TypedDataDefinition {
  const bytes32 = [
    "sourceContract",
    "destinationContract",
    "sourceToken",
    "destinationToken",
    "sourceDepositor",
    "destinationRecipient",
    "sourceSigner",
    "destinationCaller",
  ];
  return {
    domain: { name: "GatewayWallet", version: "1" },
    types: {
      TransferSpec: [
        { name: "version", type: "uint32" },
        { name: "sourceDomain", type: "uint32" },
        { name: "destinationDomain", type: "uint32" },
        ...bytes32.map((name) => ({ name, type: "bytes32" })),
        { name: "value", type: "uint256" },
        { name: "salt", type: "bytes32" },
        { name: "hookData", type: "bytes" },
      ],
      BurnIntent: [
        { name: "maxBlockHeight", type: "uint256" },
        { name: "maxFee", type: "uint256" },
        { name: "spec", type: "TransferSpec" },
      ],
    },
    primaryType: "BurnIntent",
    message: { maxBlockHeight: BigInt(b.maxBlockHeight), maxFee: BigInt(b.maxFee), spec: { ...b.spec, value: BigInt(b.spec["value"] as string) } },
  } as TypedDataDefinition;
}
