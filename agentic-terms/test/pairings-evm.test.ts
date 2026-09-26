// B2 and B6 for the x402 EVM breadth pairings. Expected digests, signatures and salts are the vector files'; the payer is the published Anvil key #0 the files name.
import { describe, expect, it } from "vitest";
import { encodeAbiParameters, hashTypedData, type TypedDataDefinition } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  authCaptureEip3009,
  authCapturePermit2,
  exactErc7710,
  exactErc7710Salt,
  exactPermit2,
  uptoPermit2,
  type PaymentRequired,
  type PaymentRequirements,
} from "@integraledger/lcp/x402";
import { pairingOf } from "@integraledger/lcp";
import type { Binding, SigningRequest } from "../src/index.js";
import { buildAndSign, H, LINK, vectors, type Pairing } from "./support.js";

type Fixed = {
  option: PaymentRequirements;
  payer: `0x${string}`;
  payerKey: `0x${string}`;
  now: number;
  resource: { url: string };
};

/** The seller's document for the fixed option, as the pairing's `advertise` places H and the link. */
function docOf(binding: Binding, f: Fixed): PaymentRequired {
  const base: PaymentRequired = { x402Version: 2, resource: f.resource, accepts: [f.option] } as PaymentRequired;
  const placed = (binding as unknown as { advertise(d: PaymentRequired, h: string, l: string, o: unknown): unknown })
    .advertise(base, H, LINK, f.option);
  if (typeof placed === "object" && placed !== null && "refused" in placed) throw new Error(JSON.stringify(placed));
  return placed as PaymentRequired;
}

function typedDataOf(r: SigningRequest): TypedDataDefinition {
  if (r.kind !== "eip712") throw new Error(`not eip712: ${r.kind}`);
  return r.typedData as unknown as TypedDataDefinition;
}

const eip712 = (f: Fixed) => (r: SigningRequest) => privateKeyToAccount(f.payerKey).signTypedData(typedDataOf(r));

function eip712Pairing(binding: Binding, f: Fixed): Pairing {
  return { binding, doc: docOf(binding, f), account: `${f.option.network}:${f.payer}`, answer: eip712(f) };
}

/** Freezes the clock at the vectors' `now`, and restores it. */
async function at<T>(now: number, run: () => Promise<T>): Promise<T> {
  const real = Date.now;
  Date.now = () => now * 1000;
  try {
    return await run();
  } finally {
    Date.now = real;
  }
}

type Row = { expectDigest: string; expectSignature?: string };
const file = <K extends string>(name: string, row: K): [Fixed, Row] => {
  const v = vectors<{ fixed: Fixed } & { [k in K]: Row }>(name);
  return [v.fixed, v[row]];
};
const rows: [string, Binding, [Fixed, Row]][] = [
  ["x402/exact/eip155/permit2", exactPermit2, file("x402-exact-eip155-permit2.json", "EV1")],
  ["x402/upto/eip155/permit2", uptoPermit2, file("x402-upto-eip155-permit2.json", "EV2")],
  ["x402/auth-capture/eip155/eip3009", authCaptureEip3009, file("x402-auth-capture-eip155-eip3009.json", "EV4")],
  ["x402/auth-capture/eip155/permit2", authCapturePermit2, file("x402-auth-capture-eip155-permit2.json", "EV4")],
];

describe.each(rows)("%s", (_id, binding, [fixed, v]) => {
  const p = eip712Pairing(binding, fixed);
  it("B6: the request's digest is the vectors', and the Anvil key's signature completes a payment bound to H", () =>
    at(fixed.now, async () => {
      await buildAndSign(p, async (r) => {
        const td = typedDataOf(r);
        expect(hashTypedData(td)).toBe(v.expectDigest);
        if (v.expectSignature !== undefined) expect(await eip712(fixed)(r)).toBe(v.expectSignature);
      });
    }));
});

describe("x402/exact/eip155/erc7710-salt", () => {
  type Leaf = { delegate: string; delegator: string; authority: string; caveats: unknown[]; salt: string };
  const ES = vectors<{
    fixed: Fixed & { delegationManager: `0x${string}`; leaf: Leaf; delegationDomain: TypedDataDefinition["domain"] };
    EV8: { expectSignature: string; expectContextSha256: string };
  }>("x402-exact-eip155-erc7710-salt.json");
  const f = ES.fixed;
  const delegationTypes = {
    Delegation: [
      { name: "delegate", type: "address" },
      { name: "delegator", type: "address" },
      { name: "authority", type: "bytes32" },
      { name: "caveats", type: "Caveat[]" },
      { name: "salt", type: "uint256" },
    ],
    Caveat: [
      { name: "enforcer", type: "address" },
      { name: "terms", type: "bytes" },
    ],
  } as const;
  const delegationAbi = [
    {
      type: "tuple[]",
      components: [
        { name: "delegate", type: "address" },
        { name: "delegator", type: "address" },
        { name: "authority", type: "bytes32" },
        {
          name: "caveats",
          type: "tuple[]",
          components: [
            { name: "enforcer", type: "address" },
            { name: "terms", type: "bytes" },
            { name: "args", type: "bytes" },
          ],
        },
        { name: "salt", type: "uint256" },
        { name: "signature", type: "bytes" },
      ],
    },
  ] as const;

  /** The buyer's delegation tooling: the leaf delegation with the request's salt, signed by the Anvil key. */
  const answer = (manager: `0x${string}`) => async (r: SigningRequest) => {
    if (r.kind !== "erc7710") throw new Error(`not erc7710: ${r.kind}`);
    const leaf = { ...f.leaf, salt: BigInt(r.salt) };
    const signature = await privateKeyToAccount(f.payerKey).signTypedData({
      domain: f.delegationDomain,
      types: delegationTypes,
      primaryType: "Delegation",
      message: leaf as never,
    });
    expect(signature).toBe(ES.EV8.expectSignature);
    const permissionContext = encodeAbiParameters(delegationAbi, [[{ ...leaf, signature } as never]]);
    return { delegationManager: manager, permissionContext, delegator: f.payer };
  };
  const p: Pairing = {
    binding: exactErc7710Salt,
    doc: docOf(exactErc7710Salt, f),
    account: `${f.option.network}:${f.payer}`,
    answer: answer(f.delegationManager),
  };
  it("B6: the request carries salt = H; the signed leaf's context completes a payment bound to H", () =>
    at(f.now, async () => {
      await buildAndSign(p, (r) => {
        if (r.kind !== "erc7710") throw new Error(r.kind);
        expect(r.salt).toBe(H);
        expect(r.payTo).toBe(f.option.payTo);
      });
    }));

  // x402/exact/eip155/erc7710, the unsigned level (EV7): the same tooling under another delegation manager; H rides in
  // the echoed legal context, so the pairing has no public proof and its offer names the agreement URL. Each breadth
  // pairing adds its own B2 and B6.
  describe("x402/exact/eip155/erc7710", () => {
    const E = vectors<{
      fixed: Fixed;
      EV7: { otherManager: `0x${string}`; expectBound: string; expectPairingOfPayment: string };
    }>("x402-exact-eip155-erc7710.json");
    const q: Pairing = {
      binding: exactErc7710,
      doc: docOf(exactErc7710, E.fixed),
      account: `${E.fixed.option.network}:${E.fixed.payer}`,
      answer: answer(E.EV7.otherManager),
    };
    it("B6: the request carries salt = H; the payment is bound to EV7's H through the echoed legal context", () =>
      at(E.fixed.now, async () => {
        const { signed } = await buildAndSign(q, (r) => {
          if (r.kind !== "erc7710") throw new Error(r.kind);
          expect(r.salt).toBe(H);
          expect(r.payTo).toBe(E.fixed.option.payTo);
        });
        expect(pairingOf((signed as { accepted: PaymentRequirements }).accepted)).toBe(E.EV7.expectPairingOfPayment);
        expect(await exactErc7710.bound(signed as never)).toBe(E.EV7.expectBound);
      }));
  });
});
