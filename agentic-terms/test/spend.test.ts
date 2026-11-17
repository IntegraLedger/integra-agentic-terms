// spend-permissions/eip155's buyer piece and its approval summary, over the protocol package's
// spend-permissions-eip155.json: the offer its `advertise` places for the file's H, the account the file names, and on
// each route the request the piece hands the signer, held to the file's build (viem 2.57.4's typed-data hash and
// `approve` encoding), the answer, held to the file's signature (viem's signTypedData of the published key #0) or its
// transaction, and the payment, held to the file's return and its `Spend-Permission` header (Node's base64url). Each
// summary member is the file's permission member it names. The B2 and B6 rows run in buyer-rows.test.ts.
import { describe, expect, it } from "vitest";
import { hashTypedData, type TypedDataDefinition } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { encodeSpendPermissionHeader, spendPermissionsEip155, type SpendPermissionOfferInput } from "@integraledger/lcp/spend-permissions";
import type { AtrHash } from "@integraledger/lcp";
import { summaryOf } from "../src/summary.js";
import type { Binding, SigningRequest } from "../src/index.js";
import { ABC, buildAndSign, vectors, type Pairing } from "./support.js";

type Permission = Record<"account" | "spender" | "token" | "allowance" | "period" | "start" | "end" | "salt" | "extraData", string>;
interface File {
  fixed: { H: AtrHash; L: string; network: string; account: string; now: number; offerInput: SpendPermissionOfferInput; signature: string };
  build: { expect: { permission: Permission; hash: string; typedData: object; approve: { to: string; data: string } } };
  header: Record<"signature" | "transaction", { return: Record<string, unknown>; value: string }>;
}
const V = vectors<File>("spend-permissions-eip155.json");
const F = V.fixed;
const P = V.build.expect.permission;
/** buyer.json's published key #0, whose account is the file's. */
const KEY = vectors<{ fixed: { payerKey: `0x${string}` } }>("buyer.json").fixed.payerKey;
const binding = spendPermissionsEip155 as unknown as Binding;
const ACCOUNT = `${F.network}:${privateKeyToAccount(KEY).address}`;

/** The `402` body the protocol package's `advertise` places for `h`, the offer accepting `accepts`. */
function bodyFor(h: AtrHash, accepts: readonly ("signature" | "transaction")[]): unknown {
  const placed = spendPermissionsEip155.advertise({}, h, F.L, { ...F.offerInput, accepts: [...accepts] });
  if ("refused" in placed) throw new Error(placed.code);
  return placed;
}

const signTyped = (r: SigningRequest) => {
  if (r.kind !== "eip712") throw new Error(`not eip712: ${r.kind}`);
  return privateKeyToAccount(KEY).signTypedData(r.typedData as unknown as TypedDataDefinition);
};

/** Freezes the clock at the file's `now`, and restores it. */
async function at<T>(run: () => Promise<T>): Promise<T> {
  const real = Date.now;
  Date.now = () => F.now * 1000;
  try {
    return await run();
  } finally {
    Date.now = real;
  }
}

/** The summary of the permission the file builds: each member the file's permission member it names. */
const SHOWN = {
  payees: [{ account: P.spender, amount: P.allowance }],
  period: P.period,
  limitPerPeriod: P.allowance,
  end: P.end,
  asset: P.token,
  network: F.network,
  validity: { notBefore: P.start, notAfter: P.end, unit: "seconds" },
  atr: ABC,
};

// The permission stays drawable until its end, past the 600 s default, so the payment through the gate is given a
// ceiling of the permission's whole life, `end` less `start`.
const CEILINGS = { "spend-permissions/eip155": Number(P.end) - Number(P.start) };

describe("spend-permissions/eip155: the route signature", () => {
  const p: Pairing = {
    binding,
    doc: bodyFor(F.H, ["signature", "transaction"]),
    placed: (h) => bodyFor(h, ["signature", "transaction"]),
    account: ACCOUNT,
    ceilings: CEILINGS,
    answer: signTyped,
  };

  it("the typed data hashes to the file's, its signature is the file's, and the return is the file's header", () =>
    at(async () => {
      expect(ACCOUNT.toLowerCase()).toBe(`${F.network}:${F.account}`);
      const { signed, request } = await buildAndSign(p, async (r) => {
        expect(hashTypedData(r.kind === "eip712" ? (r.typedData as unknown as TypedDataDefinition) : ({} as never))).toBe(V.build.expect.hash);
        expect(r).toMatchObject({ kind: "eip712", typedData: V.build.expect.typedData });
        expect(await signTyped(r)).toBe(F.signature);
      });
      expect(signed).toEqual(V.header.signature.return);
      expect(encodeSpendPermissionHeader(signed as never)).toBe(V.header.signature.value);
      expect(await summaryOf(binding.id, request, ABC)).toEqual(SHOWN);
    }));
});

describe("spend-permissions/eip155: the route transaction, where the offer accepts it alone", () => {
  const sent = V.header.transaction.return["transaction"] as string;
  const p: Pairing = {
    binding,
    doc: bodyFor(F.H, ["transaction"]),
    placed: (h) => bodyFor(h, ["transaction"]),
    account: ACCOUNT,
    ceilings: CEILINGS,
    answer: async () => sent,
  };

  it("the call is the file's approve, broadcast by the account, and the return is the file's header", () =>
    at(async () => {
      const { signed, request } = await buildAndSign(p, (r) => {
        expect(r).toEqual({ kind: "evm-call", chainId: Number(F.network.split(":")[1]), call: V.build.expect.approve, broadcast: true });
      });
      expect(signed).toEqual(V.header.transaction.return);
      expect(encodeSpendPermissionHeader(signed as never)).toBe(V.header.transaction.value);
      expect(await summaryOf(binding.id, request, ABC)).toEqual(SHOWN);
    }));
});
