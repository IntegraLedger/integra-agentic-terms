// Circle Gateway's two forms on the buyer's side: x402/exact/eip155/gateway-batched's piece and summary, and the served
// floor of it and of mpp/charge/usdc/gateway, and the latter's ceiling in blocks (terms' profile buyer-gate.md, rules 8,
// 9, 13 and 14). Every input is lcp's: x402-exact-eip155-gateway-batched.json's S rows (the typed data Circle's own
// client, @circle-fin/x402-batching 4.0.0, handed its signer, the signature it returned and the payment it made) and
// wallets rows (that client's network table), and mpp-charge-usdc-gateway.json's B2 row, M5's request and its ceiling
// rows.
import { describe, expect, it } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import type { TypedDataDefinition } from "viem";
import { exactGatewayBatched, type PaymentRequired, type PaymentRequirements } from "@integraledger/lcp/x402";
import { chargeUsdcGateway, type MppChallenge } from "@integraledger/lcp/mpp";
import type { AtrHash } from "@integraledger/lcp";
import { confirm, FLOOR_INPUTS, transact, type Inputs, type SigningRequest } from "../src/index.js";
import { shown } from "../src/checks.js";
import { summaryOf } from "../src/summary.js";
import { AGREEMENT_URL, buildAndSign, CONFIRMING, counting, fromHex, GATE, H, LINK, serving, vectors } from "./support.js";

const PAIRING = "x402/exact/eip155/gateway-batched";
type Authorization = { from: string; to: string; value: string; validAfter: string; validBefore: string; nonce: string };
type SRow = { case: string; option: "O1" | "O2" | "O3"; signature: string; payment: { payload: { authorization: Authorization } } };
const V = vectors<{
  fixed: Record<"O1" | "O2" | "O3", PaymentRequirements> & {
    resource: { url: string };
    payer: string;
    payerKey: `0x${string}`;
    now: number;
    minValiditySeconds: number;
  };
  S: SRow[];
  wallets: { name: string; network: string; gatewayWallet: string; usdc: string }[];
}>("x402-exact-eip155-gateway-batched.json");
const F = V.fixed;
const SERVED: Inputs = { minValiditySeconds: F.minValiditySeconds };

/** The seller's document for one option, as the pairing's `advertise` places H, the link and the agreement URL. */
function docOf(o: PaymentRequirements, h: AtrHash = H): PaymentRequired {
  const placed = exactGatewayBatched.advertise({ x402Version: 2, resource: F.resource, accepts: [o] } as PaymentRequired, h, LINK, o, AGREEMENT_URL);
  if ("refused" in placed) throw new Error(placed.code);
  return placed;
}

const signs = (r: SigningRequest) => {
  if (r.kind !== "eip712") throw new Error(`not eip712: ${r.kind}`);
  return privateKeyToAccount(F.payerKey).signTypedData(r.typedData as unknown as TypedDataDefinition);
};

/** Freezes the clock at the vectors' `now`, and restores it. */
async function atNow<T>(run: () => Promise<T>): Promise<T> {
  const real = Date.now;
  Date.now = () => F.now * 1000;
  try {
    return await run();
  } finally {
    Date.now = real;
  }
}

/** lcp's build of `o` with the vectors' choice, as the request the signer is handed. */
async function requestFor(o: PaymentRequirements): Promise<SigningRequest> {
  const unsigned = await exactGatewayBatched.build(
    { required: docOf(o), accepted: o, from: F.payer as `0x${string}`, now: F.now, minValiditySeconds: F.minValiditySeconds },
    H,
  );
  if ("refused" in unsigned) throw new Error(unsigned.code);
  return { kind: "eip712", typedData: unsigned.typedData } as unknown as SigningRequest;
}

describe("x402/exact/eip155/gateway-batched: S, Circle's own authorization under each domain", () => {
  for (const row of V.S) {
    const o = F[row.option];
    it(`${row.case}: the signer is handed lcp's typed data, Circle's signature completes the payment, and the summary shows what it signs`, () =>
      atNow(async () => {
        const a = row.payment.payload.authorization;
        await buildAndSign(
          {
            binding: exactGatewayBatched as never,
            doc: docOf(o),
            placed: (h) => docOf(o, h),
            account: `${o.network}:${F.payer}`,
            answer: signs,
            inputs: SERVED,
          },
          async (request) => {
            expect(await signs(request)).toBe(row.signature);
            const shown = await summaryOf(PAIRING, request, new Uint8Array([0x61]));
            expect(shown === undefined ? undefined : { ...shown, asset: shown.asset.toLowerCase(), atr: undefined }).toEqual({
              amount: a.value,
              payees: [{ account: a.to, amount: a.value }],
              asset: o.asset.toLowerCase(),
              network: o.network,
              validity: { notBefore: a.validAfter, notAfter: a.validBefore, unit: "seconds" },
              atr: undefined,
            });
          },
        );
      }));
  }
});

describe("x402/exact/eip155/gateway-batched: wallets, the summary's asset on each network Circle's client configures", () => {
  for (const row of V.wallets) {
    it(`${row.name}: version 1, whose domain names no token, shows the network's USDC; version 2 the token its salt names`, async () => {
      const v1 = { ...F.O1, network: row.network, asset: row.usdc, extra: { ...F.O1.extra, verifyingContract: row.gatewayWallet } };
      const v2 = { ...v1, extra: { ...v1.extra, version: "2" } };
      for (const o of [v1, v2]) {
        const shown = await summaryOf(PAIRING, await requestFor(o), new Uint8Array([0x61]));
        expect([shown?.asset.toLowerCase(), shown?.network]).toEqual([row.usdc.toLowerCase(), row.network]);
      }
    });
  }
});

describe("mpp/charge/usdc/gateway: the served floor (rule 9)", () => {
  const G = vectors<{
    buyer: { rows: { name: string; input: { doc: unknown; servesHex: string; account: string; inputs: Inputs } }[] };
    ceiling: { buildRefusals: { case: string; omit?: string; set?: Record<string, unknown> }[] };
  }>("mpp-charge-usdc-gateway.json");
  const B2 = G.buyer.rows.find((r) => r.name === "B2")!.input;
  const binding = { id: "mpp/charge/usdc/gateway" } as const;

  it("FLOOR_INPUTS names the inputs lcp's B2 row gives the build", () => {
    expect([...FLOOR_INPUTS.get(binding.id)!].sort()).toEqual(Object.keys(B2.inputs).sort());
  });

  // Each refusal row that omits one input, or gives one in another form, is floor-missing naming it, before the offer
  // is read; the row that gives both heights in form, whose sum the build refuses, passes the floor and meets B2's plant.
  for (const r of G.ceiling.buildRefusals) {
    const changed = r.omit !== undefined ? [r.omit] : Object.keys(r.set ?? {});
    it(`${r.case}: ${changed.length === 1 ? `floor-missing, naming ${changed[0]}` : "the floor holds; hash-mismatch on B2's plant"}`, async () => {
      const inputs: Record<string, unknown> = { ...B2.inputs, ...(r.set ?? {}) };
      if (r.omit !== undefined) delete inputs[r.omit];
      const { BINDINGS } = await import("@integraledger/lcp");
      const b = BINDINGS.find((x) => x.id === binding.id)!;
      const signer = counting(B2.account, async () => {
        throw new Error("the signer is never called");
      });
      const fetch = serving(fromHex(B2.servesHex));
      const out = await transact(structuredClone(B2.doc), b, signer, fetch, { ...GATE, inputs: inputs as Inputs });
      const confirmed = await confirm(structuredClone(B2.doc), b, B2.account, fetch, { ...CONFIRMING, inputs: inputs as Inputs });
      const expected = changed.length === 1 ? { code: "floor-missing", detail: changed[0] } : { code: "hash-mismatch" };
      for (const got of [out, confirmed]) {
        const d = "decline" in got ? got.decline : undefined;
        expect(changed.length === 1 ? d : { code: d?.code }).toEqual(expected);
      }
      expect([signer.requests.length, fetch.calls]).toEqual([0, changed.length === 1 ? 0 : 2]);
    });
  }
});

describe("mpp/charge/usdc/gateway: the ceiling, in the blocks of the network the burn intent spends from (rules 8 and 14)", () => {
  type Row = { case: string; burnIntentExpirationHeight: string; withdrawalDelay: string; expectMaxBlockHeight: string };
  const G = vectors<{
    fixed: { realm: string; expires: string };
    M5: { requestJson: string };
    ceiling: {
      good: Row & { sourceNetwork: string };
      built: Row[];
      completeRefusals: { case: string; stock?: boolean; expectStockMaxBlockHeight?: string; set?: string }[];
    };
  }>("mpp-charge-usdc-gateway.json");
  const good = G.ceiling.good;
  const issued: MppChallenge = {
    realm: G.fixed.realm,
    method: "usdc",
    intent: "charge",
    request: Buffer.from(G.M5.requestJson, "utf8").toString("base64url"),
    expires: G.fixed.expires,
  } as MppChallenge;
  const placed = chargeUsdcGateway.advertise([issued], H, LINK, issued, 0);
  if (!Array.isArray(placed)) throw new Error(JSON.stringify(placed));
  const challenge = placed[0]!;
  const binding = chargeUsdcGateway as never;
  const servedOf = (r: Row): Inputs => ({
    sourceNetwork: good.sourceNetwork,
    burnIntentExpirationHeight: r.burnIntentExpirationHeight,
    withdrawalDelay: r.withdrawalDelay,
  });

  /** lcp's build for the served inputs: the request the signer is handed. */
  async function requestFor(served: Inputs): Promise<SigningRequest> {
    const u = await chargeUsdcGateway.build({ challenge, ...served } as never, H);
    if ("refused" in u) throw new Error(u.code);
    return u.request as SigningRequest;
  }

  // Each built row's request, maxBlockHeight the served height plus the build's own margin, is within the ceiling, the
  // margin compared in exact integers: a delay of 0 gives none, and the last row's ceiling is 2^256 - 1.
  for (const row of G.ceiling.built) {
    it(`${row.case}: shown, its validity ending at ${row.expectMaxBlockHeight}`, async () => {
      const out = await shown(binding, await requestFor(servedOf(row)), new Uint8Array([0x61]), servedOf(row), undefined, good.sourceNetwork);
      expect("decline" in out ? out.decline : out.validity).toEqual({ notBefore: null, notAfter: row.expectMaxBlockHeight, unit: "block" });
    });
  }

  // A burn intent whose maxBlockHeight lies past the built ceiling, as the stock client's own and the row one block above
  // sign it, is declined past-ceiling before it is signed.
  const above = G.ceiling.completeRefusals.filter((r) => {
    const height = r.stock === true ? r.expectStockMaxBlockHeight : r.set;
    return typeof height === "string" && /^[0-9]+$/.test(height) && BigInt(height) > BigInt(good.expectMaxBlockHeight);
  });
  it("the rows past the ceiling are read", () => expect(above.length).toBeGreaterThan(0));
  for (const row of above) {
    it(`${row.case}: past-ceiling`, async () => {
      const request = (await requestFor(servedOf(good))) as SigningRequest & { maxBlockHeight: string };
      request.maxBlockHeight = (row.stock === true ? row.expectStockMaxBlockHeight : row.set)!;
      const out = await shown(binding, request, new Uint8Array([0x61]), servedOf(good), undefined, good.sourceNetwork);
      expect("decline" in out && out.decline.code).toBe("past-ceiling");
    });
  }
});
