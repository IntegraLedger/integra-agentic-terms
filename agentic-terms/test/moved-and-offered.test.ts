// The buyer's rules once money may move, through the gate, with MPP Hedera's configured network. Expected values: a
// pairing with no public proof, offered with no agreement URL, is `agreement-not-offered` before any signer call (the
// gate never starts the full payment without the receipt); a payment the signer moved whose check fails after the
// signer returns gives `{decline, moved: {signed, bytes, h}}`, never a bare decline; MPP's Hedera charge
// (`draft-hedera-charge-00`: "Clients MUST reject challenges whose `chainId` does not match their configured
// network"), with a challenge with no `chainId` read on the signer account's own network. The offers and payers are
// the vector files'.
import { describe, expect, it } from "vitest";
import { exactLnbtc } from "@integraledger/lcp/lightning";
import { chargeHedera, type MppChallenge } from "@integraledger/lcp/mpp";
import { exactErc7710, type PaymentRequired, type PaymentRequirements } from "@integraledger/lcp/x402";
import { confirm, transact, type Binding } from "../src/index.js";
import { ABC, code, counting, H, isDeclined, LINK, offered, serving, vectors } from "./support.js";

const NOW = 1_790_000_000;
async function at<T>(run: () => Promise<T>): Promise<T> {
  const real = Date.now;
  Date.now = () => NOW * 1000;
  try {
    return await run();
  } finally {
    Date.now = real;
  }
}

function x402Doc(binding: Binding, resource: object, option: PaymentRequirements): PaymentRequired {
  const placed = (binding as unknown as { advertise(d: object, h: string, l: string, o: object): unknown }).advertise(
    { x402Version: 2, resource, accepts: [option] },
    H,
    LINK,
    option,
  );
  if (typeof placed !== "object" || placed === null || "refused" in placed) throw new Error(JSON.stringify(placed));
  return placed as PaymentRequired;
}

describe("a pairing with no public proof, offered with no agreement URL", () => {
  const E = vectors<{ fixed: { option: PaymentRequirements; payer: string; resource: object } }>(
    "x402-exact-eip155-erc7710.json",
  );
  const doc = x402Doc(exactErc7710, E.fixed.resource, E.fixed.option);
  const account = `${E.fixed.option.network}:${E.fixed.payer}`;

  it("x402/exact/eip155/erc7710: agreement-not-offered from confirm and transact; the signer is never called", async () => {
    expect(exactErc7710.pattern.publicProof).toBe(false);
    const signer = counting(account, async () => {
      throw new Error("no signer call");
    });
    expect(code(await transact(doc, exactErc7710, signer, serving(ABC)))).toBe("agreement-not-offered");
    expect(code(await confirm(doc, exactErc7710, account, serving(ABC)))).toBe("agreement-not-offered");
    expect(signer.requests.length).toBe(0);
  });
});

describe("a payment the signer moved, whose check fails after the signer returns", () => {
  const V = vectors<{ fixed: { O: PaymentRequirements; resource: object; preimage: string; payee: string } }>(
    "x402-exact-lnbtc.json",
  );
  const f = V.fixed;
  const doc = x402Doc(exactLnbtc, f.resource, f.O);
  const account = `${f.O.network}:${f.payee}`;
  // The buyer's own request: x402's lnbtc example, GET of the vector's resource with an empty body.
  const inputs = { request: { method: "GET", url: "https://api.example.com/article/A" } };

  it("x402/exact/lnbtc: the node paid and answered no preimage; the decline keeps what it answered, with the bytes and H", () =>
    at(async () => {
      const node = counting(account, async () => "not-a-preimage");
      const out = await transact(doc, offered(exactLnbtc), node, serving(ABC), { inputs });
      expect(node.requests.map((r) => r.kind)).toEqual(["bolt11-pay"]);
      if (!isDeclined(out)) throw new Error("completed");
      expect(out.decline.code).toBe("signed-not-bound");
      expect(out.moved).toEqual({ signed: "not-a-preimage", bytes: ABC, h: H });
    }));

  it("a payment the signer does not move keeps nothing on a decline: x402/exact/lnbtc's plant is a bare decline", () =>
    at(async () => {
      const node = counting(account, async () => f.preimage);
      const out = await transact(doc, offered(exactLnbtc), node, serving(new TextEncoder().encode("abd")), { inputs });
      expect(code(out)).toBe("hash-mismatch");
      expect(out).not.toHaveProperty("moved");
      expect(node.requests.length).toBe(0);
    }));
});

describe("an MPP Hedera charge challenge with no chainId", () => {
  // The vector file is read as loose JSON data; the test names the fields it uses.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const V = vectors<any>("mpp-charge-hedera.json");
  const f = V.fixed;
  const { chainId: _named, ...details } = f.request.methodDetails as { chainId: number };
  const request = { ...f.request, methodDetails: details };
  const issued = {
    realm: f.realm,
    method: "hedera",
    intent: "charge",
    request: Buffer.from(JSON.stringify(request), "utf8").toString("base64url"),
    expires: f.expires,
  } as MppChallenge;
  const placed = chargeHedera.advertise([issued], H as never, LINK, issued);
  if (!Array.isArray(placed)) throw new Error(JSON.stringify(placed));
  const inputs = { node: f.node, validStart: f.validStart, maxFee: f.maxFee };

  it.each(["testnet", "mainnet"])("is read on the %s account's own network, and its body is handed to the signer", async (net) => {
    const out = await confirm(placed, chargeHedera as unknown as Binding, `hedera:${net}:${f.payer}`, serving(ABC), inputs);
    if (isDeclined(out)) throw new Error(`${out.decline.code}: ${out.decline.detail}`);
    expect(out.request?.kind).toBe("hedera-body");
  });

  it("a challenge whose chainId names testnet (296) is no-payable-option for a mainnet account, before any fetch", async () => {
    const named = { ...issued, request: Buffer.from(JSON.stringify(f.request), "utf8").toString("base64url") } as MppChallenge;
    const doc = chargeHedera.advertise([named], H as never, LINK, named);
    const fetch = serving(ABC);
    const out = await confirm(doc, chargeHedera as unknown as Binding, `hedera:mainnet:${f.payer}`, fetch, inputs);
    expect(code(out)).toBe("no-payable-option");
    expect(fetch.calls).toBe(0);
  });
});
