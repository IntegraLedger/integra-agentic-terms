// The buyer's rules once money may move, through the gate. Expected values: a pairing at coverage `none`, offered with
// no agreement URL, is `agreement-not-offered` before any signer call (the gate never starts the full payment without
// the receipt). The offer and payer are the vector file's.
import { describe, expect, it } from "vitest";
import { exactErc7710, type PaymentRequired, type PaymentRequirements } from "@integraledger/lcp/x402";
import { confirm, transact, type Binding } from "../src/index.js";
import { ABC, code, counting, H, LINK, serving, vectors } from "./support.js";

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

describe("a pairing at coverage none, offered with no agreement URL", () => {
  const E = vectors<{ fixed: { option: PaymentRequirements; payer: string; resource: object } }>(
    "x402-exact-eip155-erc7710.json",
  );
  const doc = x402Doc(exactErc7710, E.fixed.resource, E.fixed.option);
  const account = `${E.fixed.option.network}:${E.fixed.payer}`;

  it("x402/exact/eip155/erc7710: agreement-not-offered from confirm and transact; the signer is never called", async () => {
    expect(exactErc7710.data.coverage).toBe("none");
    const signer = counting(account, async () => {
      throw new Error("no signer call");
    });
    expect(code(await transact(doc, exactErc7710, signer, serving(ABC)))).toBe("agreement-not-offered");
    expect(code(await confirm(doc, exactErc7710, account, serving(ABC)))).toBe("agreement-not-offered");
    expect(signer.requests.length).toBe(0);
  });
});
