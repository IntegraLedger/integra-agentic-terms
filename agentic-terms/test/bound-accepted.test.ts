// Every x402 pairing's bound holds a presented payment's accepted to the option filter its own read applies. The rows
// are the x402 vector files' boundAccepted rows: a payment in the file, named by JSON Pointer (RFC 6901), presented
// under an option the pairing's read does not offer, refused with the row's code by bound and, where the pairing has
// one, by reference.
import { readdirSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { BINDINGS, isRefusal } from "@integraledger/lcp";
import type { PaymentRequired, PaymentRequirements } from "@integraledger/lcp/x402";
import { vectors } from "./support.js";

interface X402Pairing {
  id: string;
  read(doc: unknown): unknown;
  bound(presented: unknown): Promise<unknown>;
  reference?(presented: unknown): Promise<unknown>;
}
interface BoundAcceptedRow {
  case: string;
  pairing: string;
  payment: string;
  accepted: PaymentRequirements;
  expect: string;
}
type Payment = Record<string, unknown>;

const X402 = BINDINGS.filter((b) => b.id.startsWith("x402/")) as unknown as X402Pairing[];
const FILES = readdirSync(new URL("../node_modules/@integraledger/lcp/vectors/", import.meta.url))
  .filter((f) => f.startsWith("x402-") && f.endsWith(".json"))
  .sort();

/** The value at a JSON Pointer (RFC 6901) into `doc`. */
function at(doc: unknown, pointer: string): unknown {
  return pointer
    .split("/")
    .slice(1)
    .reduce((o, k) => (o as Record<string, unknown>)[k.replaceAll("~1", "/").replaceAll("~0", "~")], doc);
}

/** A document offering the option alone, with a legal context. */
function offering(option: PaymentRequirements): PaymentRequired {
  const info = { type: "sha256", value: `0x${"00".repeat(32)}`, legalContextUrl: "https://pairing.invalid/" };
  return {
    x402Version: 2,
    resource: { url: "https://pairing.invalid/" },
    accepts: [option],
    extensions: { legalContext: { info } },
  } as unknown as PaymentRequired;
}

const pairing = (id: string): X402Pairing => {
  const b = X402.find((x) => x.id === id);
  if (b === undefined) throw new Error(`no x402 pairing ${id}`);
  return b;
};

const ROWS = FILES.flatMap((f) => {
  const v = vectors<{ boundAccepted?: { rows: BoundAcceptedRow[] } }>(f);
  return (v.boundAccepted?.rows ?? []).map((row, i) => ({ file: f, i, row, payment: at(v, row.payment) as Payment }));
});

describe("the x402 vector files' boundAccepted rows", () => {
  it("the files hold rows, and every x402 pairing has one", () => {
    expect(ROWS.length).toBeGreaterThan(0);
    expect([...new Set(ROWS.map((r) => r.row.pairing))].sort()).toEqual(X402.map((b) => b.id).sort());
  });

  it.each(ROWS.map((r) => [`${r.file} boundAccepted.rows[${r.i}]`, r] as const))("%s", async (_, { row, payment }) => {
    const b = pairing(row.pairing);
    const presented = { ...payment, accepted: row.accepted };
    expect(isRefusal(await b.bound(payment)), row.case).toBe(false);
    expect(await b.bound(presented), row.case).toEqual({ refused: true, code: row.expect });
    if (b.reference !== undefined) expect(await b.reference(presented), row.case).toEqual({ refused: true, code: row.expect });
    expect(b.read(offering(row.accepted)), row.case).toEqual({ refused: true, code: "x402/no-payable-option" });
  });

  it("x402-exact-aptos.json: the payment the rows present is bound under its own option", async () => {
    const v = vectors<{ boundAccepted: { payment: Payment & { extensions: { legalContext: { info: { value: string } } } } } }>(
      "x402-exact-aptos.json",
    );
    const rows = ROWS.filter((r) => r.row.pairing === "x402/exact/aptos");
    expect(rows.length).toBeGreaterThan(0);
    for (const r of rows) expect(r.row.payment).toBe("/boundAccepted/payment");
    const { payment } = v.boundAccepted;
    expect(await pairing("x402/exact/aptos").bound(payment)).toBe(payment.extensions.legalContext.info.value);
  });
});

// The auth-capture EVM scheme (scheme_auth_capture_evm.md at x402-foundation/x402 e95b06661e, "Payment identity"):
// with receiverAuthorizer and policy both absent or zero the payload's salt is the client's random 32 bytes and it
// carries no saltNonce. A bound payment presented under its option with no receiver authorizer, which read offers, is
// refused with the row's code by bound and reference rather than answered with its salt.
describe("auth-capture: a bound payment under its option with the receiver authorizer removed", () => {
  it.each([
    ["x402-auth-capture-eip155-eip3009.json", "x402/auth-capture/eip155/eip3009"],
    ["x402-auth-capture-eip155-permit2.json", "x402/auth-capture/eip155/permit2"],
  ])("%s unboundSaltNonce", async (file, id) => {
    const v = vectors<{ unboundSaltNonce: { payment: string; accepted: PaymentRequirements; expect: string } }>(file);
    const row = v.unboundSaltNonce;
    const payment = at(v, row.payment) as Payment;
    const b = pairing(id);
    const presented = { ...payment, accepted: row.accepted };
    expect(typeof (await b.bound(payment))).toBe("string");
    expect(isRefusal(b.read(offering(row.accepted)))).toBe(false);
    expect(await b.bound(presented)).toEqual({ refused: true, code: row.expect });
    expect(await b.reference!(presented)).toEqual({ refused: true, code: row.expect });
  });
});
