/**
 * The `PAYMENT-SIGNATURE` envelope.
 *
 * The property under test is the one a hand-written envelope gets wrong: whether the `accepted` entry a
 * payer presents is the entry it was SERVED, or a locally-authored copy that agrees with the seller today
 * and drifts tomorrow. So most of what follows drives a challenge carrying fields this module has never
 * heard of, and asserts they come back unaltered — a template-based builder passes none of them.
 *
 * ⛔ Every refusal has a matching positive case. A validator that refuses everything and a validator that
 * accepts everything are both vacuous, and only driving both directions tells them apart.
 */

import { describe, expect, it } from "vitest";
import {
  decodeX402Challenge,
  x402AcceptedEntry,
  x402PaymentHeader,
} from "../src/index.js";

/** UTF-8 bytes → base64, the way a seller encodes the header. Written out, not imported: see below. */
function encode(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/** base64 → UTF-8, the way a seller decodes the payment. */
function decode(encoded: string): string {
  const binary = atob(encoded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

const ATR_HASH = `0x${"ab".repeat(32)}`;

/**
 * A challenge shaped as a conformant server serves one, carrying two things this module must not be able to
 * invent: a `payTo` and asset identity it has no template for, and a `notAField` nobody has defined.
 */
const CHALLENGE = {
  x402Version: 2,
  accepts: [
    {
      scheme: "exact",
      network: "eip155:84532",
      payTo: "0xSeller",
      asset: "0xUSDC",
      maxAmountRequired: "1000",
      maxTimeoutSeconds: 300,
      notAField: "echoed because it was served, not because it is known",
      extra: {
        name: "USDC",
        version: "2",
        atrHash: ATR_HASH,
      },
    },
  ],
  extensions: {
    legalContext: { atrHash: ATR_HASH, termsUrl: "https://s.example/t" },
  },
};

const AUTHORIZATION = {
  from: "0xBuyer",
  to: "0xSeller",
  value: "1000",
  validAfter: "0",
  validBefore: "9999999999",
  nonce: ATR_HASH,
};

const PAYMENT = {
  challenge: CHALLENGE,
  authorization: AUTHORIZATION,
  signature: "0xsig",
  paymentIdentifier: "pay_01HZ",
  assetTransferMethod: "eip3009",
} as const;

/** What a seller reads back off the header. Typed loosely on purpose — this is the wire, not our types. */
function presented(header: string): Record<string, unknown> {
  return JSON.parse(decode(header)) as Record<string, unknown>;
}

describe("decodeX402Challenge", () => {
  it("reads the advertisement off the header a conformant server sets", () => {
    const response = new Response(null, {
      status: 402,
      headers: { "payment-required": encode(JSON.stringify(CHALLENGE)) },
    });
    expect(decodeX402Challenge(response)).toStrictEqual(CHALLENGE);
  });

  it("⭐ survives a non-ASCII advertisement, which `atob` alone would mangle", () => {
    // A terms summary with a typographic dash decodes to latin-1 mojibake under a bare `atob`, and the
    // buyer would then answer an offer whose text differs from the one it was served. Bytes, then UTF-8.
    const document = { accepts: [{ extra: {}, note: "terms — as served" }] };
    const response = new Response(null, {
      status: 402,
      headers: { "payment-required": encode(JSON.stringify(document)) },
    });
    expect(decodeX402Challenge(response)).toStrictEqual(document);
  });

  it("⛔ refuses a 402 with no advertisement rather than returning an empty one", () => {
    const response = new Response(null, { status: 402 });
    expect(() => decodeX402Challenge(response)).toThrow(
      /no `payment-required` header/,
    );
  });

  it("does not consume the body, so the caller may still read it", async () => {
    const response = new Response("the seller's own 402 body", {
      status: 402,
      headers: { "payment-required": encode(JSON.stringify(CHALLENGE)) },
    });
    decodeX402Challenge(response);
    expect(await response.text()).toBe("the seller's own 402 body");
  });
});

describe("x402AcceptedEntry — the entry is ECHOED, never authored", () => {
  it("⛔ returns every field it was served, including ones it has no knowledge of", () => {
    const entry = x402AcceptedEntry(CHALLENGE, {
      assetTransferMethod: "eip3009",
    });
    // The whole subject of this module. A builder working from a local template drops `notAField` and
    // whatever the seller adds next, and the payment then answers an offer that was never made.
    expect(entry["notAField"]).toBe(
      "echoed because it was served, not because it is known",
    );
    expect(entry["payTo"]).toBe("0xSeller");
    expect(entry["asset"]).toBe("0xUSDC");
    expect(entry["maxAmountRequired"]).toBe("1000");
    expect(entry["maxTimeoutSeconds"]).toBe(300);
  });

  it("adds exactly one field, and it is the one the PRESENTATION owns", () => {
    const entry = x402AcceptedEntry(CHALLENGE, {
      assetTransferMethod: "eip3009",
    });
    const served = CHALLENGE.accepts[0] as Record<string, unknown>;
    expect(Object.keys(entry).sort()).toStrictEqual(Object.keys(served).sort());
    const extra = entry["extra"] as Record<string, unknown>;
    expect(extra["assetTransferMethod"]).toBe("eip3009");
    // …and nothing else in `extra` moved, the carrier included.
    expect(extra["atrHash"]).toBe(ATR_HASH);
    expect(extra["name"]).toBe("USDC");
    expect(extra["version"]).toBe("2");
  });

  it("does not mutate the challenge it was handed", () => {
    const challenge = JSON.parse(JSON.stringify(CHALLENGE)) as unknown;
    x402AcceptedEntry(challenge, { assetTransferMethod: "eip3009" });
    expect(challenge).toStrictEqual(CHALLENGE);
  });

  it.each([
    ["a challenge that is not an object", "nope", /not a JSON object/],
    ["a challenge that is an array", [], /not a JSON object/],
    ["no accepts at all", {}, /carried no `accepts\[\]`/],
    ["an empty accepts", { accepts: [] }, /carried no `accepts\[\]`/],
    [
      "an unreadable accepts[0]",
      { accepts: ["not an entry"] },
      /`accepts\[0\]` is not a readable object/,
    ],
    [
      "an entry with no extra",
      { accepts: [{ scheme: "exact" }] },
      /`accepts\[0\]\.extra` is not a readable object/,
    ],
  ])("⛔ refuses %s", (_what, challenge, message) => {
    expect(() =>
      x402AcceptedEntry(challenge, { assetTransferMethod: "eip3009" }),
    ).toThrow(message);
  });

  it("⭐ and the refusals discriminate: the well-formed challenge above passes all of them", () => {
    // The control. Six refusals in a row prove nothing unless something gets through.
    expect(() =>
      x402AcceptedEntry(CHALLENGE, { assetTransferMethod: "eip3009" }),
    ).not.toThrow();
  });
});

describe("x402PaymentHeader", () => {
  it("is base64 of a JSON document a seller can read", () => {
    const payment = presented(x402PaymentHeader(PAYMENT));
    expect(payment["x402Version"]).toBe(2);
    expect(payment["paymentIdentifier"]).toBe("pay_01HZ");
  });

  it("⛔ carries the payer's OWN instrument, unaltered", () => {
    const payment = presented(x402PaymentHeader(PAYMENT));
    const payload = payment["payload"] as Record<string, unknown>;
    expect(payload["authorization"]).toStrictEqual(AUTHORIZATION);
    expect(payload["signature"]).toBe("0xsig");
  });

  it("⭐ the nonce IS the weld — the atrHash the challenge advertised", () => {
    // The one property this envelope exists to carry. A payment whose nonce is anything else commits to
    // no terms document at all, and the seller's weld check is what refuses it.
    const payment = presented(x402PaymentHeader(PAYMENT));
    const payload = payment["payload"] as Record<string, unknown>;
    const authorization = payload["authorization"] as Record<string, unknown>;
    const accepted = payment["accepted"] as Record<string, unknown>;
    const extra = accepted["extra"] as Record<string, unknown>;
    expect(authorization["nonce"]).toBe(extra["atrHash"]);
  });

  it("presents the `accepted` entry it was served, not a minimal one", () => {
    const payment = presented(x402PaymentHeader(PAYMENT));
    const accepted = payment["accepted"] as Record<string, unknown>;
    expect(accepted["payTo"]).toBe("0xSeller");
    expect(accepted["notAField"]).toBe(
      "echoed because it was served, not because it is known",
    );
  });

  it("restates the document-level `extensions` the challenge carried", () => {
    const payment = presented(x402PaymentHeader(PAYMENT));
    expect(payment["extensions"]).toStrictEqual(CHALLENGE.extensions);
  });

  it("⛔ omits `extensions` entirely when the challenge carried none", () => {
    // An `extensions: undefined` — or an empty object — would be this buyer claiming a carrier placement
    // the seller never used. Absence says the challenge stated none.
    const header = x402PaymentHeader({
      ...PAYMENT,
      challenge: { accepts: [{ extra: {} }] },
    });
    const payment = presented(header);
    expect(Object.hasOwn(payment, "extensions")).toBe(false);
  });

  it("⛔ cannot build a payment from a challenge it could not read", () => {
    // The shape of the API is the guarantee: there is no overload that omits the challenge, and an
    // unreadable one refuses rather than defaulting to an entry nobody advertised.
    expect(() => x402PaymentHeader({ ...PAYMENT, challenge: null })).toThrow(
      /not a JSON object/,
    );
  });

  it("⭐ round-trips through a non-ASCII advertisement", () => {
    const challenge = {
      accepts: [{ extra: { atrHash: ATR_HASH }, note: "terms — as served" }],
    };
    const payment = presented(x402PaymentHeader({ ...PAYMENT, challenge }));
    const accepted = payment["accepted"] as Record<string, unknown>;
    expect(accepted["note"]).toBe("terms — as served");
  });
});
