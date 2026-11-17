---
title: Keeping the record
description: What to keep after a payment, how to confirm later that a payment carries the hash of the record you kept, and what to do with a moved payment.
---

The gate does not store anything. After a payment, what you keep is your proof of what you agreed to.

## What to keep

| Keep | Why |
| --- | --- |
| The ATR's bytes (`bytes`, or `atr_bytes` in Python) | Your copy of the record, exactly as served. Its hash is in the payment. |
| H (`h`) | The hash of those bytes, as the gate computed it. |
| The payment (`signed`) | What you sent. It carries H in its signed contents, for most pairings. |
| `landed`, where returned | A landed receipt some pairings return beside the payment. `check` reads the payment with it. |
| The agreement's receipt (`agreement`), where returned | The agreement URL's answer that the agreement payment for H is recorded: `atrHash`, `network` and `transaction`. It is returned for a pairing whose payment is not a public proof. |

Keep the bytes as bytes. Re-encoding them as a parsed and re-serialised JSON document changes the hash.

## Confirm a payment later: `check`

`check(bytes, presented, binding, landed?, act?)` answers one question: is the ATR hash the pairing reads from this
payment the SHA-256 of these bytes? A payment from which the pairing reads no ATR hash is declined `signed-not-bound`.
It fetches nothing and calls no signer. `act` is the act the payment was paid as: `"payment"`, the default, or
`"agreement"` for an agreement payment (see below).

```ts
import { check, transact, type Fetch, type Signer } from "@integraledger/terms";
import { exactEip3009 } from "@integraledger/lcp/x402";
import { privateKeyToAccount } from "viem/accounts";

const atr = new TextEncoder().encode(
  '{"atrVersion":"1","id":"0f8fad5b-d9cb-469f-a165-70867728950e","x402":{"z":1.0,"a":"caf\\u00e9"},"seller":{"note":"Café — 30 días ✓"}}',
);
const H = "0x8b1e122580ae3f6a8c3d36a24294e1260a87bde70f597279b973e39310072938";
const link = `https://atr.seller.example/${crypto.randomUUID()}`;
const offer = {
  x402Version: 2,
  resource: { url: "https://api.seller.example/v1/quote" },
  accepts: [
    {
      scheme: "exact",
      network: "eip155:84532",
      amount: "10000",
      asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
      payTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
      maxTimeoutSeconds: 60,
      extra: { name: "USDC", version: "2" },
    },
  ],
  extensions: { legalContext: { info: { type: "sha256", value: H, legalContextUrl: link }, schema: {} } },
};
const fetch: Fetch = async (url) => (url === link ? new Response(atr) : new Response(null, { status: 404 }));
const wallet = privateKeyToAccount("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const signer: Signer = {
  account: `eip155:84532:${wallet.address}`,
  async sign(request) {
    if (request.kind !== "eip712") throw new Error(request.kind);
    return wallet.signTypedData(request.typedData as Parameters<typeof wallet.signTypedData>[0]);
  },
};

const paid = await transact(offer, exactEip3009, signer, fetch, {
  resourceRequest: { method: "GET", target: "/v1/quote", body: new Uint8Array() },
  approver: () => true,
});
if ("decline" in paid || "approve" in paid || "charge" in paid || "agreementChallenges" in paid || paid.signed === null) {
  throw new Error("not paid");
}

// Later: the payment against the bytes you kept, and against a record that differs by one byte.
const kept = await check(paid.bytes, paid.signed, exactEip3009);
const other = new TextEncoder().encode(new TextDecoder().decode(paid.bytes).replace("30 días", "31 días"));
const altered = await check(other, paid.signed, exactEip3009);

console.log("kept bytes   ", "decline" in kept ? kept.decline.code : kept.h);
console.log("altered bytes", "decline" in altered ? altered.decline.code : altered.h);
```

```text output
kept bytes    0x8b1e122580ae3f6a8c3d36a24294e1260a87bde70f597279b973e39310072938
altered bytes signed-not-bound
```

Where `finish` or `transact` returned `landed`, pass it beside the payment: `check(bytes, signed, binding, landed)`. The
caller passes as `landed` only the receipt its own reader read for the payment, as `finish` or `transact` returned it,
never a value another party sent. A `landed` member written into the payment is not read.

For a pairing whose payment is not a public proof of H, `check` reads the payment as it reads any other: it confirms
that the hash the pairing reads from it is the SHA-256 of the kept bytes, and declines `signed-not-bound` where the
pairing reads none. That payment does not prove H in public. The proof of H is the agreement payment, which is itself a
payment at coverage `full`: check it with the binding of the pairing it was paid with, and `act` `"agreement"`, as
`check(bytes, agreementPayment, binding, null, "agreement")`.

The agreement payment does not always carry H itself. On a pairing whose agreement has its own single-use value, such
as an EIP-3009 or Permit2 nonce, the agreement payment carries the agreement's value of H, `agreementValue(H)` from
`@integraledger/lcp`, so that one H cannot be spent both as the agreement and as a payment for the resource. Given
`act` `"agreement"`, `check` reads the payment that way and answers H; read as a payment, the same agreement payment is
declined `signed-not-bound`.

The gate returns the agreement's receipt as `agreement`, not the signed agreement payment. The receipt is the agreement
URL's statement: the gate checks that it names H and is a recorded agreement, and does not look up the transaction it
names. Keep it, and confirm H from that transaction on `network`: for an EIP-3009 agreement payment, the `nonce` of the
token's `AuthorizationUsed` event is `agreementValue(H)`, which you compute from your own H and compare.

## A moved payment

A decline that carries `moved` means your signer moved the payment itself before the gate declined: a Lightning node
paid the invoice, or a signer broadcast a transaction. It also means, in the agreement exchange, that the gate sent the
agreement payment and then declined. `moved` holds the payment as signed, the ATR's bytes and their hash.

- Keep all three, as you would keep a payment that succeeded.
- For the payment for the resource, present `moved.signed` to the seller again rather than signing a new payment.
- For an agreement payment, call again without `approved` to collect its receipt, never with `approved`: every call
  with `approved` signs and sends a new agreement payment. See
  [agreement payments](./agreement-payments.md#once-the-agreement-payment-is-sent).
- Whether to deal with the seller another way is your principal's decision.

## A payment still settling

If the seller answers that your payment is still settling, send the same payment again. Never sign a new one: the
payment already carries H, and a second signature is a second payment.
