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
| The agreement's receipt (`agreement`), where returned | The record of the agreement payment, for a pairing whose payment is not a public proof. |

Keep the bytes as bytes. Re-encoding them as a parsed and re-serialised JSON document changes the hash.

## Confirm a payment later: `check`

`check(bytes, presented, binding)` answers one question: does this payment carry, inside what was signed, the SHA-256
of these bytes? It fetches nothing and calls no signer.

```ts
import { check, transact, type Fetch, type Signer } from "@integraledger/terms";
import { exactEip3009 } from "@integraledger/lcp/x402";
import { privateKeyToAccount } from "viem/accounts";

const atr = new TextEncoder().encode(
  '{"atrVersion":"1","id":"0f8fad5b-d9cb-469f-a165-70867728950e","x402":{"z":1.0,"a":"caf\\u00e9"},"seller":{"note":"Café — 30 días ✓"}}',
);
const H = "0x8b1e122580ae3f6a8c3d36a24294e1260a87bde70f597279b973e39310072938";
const link = `https://atr.seller.example/${H}`;
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

const paid = await transact(offer, exactEip3009, signer, fetch);
if ("decline" in paid || "approve" in paid || paid.signed === null) throw new Error("not paid");

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

Where `finish` or `transact` returned `landed`, put it back into the payment before you check it:
`check(bytes, { ...signed, landed }, binding)`.

For a pairing whose payment is not a public proof of H, `check` has nothing to read in the payment. The proof is the
agreement payment, which is itself a public-proof payment: check it with the binding of the pairing it was paid with.

## A moved payment

A decline that carries `moved` means your signer moved the payment itself before the gate declined: a Lightning node
paid the invoice, or a signer broadcast a transaction. `moved` holds the payment as signed, the ATR's bytes and their
hash.

- Keep all three, as you would keep a payment that succeeded.
- Present `moved.signed` to the seller again rather than signing a new payment.
- Whether to deal with the seller another way is your principal's decision.

## A payment still settling

If the seller answers that your payment is still settling, send the same payment again. Never sign a new one: the
payment already carries H, and a second signature is a second payment.
