---
title: Pay with the gate
description: Compare, then build and sign, then finish. One call with transact, or two with confirm and finish when your signer lives elsewhere.
---

Every payment through the gate follows the same order: compare the served bytes with H, build the payment with the
hash the gate computed, have your signer sign exactly that request, and finish only when what was signed carries H.
You can run the whole order with one call, `transact`, or split it with `confirm` and `finish`.

## What you pass

Every gate function takes the same few values:

| Value | What it is |
| --- | --- |
| `doc` | The seller's payment request, as the protocol delivers it: an x402 `PaymentRequired` object, a list of MPP challenges, or the pairing's document. Pass it as parsed JSON; the gate never needs the raw response. |
| `binding` | The pairing's binding, from `@integraledger/lcp` (TypeScript) or a constant of `integraledger_terms` (Python). The [pairings reference](../reference/pairings.md) names each one. |
| `signer` | Your wallet: an `account` in CAIP-10 form (`eip155:84532:0xf39F…2266`) and a `sign(request)` method. See [signers](./signers.md). |
| `fetch` | Your HTTP client. TypeScript: WHATWG `fetch`, or anything with its call shape. Python: an `httpx.AsyncClient`. Your network policy (proxy, egress rules, timeouts of your own) lives here. |
| `inputs` | The buyer's own values a pairing's build needs beside the offer, such as a recent blockhash or an account sequence. Most pairings need none. See [rails](./rails.md). |

The `account` names the network the buyer pays on. The gate pays the first option (an x402 `accepts` entry, an MPP
challenge) in document order that the pairing serves on the account's network. To pay a different option, remove the
others from the document before you pass it.

## One call: `transact`

`transact` compares, pays the agreement first where the pairing needs one, calls your signer, and finishes:

```ts no-run
import { transact } from "@integraledger/terms";
import { exactEip3009 } from "@integraledger/lcp/x402";
import type { Signer } from "@integraledger/terms";

declare const offer: unknown; // the seller's PAYMENT-REQUIRED document, parsed
declare const signer: Signer;

const result = await transact(offer, exactEip3009, signer, globalThis.fetch, { inputs: {} });
if ("decline" in result) {
  console.error(result.decline.code, result.decline.detail);
} else {
  // result.signed: the payment to send (null when the pairing has nothing for the buyer to sign)
  // result.bytes:  the ATR's exact bytes, your copy of the record
  // result.h:      their SHA-256
  // result.agreement: the agreement's receipt, when an agreement was paid first
  // result.landed: a landed receipt to keep beside the payment, for the few pairings that return one
}
```

The signer is called only after the comparison matched, and only for this pairing's requests. On any decline before
it, the signer is never called.

`transact`'s options take two members, both optional:

- `inputs`: the buyer's own values the build needs.
- `agreementSigner`: the signer that pays the agreement, where it differs from the one that pays the resource (for
  example a card payment whose agreement is paid from an EVM wallet). Without it, `signer` pays both.

Any other member is declined with `no-payable-option` and the detail `<protocol>/input-malformed`, before any fetch.

## Two calls: `confirm`, then `finish`

When the key lives somewhere else (a hardware wallet, a signing service, another process), split the order:

1. `confirm(doc, binding, account, fetch, inputs)` reads the offer, fetches and compares, and returns the signing
   request built with H, together with `chosen` and the ATR's bytes.
2. Your signer signs `request`, exactly as given.
3. `finish(bytes, chosen, signature, binding)` rebuilds the same payment from `chosen` and the bytes, joins the
   signature, and returns the payment only when what was signed carries the hash of those bytes.

`chosen` is plain JSON and the bytes are bytes, so both cross process boundaries. `finish` does not trust anything it
did not rebuild: it recomputes H from the bytes you hand back.

```ts
import { confirm, finish, type Fetch } from "@integraledger/terms";
import { exactEip3009, type Eip3009Payment } from "@integraledger/lcp/x402";
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

// 1. Compare, and build the request with H.
const confirmed = await confirm(offer, exactEip3009, "eip155:84532:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", fetch);
if ("decline" in confirmed) throw new Error(confirmed.decline.code);
if (confirmed.request === null || confirmed.request.kind !== "eip712") throw new Error("expected an EIP-712 request");

// What crosses to the signing side and back: plain JSON and the bytes.
const handOff = JSON.stringify({ chosen: confirmed.chosen, atr: Buffer.from(confirmed.bytes).toString("base64") });

// 2. Sign exactly the request, elsewhere. The published Anvil development key; never use it for real funds.
const wallet = privateKeyToAccount("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const signature = await wallet.signTypedData(
  confirmed.request.typedData as Parameters<typeof wallet.signTypedData>[0],
);

// 3. Finish from what came back.
const back = JSON.parse(handOff);
const done = await finish(new Uint8Array(Buffer.from(back.atr, "base64")), back.chosen, signature, exactEip3009);
if ("decline" in done) throw new Error(done.decline.code);
if ("next" in done) throw new Error("this pairing signs in one step");

console.log("nonce is H:", (done.signed as Eip3009Payment).payload.authorization.nonce === H);
```

```text output
nonce is H: true
```

### A request of `null`

Some pairings give the buyer nothing to sign: the seller's own flow completes the payment (an MPP `card` or `stripe`
charge, an ACP checkout without delegation, a UCP checkout without a mandate). For these, `confirm` returns
`request: null` after the comparison, and `transact` returns `signed: null`. The comparison was the whole of your step;
complete the payment through the protocol's own flow.

### Payments signed in steps

A few pairings take two signatures: a channel funding and then its first voucher (`mpp/session/evm` and others). For
these, `finish` returns `{ next, h }` instead of the payment. Have your signer sign `next`, then call `finish` again with
every answer so far, in order, as a list:

```ts no-run
import { finish, type Chosen, type Signature, type SigningRequest } from "@integraledger/terms";
import type { Binding } from "@integraledger/terms";

declare const bytes: Uint8Array;
declare const chosen: Chosen;
declare const binding: Binding;
declare const first: SigningRequest;
declare function sign(request: SigningRequest): Promise<Signature>;

const answers: Signature[] = [await sign(first)];
let done = await finish(bytes, chosen, answers[0]!, binding);
while (!("decline" in done) && "next" in done) {
  answers.push(await sign(done.next));
  done = await finish(bytes, chosen, answers, binding);
}
```

`transact` does this for you. It never calls the signer more than twice for one payment.

## Sending the payment

The gate returns the payment in the protocol's own form. You send it as that protocol defines:

| Protocol | How the payment travels |
| --- | --- |
| x402 over HTTP | Base64 of the payment's JSON, in the `PAYMENT-SIGNATURE` request header, on a retry of the original request. |
| x402 over MCP | The payment object in the tool call's `_meta["x402/payment"]`. |
| MPP | The credential in the field the challenge selects, `Authorization` by default, after the `Payment` scheme name. |
| Card, AP2, UCP, ACP, ACK | The pairing's own message: the TAP field, the mandate, the checkout completion, as its protocol defines. |

Where `transact` or `finish` also returned `landed`, keep it beside the payment. `check` reads the payment with it.

## After you send it

- **The seller answers that the payment is still settling.** Send the same payment again. Never sign a new one: the
  payment already carries H, and a second signature would be a second payment.
- **A decline carries `moved`.** Your signer moved the payment itself (a Lightning invoice paid, a transaction
  broadcast) before the gate declined. `moved.signed` is that payment, with the bytes and their hash. Keep it and
  present it again rather than signing a new one. See [keeping the record](./keeping-the-record.md).
- **Any other decline.** Nothing was sent, and nothing should be. The [declines reference](../reference/declines.md)
  says what each code means. Whether to deal with the seller another way is your principal's decision.

## In a Cloudflare Worker

Pass the Worker's own `fetch`. The gate asks with `redirect: "manual"`: the Workers runtime refuses
`redirect: "error"` with a `TypeError`, and under `"manual"` it answers a redirect with the `3xx` itself.

Measured on Cloudflare's runtime (`wrangler dev --remote`, wrangler 4.141.0, compatibility date 2026-09-01), with this
package, `@integraledger/lcp` and all ten of lcp's optional peer dependencies installed:

- With and without the `nodejs_compat` flag, `confirm` fetched a link that answered `200`, hashed the bytes and
  compared them with the advertised hash.
- A link that answered `301` or `302` was declined `atr-unfetchable`, and the fetch did not throw.
- Without the optional peer dependencies, wrangler's build stopped at `Could not resolve` for `@mysten/sui/bcs`,
  `@mysten/sui/utils`, `@near-js/crypto`, `@near-js/transactions` and `borsh`.

## In Python

The Python gate has the same functions, with Python names and dataclass results:

| TypeScript | Python |
| --- | --- |
| `transact(doc, binding, signer, fetch, { inputs, agreementSigner })` | `await transact(doc, binding, signer, client, inputs=…, agreement_signer=…)` |
| `confirm(doc, binding, account, fetch, inputs)` | `await confirm(doc, binding, account, client, inputs)` |
| `finish(bytes, chosen, signature, binding)` | `finish(atr_bytes, chosen, signature, binding)` |
| `check(bytes, presented, binding)` | `check(atr_bytes, presented, binding)` |
| `{ decline: { code, detail } }` | `Declined(code, detail, moved)` |

See the [Python guide](./python.md).
