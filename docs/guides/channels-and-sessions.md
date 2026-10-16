---
title: Channels and sessions
description: One ATR for a whole channel or session. Compare once at the opening, keep a hold, and sign every later voucher from it.
---

In a payment channel, the buyer funds a channel once and then pays each request with a signed voucher. x402's
`batch-settlement` scheme and MPP's sessions work this way. One ATR, and so one H, covers the whole channel: the
agreement is made at the opening, and every voucher pays under it.

The gate follows that shape:

1. **Open.** `transact` (or `confirm` and `finish`) compares the ATR and signs the opening, whose signed contents carry
   H. It is a payment like any other.
2. **Hold.** `openChannel(bytes, opened, binding, landed?)` checks that the opening is an opening, that the pairing
   reads the hash of the bytes from it and that it names its channel, and returns a **hold**: the bytes, the opening and
   the channel, as JSON you keep. `landed` is the landed receipt `transact` returned beside the opening, where it
   returned one. Pass it: a pairing such as `mpp/session/hedera` binds its opening by a log only that receipt carries,
   and the hold keeps it as its own `landed` member, beside the opening as signed. The caller passes as `landed` only
   the receipt its own reader read for the opening, as `transact` returned it, never a value another party sent. An
   opening that holds its read under its own `FETCHED` member, as `@integraledger/lcp`'s `fetchPresented` returns it,
   is read with that read without `landed`, and the hold keeps it the same way.
3. **Pay within.** For each later request, `within(doc, hold, binding, signer)` signs one voucher from the hold. It
   takes the bytes, the hash and the channel from the hold, and the amount from the seller's new challenge. On x402's
   batch channels it signs only when that challenge advertises the held H and the payment it builds names the held
   channel. On an MPP session it declines a challenge that names another channel or another H, and signs one with no
   legal context under the held H.
4. **Record the charge.** When the seller reports its cumulative charge, `recordCharge(hold, charged)` records it. The
   charge may not fall below the last one recorded, nor rise above the largest amount you signed.

## The pairings

| Pairing | Opening | Within (handed to the signer as a `batch` of) |
| --- | --- | --- |
| `x402/batch-settlement/eip155` | A deposit authorization and the first voucher, signed as a `batch` | A voucher (`eip712`) |
| `x402/batch-settlement/solana` | The opening's message and first voucher, signed as a `batch` | A voucher (`ed25519-raw`) |
| `mpp/session/evm` | The funding, then the first voucher | A voucher |
| `mpp/session/tempo` | The signed open transaction, then the first voucher | A voucher |
| `mpp/session/solana` | The session opening | A voucher |
| `mpp/session/hedera` | The session opening, broadcast by the signer | A voucher |
| `mpp/session/xrpl` | A `PaymentChannelCreate` and the first claim | A claim |

`within` signs in-channel payments for these seven pairings. For any other pairing it declines
`pairing-not-supported`. It hands your signer every in-channel payment as a `batch`: answer a `batch` with a list, one
answer per request, in order.

## Example

An x402 batch-settlement channel on an EVM chain, opened and then used for two more requests. The payer funds the
channel; a second key, the payer authorizer, signs the vouchers. A local stand-in serves the ATR:

```ts
import { openChannel, recordCharge, transact, within, type Fetch, type Signature, type Signer, type SigningRequest } from "@integraledger/terms";
import { batchEvm } from "@integraledger/lcp/x402-batch-settlement";
import { privateKeyToAccount } from "viem/accounts";

const atr = new TextEncoder().encode(
  '{"atrVersion":"1","id":"0f8fad5b-d9cb-469f-a165-70867728950e","x402":{"z":1.0,"a":"caf\\u00e9"},"seller":{"note":"Café — 30 días ✓"}}',
);
const H = "0x8b1e122580ae3f6a8c3d36a24294e1260a87bde70f597279b973e39310072938";
const link = `https://atr.seller.example/${crypto.randomUUID()}`;

// The seller's batch-settlement offer: 1000 units per request, into a channel.
const offer = {
  x402Version: 2,
  resource: { url: "https://api.seller.example/v1/quote" },
  accepts: [
    {
      scheme: "batch-settlement",
      network: "eip155:84532",
      amount: "1000",
      asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
      payTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
      maxTimeoutSeconds: 3600,
      extra: { receiverAuthorizer: "0x90F79bf6EB2c4f870365E785982E1f101E93b906", withdrawDelay: 900, name: "USDC", version: "2" },
    },
  ],
  extensions: { legalContext: { info: { type: "sha256", value: H, legalContextUrl: link }, schema: {} } },
};
const fetch: Fetch = async (url) => (url === link ? new Response(atr) : new Response(null, { status: 404 }));

// Anvil development keys: the payer funds the channel, the payer authorizer signs vouchers. Never use them for real funds.
const payer = privateKeyToAccount("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const authorizer = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");
type TypedData = Parameters<typeof payer.signTypedData>[0];
const signer: Signer = {
  account: `eip155:84532:${payer.address}`,
  async sign(request: SigningRequest): Promise<Signature> {
    if (request.kind !== "batch") throw new Error(`unexpected ${request.kind}`);
    const answers: Signature[] = [];
    for (const each of request.requests) {
      const typedData = (each as { typedData: TypedData }).typedData;
      const key = typedData.primaryType === "Voucher" ? authorizer : payer;
      answers.push(await key.signTypedData(typedData));
    }
    return answers;
  },
};

// Open: compare the ATR once, sign the deposit and the first voucher.
const opened = await transact(offer, batchEvm, signer, fetch, {
  inputs: { payerAuthorizer: authorizer.address, deposit: "100000" },
});
if ("decline" in opened || "approve" in opened || opened.signed === null) throw new Error("the channel did not open");
let hold = await openChannel(opened.bytes, opened.signed, batchEvm);
if ("decline" in hold) throw new Error(hold.decline.code);
console.log("channel ", hold.channel);

// Each later request: the seller's new offer must advertise the held H.
for (const charged of ["1000", "2000"]) {
  const next = await within(offer, hold, batchEvm, signer);
  if ("decline" in next) throw new Error(next.decline.code);
  console.log("voucher up to", next.hold.signedMax);
  // The seller reports its cumulative charge; it may not exceed what was signed.
  const recorded = recordCharge(next.hold, charged);
  if ("decline" in recorded) throw new Error(recorded.decline.code);
  hold = recorded;
}
```

```text output
channel  0x9c2d7031768ecb3fe688ae307c45f2e3a3d98b0d9ce1a6afcd27131fabb67e56
voucher up to 1000
voucher up to 2000
```

Each voucher's `maxClaimableAmount` is the charge last recorded plus the option's amount, as x402's batch-settlement
client rule sets it: `1000` before any charge is recorded, `2000` after the seller reports `1000`.

## The hold

```json
{
  "pairing": "x402/batch-settlement/eip155",
  "network": "eip155:84532",
  "channel": "0x9c2d7031768ecb3fe688ae307c45f2e3a3d98b0d9ce1a6afcd27131fabb67e56",
  "h": "0x8b1e122580ae3f6a8c3d36a24294e1260a87bde70f597279b973e39310072938",
  "atr": "eyJhdHJWZXJzaW9uIjoiMSIs…",
  "opening": { "x402Version": 2 },
  "charged": "1000",
  "signedMax": "2000"
}
```

| Member | What it is |
| --- | --- |
| `pairing` | The pairing the channel was opened with. |
| `network`, `channel` | The channel, as the pairing names it. |
| `h` | H. |
| `atr` | Padded standard base64 of the ATR's bytes the opening compared, in its canonical form (RFC 4648 sections 3.5 and 4). `within` reads no other spelling. |
| `opening` | The signed opening as the gate returned it, written as plain JSON, its own members as signed (abridged above). A member of its own, `landed` or any other, is never read as the read made for the opening. `openChannel` declines an opening holding a number JSON does not carry (NaN, an infinity), or arrays and objects nested more than 64 levels deep, with `signed-not-bound`. |
| `landed` | The read made for the opening, where there is one: the `landed` receipt `openChannel` took, else the read the opening held under its own `FETCHED` member, as a JSON object. `within` holds it under the opening's `FETCHED` member, as `bound` reads it. |
| `charged` | The seller's cumulative charge last recorded, decimal; `"0"` at the opening. |
| `signedMax` | The largest cumulative amount signed in the channel, decimal. |

The hold is plain JSON. Store it between requests, and always pass the latest one: each `within` and `recordCharge`
returns an updated hold. `within` checks the hold before it signs anything: the bytes must still hash to `h`, the
opening must carry `h`, and the opening must name `network` and `channel`.

Over MCP, the hold is the server's to check: each opening and hold a tool returns also carries `mac`, and the channel
tools use only an opening or hold the same server process returned, unchanged. `atr_channel_open` takes the opening
with the `landed` receipt returned beside it, where there is one. See [channel holds](../reference/mcp.md#channel-holds).

## Refunds and closing

Pass `refund` to `within` to sign a refund instead of a voucher. Its `maxClaimableAmount` is the recorded charge.

- `refund: {}` closes the channel for the remainder.
- `refund: { amount }` asks for a partial refund, where the pairing builds one.
- On Solana the refund is the voucher for the recorded charge. When the seller answers it with
  `invalid_batch_settlement_svm_receiver_binding_unavailable`, call `within` again: the refund then also carries the
  payer-signed `request_close`, built with your `recentBlockhash` (a base58 blockhash) and, where you give them,
  `computeUnitLimit` (a u32) and `computeUnitPrice` (a u64, in decimal). These go in `within`'s last argument,
  `inputs`.
- The seller gives that code in one of two places, and `within` reads them as x402's reference client does: the
  `errorReason` of a settle failure's `PAYMENT-RESPONSE`, which you pass decoded as `refund.paymentResponse`
  (`refund: { paymentResponse }`), read first; or else the `error` of the payment request you pass as the document.
- Without `recentBlockhash` the refund taken again is declined `no-payable-option` with `x402/input-missing`. A value
  given in another form, or a `paymentResponse` that is not an object or whose `errorReason` is not a string, is
  declined with `x402/input-malformed`. No other pairing's refund reads these values or this code.

An MPP session closes with `refund: {}`; a partial refund in a session is declined with
`mpp/within-action-not-built`.

## What `within` refuses

- A hold for another pairing: `pairing-not-supported`.
- A hold whose bytes, opening or channel do not agree: `hash-mismatch` or `signed-not-bound`. An `atr` that is not
  padded standard base64 in its canonical form is unreadable: `signed-not-bound`.
- A challenge that advertises another H: `hash-mismatch`. The signer is not called.
- An x402 challenge that advertises no H: `offer-unreadable` (`x402/no-legal-context`). An MPP session challenge with
  no legal context is not refused: its voucher pays under the held H. One whose `opaque` legal context cannot be read is
  `offer-unreadable` (`mpp/legal-context-malformed`).
- An MPP challenge that names a channel this hold did not open: `no-payable-option`. The signer is not called.
- An x402 challenge under which the voucher or refund would name a channel this hold did not open:
  `no-payable-option`. Before it calls the signer, `within` completes the build with placeholder answers and reads the
  channel that payment names with the binding's `channel.ref`. On Solana the channel address is derived from the
  option's `feePayer` as well as the held configuration, so a challenge naming another fee payer is refused here.
- A signed voucher of the wrong kind, for another channel, or not committed to H: `signed-not-bound`, and it is dropped.

## In Python

The same steps: `open_channel(atr_bytes, opened, binding, landed=None)`, `await within(doc, hold, binding, signer,
refund=None, inputs=None)`, and `record_charge(hold, charged)`. The hold is a `dict` with the same members, and so is
`refund` (`amount`, `paymentResponse`). The
[Python README](https://github.com/IntegraLedger/integra-agentic-terms/tree/main/agentic-terms-py#channels-and-sessions)
runs the same channel and prints the same channel id.
