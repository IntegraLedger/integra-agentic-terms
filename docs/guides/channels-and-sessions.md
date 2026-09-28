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
2. **Hold.** `openChannel(bytes, opened, binding)` checks that the opening is an opening, carries the hash of the bytes
   and names its channel, and returns a **hold**: the bytes, the opening and the channel, as JSON you keep.
3. **Pay within.** For each later request, `within(doc, hold, binding, signer)` signs one voucher from the hold. It
   re-derives the bytes, the hash and the channel from the hold, never from the seller's new challenge, and signs only
   when that challenge advertises the held H and the payment it builds names the held channel.
4. **Record the charge.** When the seller reports its cumulative charge, `recordCharge(hold, charged)` records it. The
   charge may not fall below the last one recorded, nor rise above the largest amount you signed.

## The pairings

| Pairing | Opening | Within |
| --- | --- | --- |
| `x402/batch-settlement/eip155` | A deposit authorization and the first voucher, signed as a `batch` | A voucher (`eip712`) |
| `x402/batch-settlement/solana` | The opening's message and first voucher, signed as a `batch` | A voucher (`ed25519-raw`) |
| `mpp/session/evm` | The funding, then the first voucher | A voucher |
| `mpp/session/tempo` | The signed open transaction, then the first voucher | A voucher |
| `mpp/session/solana` | The session opening | A voucher |
| `mpp/session/hedera` | The session opening, broadcast by the signer | A voucher |
| `mpp/session/xrpl` | A `PaymentChannelCreate` and the first claim | A claim |

`within` signs in-channel payments for these seven pairings. For any other pairing it declines
`pairing-not-supported`.

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
const link = `https://atr.seller.example/${H}`;

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
| `atr` | Base64 of the ATR's bytes the opening compared. |
| `opening` | The signed opening, exactly as the gate returned it (abridged above). |
| `charged` | The seller's cumulative charge last recorded, decimal; `"0"` at the opening. |
| `signedMax` | The largest cumulative amount signed in the channel, decimal. |

The hold is plain JSON. Store it between requests, and always pass the latest one: each `within` and `recordCharge`
returns an updated hold. `within` checks the hold before it signs anything: the bytes must still hash to `h`, the
opening must carry `h`, and the opening must name `network` and `channel`.

Over MCP, the hold is the server's to check: each opening and hold a tool returns also carries `mac`, and the channel
tools use only an opening or hold the same server process returned, unchanged. See [channel holds](../reference/mcp.md#channel-holds).

## Refunds and closing

Pass `refund` to `within` to sign a refund instead of a voucher. Its `maxClaimableAmount` is the recorded charge.

- `refund: {}` closes the channel for the remainder.
- `refund: { amount }` asks for a partial refund, where the pairing builds one.
- The buyer's own chain values a refund's build needs (for Solana, a recent blockhash where the option names none, and
  the compute budget values) go in `within`'s last argument, `inputs`.

An MPP session closes with `refund: {}`; a partial refund in a session is declined with
`mpp/within-action-not-built`.

## What `within` refuses

- A hold for another pairing: `pairing-not-supported`.
- A hold whose bytes, opening or channel do not agree: `hash-mismatch` or `signed-not-bound`.
- A challenge that advertises another H: `hash-mismatch`. The signer is not called.
- An MPP challenge that names a channel this hold did not open: `no-payable-option`. The signer is not called.
- An x402 challenge under which the voucher or refund would name a channel this hold did not open:
  `no-payable-option`. Before it calls the signer, `within` completes the build with placeholder answers and reads the
  channel that payment names with the binding's `channel.ref`. On Solana the channel address is derived from the
  option's `feePayer` as well as the held configuration, so a challenge naming another fee payer is refused here.
- A signed voucher of the wrong kind, for another channel, or not committed to H: `signed-not-bound`, and it is dropped.

## In Python

The same steps: `open_channel(atr_bytes, opened, binding, landed=None)`, `await within(doc, hold, binding, signer,
refund=None, inputs=None)`, and `record_charge(hold, charged)`. The hold is a `dict` with the same members. The
[Python README](https://github.com/IntegraLedger/integra-agentic-terms/tree/main/agentic-terms-py#channels-and-sessions)
runs the same channel and prints the same channel id.
