---
title: TypeScript API
description: Every export of @integraledger/terms, with its signature and what it returns.
---

Everything on this page is exported from `@integraledger/terms`. The package is ESM only and needs Node.js
`>=26.10.0`. Bindings, one per pairing, are exported by `@integraledger/lcp`; the
[pairings reference](./pairings.md) names each one.

No function throws for a protocol outcome. Each returns its result or a `Declined`.

## Functions

### `transact`

```ts no-run
import type { AtrHash } from "@integraledger/lcp";
import type {
  AgreementReceipt,
  Binding,
  Declined,
  Fetch,
  Presented,
  Signer,
  ToApprove,
  TransactOptions,
} from "@integraledger/terms";

declare function transact(
  doc: unknown,
  binding: Binding,
  signer: Signer,
  fetch: Fetch,
  options?: TransactOptions,
): Promise<
  | { signed: Presented | null; landed?: unknown; bytes: Uint8Array; h: AtrHash; agreement?: AgreementReceipt }
  | ToApprove
  | Declined
>;
```

`confirm`, then, for a pairing whose payment is not itself a public proof, the agreement, then the signer, then
`finish`. Without `options.approved`, an agreement not yet recorded is returned as `{ approve, bytes, h }`: the agreement
payment for the agent to approve, with nothing signed. With `options.approved`, the value of `approve` carried back
unchanged, that payment is signed and paid, and the payment for the resource is signed only with the agreement's
receipt in hand. On a decline before the signer, the signer is never called. `signed` is `null` when the pairing gives
the buyer nothing to sign. `agreement` is the agreement's receipt, where the pairing needs one; `landed` where `finish`
gives one. `options.signal` ends the agreement exchange. Options holding anything but `inputs`, `agreementSigner`,
`approved` and `signal`, or a member of the wrong kind, are declined before any fetch.

### `confirm`

```ts no-run
import type { AtrHash } from "@integraledger/lcp";
import type { Binding, Chosen, Declined, Fetch, Inputs, SigningRequest } from "@integraledger/terms";

declare function confirm(
  doc: unknown,
  binding: Binding,
  account: string,
  fetch: Fetch,
  inputs?: Inputs,
): Promise<{ chosen: Chosen; request: SigningRequest | null; bytes: Uint8Array; h: AtrHash } | Declined>;
```

Reads the offer, chooses the option for `account`, fetches the ATR and compares its SHA-256 with the advertised hash.
Only on a match does it build, with the hash it computed. `request` is what the signer signs, or `null` when the pairing
has nothing for the buyer to sign. `chosen.agreement` is the agreement URL, for a pairing whose payment is not a public
proof.

### `finish`

```ts no-run
import type { AtrHash } from "@integraledger/lcp";
import type { Binding, Chosen, Declined, Presented, Signature, SigningRequest } from "@integraledger/terms";

declare function finish(
  bytes: Uint8Array,
  chosen: Chosen,
  signature: Signature,
  binding: Binding,
): Promise<{ signed: Presented; landed?: unknown; h: AtrHash } | { next: SigningRequest; h: AtrHash } | Declined>;
```

Rebuilds the payment from `chosen` and the bytes, joins the signer's answer, and returns the payment only when what was
signed carries the hash of these bytes. For a pairing signed in steps, returns `next`; call `finish` again with every
answer so far, in order, as a list. For a pairing whose payment is not a public proof and whose signed contents have no
place for H, the proof is the agreement payment, and the completed payment is returned as it is. Where the signer moved
the payment itself, a decline keeps it as `moved`. `landed` is a landed receipt the completion carried and the payment
leaves out, as JSON, each integer a decimal string.

### `check`

```ts no-run
import type { AtrHash } from "@integraledger/lcp";
import type { Binding, Declined } from "@integraledger/terms";

declare function check(bytes: Uint8Array, presented: unknown, binding: Binding): Promise<{ h: AtrHash } | Declined>;
```

Confirms that a payment held later carries, inside what was signed, the hash of the kept bytes. Put `landed` back into
the payment first, where one was returned.

### `agree`

```ts no-run
import type { AgreeOptions, AgreementReceipt, Declined, Fetch, Signer, ToApprove } from "@integraledger/terms";

declare function agree(
  bytes: Uint8Array,
  url: string,
  signer: Signer,
  fetch: Fetch,
  options?: AgreeOptions,
): Promise<ToApprove | { receipt: AgreementReceipt } | Declined>;
```

The agreement for the hash of `bytes` at `url`, in two calls. Without `options.approved`, asks the agreement URL for its
payment request and returns `{ approve, bytes, h }`, signing nothing; where the agreement is already recorded, returns
its receipt. With `options.approved`, the value of `approve` carried back unchanged, signs exactly that payment with
`signer`, sends it, and returns the receipt once recorded. The option paid is the first, in document order, that
`signer` can pay with a pairing whose payment is itself a public proof. `options.inputs` are the buyer's own chain
values; `options.signal` ends the exchange. See [agreement payments](../guides/agreement-payments.md).

### `openChannel`

```ts no-run
import type { Binding, ChannelHold, Declined, Presented } from "@integraledger/terms";

declare function openChannel(
  bytes: Uint8Array,
  opened: Presented,
  binding: Binding,
  landed?: unknown,
): Promise<ChannelHold | Declined>;
```

Takes a channel pairing's signed opening and the ATR bytes the gate compared for it, with the `landed` receipt
`transact` returned beside it, where there is one. The opening must be of kind `open`, carry the hash of these bytes,
and name its channel.

### `within`

```ts no-run
import type { Binding, ChannelHold, Declined, Inputs, Presented, Signer } from "@integraledger/terms";

declare function within(
  doc: unknown,
  hold: ChannelHold,
  binding: Binding,
  signer: Signer,
  refund?: { amount?: string },
  inputs?: Inputs,
): Promise<{ signed: Presented; hold: ChannelHold } | Declined>;
```

Signs one later voucher, or a refund, in a held channel. Everything is re-derived from the hold, the challenge must
advertise the held hash, and the payment the build returns must name the held channel before the signer is called. A
voucher's cumulative amount is the recorded charge plus the option's amount; a refund's is the recorded charge. See
[channels and sessions](../guides/channels-and-sessions.md).

### `recordCharge`

```ts no-run
import type { ChannelHold, Declined } from "@integraledger/terms";

declare function recordCharge(hold: ChannelHold, chargedCumulativeAmount: string): ChannelHold | Declined;
```

Records the seller's cumulative charge: a decimal no lower than the charge last recorded and no higher than the largest
amount signed in the channel.

## Types

| Type | Definition |
| --- | --- |
| `Binding` | A pairing's binding: a binding of `@integraledger/lcp`. |
| `Presented` | A payment in its protocol's form. |
| `Fetch` | `(url: string, init: { method: "GET"; redirect: "manual"; signal: AbortSignal; headers?: Record<string, string> }) => Promise<Response>`. A `3xx` answer, or one of type `opaqueredirect`, is a redirect, which the gate never follows. Every request the gate makes carries `Accept-Encoding: identity`. |
| `Signer` | `{ readonly account: string; sign(request: SigningRequest): Promise<Signature> }`. `account` is CAIP-10. |
| `SigningRequest` | What a signer is handed: the union of every request kind. See [signers](../guides/signers.md). |
| `Signature` | The signer's answer, as JSON. Byte strings are `0x` hex; a list, in order, for `batch`. |
| `Inputs` | `{ readonly [k: string]: Json }`: the buyer's own values a build needs. |
| `TransactOptions` | `{ inputs?: Inputs; agreementSigner?: Signer; approved?: AgreementPayment; signal?: AbortSignal }`. |
| `AgreeOptions` | `{ approved?: AgreementPayment; inputs?: Inputs; signal?: AbortSignal }`. |
| `Chosen` | `{ pairing: string; choice: Json; ref: string; agreement?: string }`: what the gate chose to pay, as plain JSON, with the agreement URL where the pairing needs one. |
| `AgreementPayment` | `{ url: string; option: PaymentRequirements; required: PaymentRequired }`: the agreement payment to approve. `option` is the x402 option paid, with its `amount`, `asset`, `payTo` and `network`; `required` is the agreement URL's payment request as served. |
| `ToApprove` | `{ approve: AgreementPayment; bytes: Uint8Array; h: AtrHash }`. |
| `AgreementReceipt` | `{ atrHash: AtrHash; agreed: true; network: string; transaction: string }`. |
| `ChannelHold` | `{ pairing; network; channel; h; atr; opening; charged; signedMax }`. See [the hold](../guides/channels-and-sessions.md#the-hold). |
| `Declined` | `{ decline: Reason; moved?: { signed: unknown; bytes: Uint8Array; h: AtrHash } }`. |
| `Reason` | `{ code: DeclineCode; detail: string }`. |
| `DeclineCode` | One of the twelve codes in the [declines reference](./declines.md). |

`AtrHash` and `Json` are exported by `@integraledger/lcp`; `PaymentRequirements` and `PaymentRequired` by
`@integraledger/lcp/x402`.

## Constants of the gate

| Bound | Value |
| --- | --- |
| Largest ATR fetched, hashed or checked | 1,048,576 bytes |
| ATR fetch deadline, over headers and body | 10 seconds |
| ATR fetch | one `GET`, `redirect: "manual"`, a redirect answered is `atr-unfetchable`, `https` only |
| Content coding, every request | `Accept-Encoding: identity`; a `200` with any other `Content-Encoding` is declined unread (`atr-unfetchable` for the ATR, `agreement-failed` for the agreement URL) |
| Signer calls for one payment | at most 2 |
| Agreement URL, unpaid request | 10 seconds |
| Agreement URL, each paid request | `min(maxTimeoutSeconds, 120) + 70` seconds |
| Agreement exchange, whole | `maxTimeoutSeconds + 180` seconds, of the option paid |
| Agreement option's `maxTimeoutSeconds` | a JSON number with an integral value, from 1 to 2<sup>53</sup> − 1 |
| Agreement receipt | at most 64 KiB |
| Agreement retry after `202` | `Retry-After` seconds, at least 1; 2 when absent |
