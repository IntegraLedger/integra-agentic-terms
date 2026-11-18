---
title: TypeScript API
description: Every export of @integraledger/terms, with its signature and what it returns.
---

Everything on this page is exported from `@integraledger/terms`. The package is ESM only and needs Node.js
`>=24.22.1`. Bindings, one per pairing, are exported by `@integraledger/lcp`; the
[pairings reference](./pairings.md) names each one.

No function throws for a protocol outcome. Each returns its result or a `Declined`; nothing the seller serves and
nothing the approver answers makes it throw. The checks, their order and their declines are the profile
[`buyer-gate.md`](https://github.com/IntegraLedger/integra-agentic-terms/blob/main/agentic-terms/profiles/buyer-gate.md)'s.

## Versions and compatibility

This page documents `@integraledger/terms` 0.5.0:

```sh
npm install @integraledger/terms@0.5.0 @integraledger/lcp@0.6.0
```

- `@integraledger/lcp` is a peer dependency, `~0.6.0`: any 0.6.x release. Import the bindings you pass in from that one
  installed copy, the one the gate itself imports.
- Node.js `>=24.22.1`.
- At 0.x a minor release may change a public call, so pin the exact version. [Upgrading](../upgrading.md) lists each
  call that changed from 0.4.x, before and after, and the decline a 0.4 call now gets.

## Functions

### `transact`

```ts no-run
import type { AtrHash } from "@integraledger/lcp";
import type {
  AgreementChallenges,
  AgreementReceipt,
  Binding,
  Declined,
  Fetch,
  Presented,
  Signer,
  ToApprove,
  ToReturn,
  TransactOptions,
} from "@integraledger/terms";

declare function transact(
  doc: unknown,
  binding: Binding,
  signer: Signer,
  fetch: Fetch,
  options: TransactOptions,
): Promise<
  | { signed: Presented | null; landed?: unknown; bytes: Uint8Array; h: AtrHash; agreement?: AgreementReceipt }
  | ToApprove
  | AgreementChallenges
  | ToReturn
  | Declined
>;
```

The gate's checks 1 to 11, then, for a pairing whose payment is not itself a public proof, the agreement, paid only on
an option the pairing's `agreementOn` admits, then for each signing the approver (check 12), then the signer, then
`finish`. `options.approver` and `options.resourceRequest` are required. Without `options.approved`, an agreement not yet recorded is returned as `{ approve, bytes, h }`: the agreement
payment for the agent to approve, with nothing signed. With `options.approved`, the value of `approve` carried back
unchanged, that payment is signed and paid as `agree` pays it, and the payment for the resource is signed only with the
agreement's receipt in hand. On a decline before the signer, the signer is never called. `signed` is `null` when the
pairing gives the buyer nothing to sign. `agreement` is the agreement's receipt, where the pairing needs one; `landed`
where `finish` gives one. `options.signal` ends the agreement exchange. `options.chosen`, the payment `confirm` chose,
unchanged, makes `transact` build that exact request rather than choose anew. Options that are not an object holding a
function `approver` and an object `resourceRequest`, or that hold a member other than `inputs`, `ceilings`,
`legalContext`, `agreementSigner`, `approved`, `signal` and `chosen`, or one of the wrong kind, and a `signer` or
`agreementSigner` whose `account` is not a string, are declined `no-payable-option` with `<namespace>/input-malformed`
before any fetch.

Every signing is shown before it is signed: the approver is called once for each, the agreement payment's and each
later step's among them, with `ToSign`, and the signer only when it answers `true`. The agreement payment is also
returned first with its amount, asset, payee and network, and signed only when a second call carries it back. The gate
applies no spending limit. Where the pairing is paid after its agreement and the first response offers the agreement
alone, `transact` pays it as soon as the approver approves it, without returning it first, and returns `ToReturn`,
signing no charge; `options.legalContext` is that response's
`Legal-Context` value as received. On MPP it follows the agreement URL the agreement challenges carry and pays an x402
agreement option there; where that resource offers only MPP agreement challenges, `ToReturn` holds them as
`agreementChallenges`, in place of `agreement`, and nothing is signed. Where the agreement URL a charge names offers
only MPP agreement challenges, `transact` returns `AgreementChallenges`, `{ agreementChallenges, bytes, h }`, signing
nothing: your own MPP client pays one at the agreement URL. Each signing is asked of the approver with `act`
`"agreement"` where it is the agreement payment, or a payment through a pairing whose agreement is never a charge (its
registry data holds `agreement.only`), and `"payment"` otherwise; `step.count` is the number of signings the pairing's
payment takes. Once the agreement payment is sent, every decline carries it as `moved`: `agreement-pending` where it
may settle yet, `agreement-failed` where the agreement URL answered otherwise. See [`agree`](#agree) for collecting its
receipt.

### `confirm`

```ts no-run
import type { AtrHash } from "@integraledger/lcp";
import type { Binding, Chosen, ConfirmOptions, Declined, Fetch, SigningRequest, Summary } from "@integraledger/terms";

declare function confirm(
  doc: unknown,
  binding: Binding,
  account: string,
  fetch: Fetch,
  options: ConfirmOptions,
): Promise<{ chosen: Chosen; request: SigningRequest | null; summary?: Summary; bytes: Uint8Array; h: AtrHash } | Declined>;
```

Reads the offer, chooses the option for `account`, fetches the ATR and compares its SHA-256 with the advertised hash;
parses the bytes, holds the option chosen to the options the ATR's binding slot lists and `options.resourceRequest` to
the `x402` slot's request commitment; and only then builds, with the hash it computed, and holds the request to its summary and its ceiling
(checks 1 to 11). It calls no approver. `request` is what the signer is handed, with its `summary`, or `null` when
nothing is handed to the signer: the pairing has nothing for the buyer to sign, or the build is itself the payment,
which `finish` completes with no signature. `chosen.agreement` is the agreement URL, for a pairing whose payment is not
a public proof; `chosen.deadline` the latest deadline handed to a wallet that picks its expiry. Options that are not an
object holding `resourceRequest` and only `inputs` and `ceilings`, of their forms, are declined before the offer is
read.

`confirm` and `finish` neither pay nor check the agreement; only `transact` and `agree` do. When `chosen.agreement` is
set, the pairing's payment is not itself a public proof of H: do not sign yet. Call
`agree(bytes, chosen.agreement, signer, fetch, { chosen })`, have your agent approve the `approve` it returns, call
`agree` again with `{ approved, chosen }`, and sign `request` only with its `receipt` in hand.

### `finish`

```ts no-run
import type { AtrHash } from "@integraledger/lcp";
import type { Binding, Chosen, Declined, FinishOptions, Presented, Signature, SigningRequest, Summary } from "@integraledger/terms";

declare function finish(
  bytes: Uint8Array,
  chosen: Chosen,
  signature: Signature,
  binding: Binding,
  options?: FinishOptions,
): Promise<{ signed: Presented; landed?: unknown; h: AtrHash } | { next: SigningRequest; summary: Summary; h: AtrHash } | Declined>;
```

Rebuilds the payment from `chosen` and the bytes, joins the signer's answer, and returns the payment only when the
pairing's `bound` reads the hash of these bytes from the completed payment. For a pairing signed in steps, returns
`next` with its `summary`, only once the later step has a summary and is within the pairing's ceiling, which
`options.ceilings` raises (checks 10 and 11); a voucher that names only its channel is shown with its opening's payees,
asset, network and validity, the channel recomputed for the account `chosen` holds; call `finish` again with every answer so far, in order, as a list. For a pairing whose payment is not a public
proof and whose `bound` finds no signed place for H, the proof is the agreement payment, and the completed payment is
returned as it is. Where the signer moved the payment itself, a decline keeps it as `moved`. `landed` is a landed
receipt the completion carried and the payment leaves out, as JSON, each integer a decimal string.

### `check`

```ts no-run
import type { AtrHash } from "@integraledger/lcp";
import type { Binding, Declined } from "@integraledger/terms";

declare function check(
  bytes: Uint8Array,
  presented: unknown,
  binding: Binding,
  landed?: unknown,
  act?: "payment" | "agreement",
): Promise<{ h: AtrHash } | Declined>;
```

Confirms that the ATR hash the pairing reads from a payment held later is the SHA-256 of the kept bytes. A payment from
which the pairing reads no ATR hash is declined `signed-not-bound`. Pass the `landed` receipt `finish` or `transact`
returned beside the payment, where there is one, as `landed`: `check` holds it under the payment's own `FETCHED`
member as `bound` reads it, and a `landed` member written into the payment is not read. The caller passes as `landed`
only the receipt its own reader read for the payment, as `finish` or `transact` returned it, never a value another
party sent. A `landed` of `null` is no receipt: the payment is read alone. A `landed` that is not a JSON object, or a
payment that is not one, is declined `signed-not-bound`. `act` is the act the payment was paid as: `"payment"`, the
default, or `"agreement"` for an agreement payment, which `bound` is then given with the hash, so it reads H where the
payment carries the agreement's own single-use value, `agreementValue(H)`, in its place.

### `agree`

```ts no-run
import type {
  AgreeOptions,
  AgreementChallenges,
  AgreementReceipt,
  Declined,
  Fetch,
  Signer,
  ToApprove,
} from "@integraledger/terms";

declare function agree(
  bytes: Uint8Array,
  url: string,
  signer: Signer,
  fetch: Fetch,
  options?: AgreeOptions,
): Promise<ToApprove | AgreementChallenges | { receipt: AgreementReceipt } | Declined>;
```

The agreement for the hash of `bytes` at `url`, in two calls. Without `options.approved`, asks the agreement URL for its
payment request and returns `{ approve, bytes, h }`, signing nothing; where the agreement is already recorded, returns
its receipt; where its `402` carries no `PAYMENT-REQUIRED` and carries MPP agreement challenges, returns them as
`{ agreementChallenges, bytes, h }`, signing nothing, for the caller's own MPP client to pay at `url`. With `options.approved`, the value of `approve` carried back unchanged, holds exactly that payment to its summary and its
own pairing's ceiling, `options.ceilings` raising it, as `transact` does, then signs it with `signer`, sends it, and
returns the receipt once recorded. Before anything is fetched or signed, an approved payment
whose `required` the protocol package's read refuses for its version, its legal context or agreement URL, or an
`accepts` that is not a list of at most 32 entries holding an option is declined `offer-unreadable` with the read's
code, as the unpaid request is, and one whose `option` is not one of `required.accepts`, compared by RFC 8785 form, is
declined `offer-unreadable` with `x402/option-not-in-document`. The option paid is the first, in document order, that
`signer` can pay with an x402 pairing whose registry data lets its payment be an agreement (`agreement`; the
[pairings reference](./pairings.md) marks these `yes` or `only`) and, given `options.chosen`, the charge the agreement is
for, exactly as `confirm` returned it, that the charge's pairing admits by its `agreementOn`. `options.inputs` are the
buyer's own chain values; `options.signal` ends the exchange. `agree` takes no approver: a request it has no summary
for is declined `summary-missing`, and one payable past the ceiling `past-ceiling` or `no-end`, before it is signed,
and a wallet that picks its expiry is handed the latest deadline it may sign.
Options holding anything but `approved`, `inputs`, `ceilings`, `signal` and `chosen`, or a member of the wrong kind,
and a `signer` whose `account` is not a string, are declined before any fetch.
See [agreement payments](../guides/agreement-payments.md).

The receipt is the agreement URL's statement: the gate checks its form and that its `atrHash` is H, and does not look
up the transaction it names. A `200` to the first, unpaid request is taken as an agreement already recorded.

Once the agreement payment is sent, every decline carries it as `moved`. The code is `agreement-pending` where it may
settle yet: a `202`, a `5xx` or a timeout until the exchange's bound, or your `signal`. It is `agreement-failed` where
the agreement URL answered with a redirect, another status, or a `200` that is not a receipt for H. Either way, keep
`moved`, and call again without `approved` to learn whether it is recorded: the gate asks the agreement URL unpaid and
goes on once it answers `200` with the receipt, or declines `agreement-pending` again while it answers `202`, signing
nothing. Never call again with `approved` for the same agreement: every call with `approved` signs and sends a new
agreement payment.

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
`transact` returned beside it, where there is one. The caller passes as `landed` only the receipt its own reader read
for the opening, as `transact` returned it, never a value another party sent. The opening must be of kind `open`, the
pairing must read the hash of these bytes from it, and it must name its channel. The hold keeps the opening as signed
and the read as its own `landed` member: the `landed` receipt, else the read the opening holds under its own `FETCHED`
member.

### `within`

```ts no-run
import type { Binding, ChannelHold, Declined, Inputs, Presented, Signer } from "@integraledger/terms";

declare function within(
  doc: unknown,
  hold: ChannelHold,
  binding: Binding,
  signer: Signer,
  refund?: { amount?: string; paymentResponse?: { errorReason?: string } },
  inputs?: Inputs,
): Promise<{ signed: Presented; hold: ChannelHold } | Declined>;
```

Signs one later voucher, or a refund, in a held channel. The ATR's bytes, its hash and the channel come from the hold,
and the amount from the new challenge. On x402's batch channels the challenge must advertise the held hash, and the
payment the build returns must name the held channel before the signer is called. On an MPP session, a challenge that
names another channel or another hash is declined before the signer is called, and one with no legal context is signed
under the held hash. `within` takes no approver, and holds the voucher to no summary or ceiling. A voucher's cumulative amount is the recorded charge plus the option's amount; a refund's is the
recorded charge. A Solana refund also carries the payer-signed `request_close` when it is taken again: when the
`errorReason` of `refund.paymentResponse`, the settle failure's decoded `PAYMENT-RESPONSE`, read first, or else the
document's `error`, is `invalid_batch_settlement_svm_receiver_binding_unavailable`. See
[channels and sessions](../guides/channels-and-sessions.md#refunds-and-closing).

### `viJson`

```ts no-run
declare function viJson(value: unknown): string | undefined;
```

The JSON text a Mastercard Verifiable Intent signer signs for a value (the protocol package's profile
`card-mastercard-vi.md`, rule 7): compact, every character outside space to `~` escaped, a non-ASCII one as `\uXXXX`
in lowercase hex, one per UTF-16 code unit, members in the order the object holds them, as Python's
`json.dumps(value, separators=(",", ":"))` writes it. Undefined for a value that is not JSON.

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
| `Signature` | The signer's answer, as JSON, in the form [signers](../guides/signers.md) names for its kind; a list, in order, for `batch`. |
| `Inputs` | `{ readonly [k: string]: Json }`: the buyer's own values a build needs. |
| `TransactOptions` | `{ approver: Approver; resourceRequest: ResourceRequest; inputs?: Inputs; ceilings?: Ceilings; legalContext?: string; agreementSigner?: Signer; approved?: AgreementPayment; signal?: AbortSignal; chosen?: Chosen }`. |
| `ConfirmOptions` | `{ resourceRequest: ResourceRequest; inputs?: Inputs; ceilings?: Ceilings }`. |
| `FinishOptions` | `{ ceilings?: Ceilings }`. |
| `AgreeOptions` | `{ approved?: AgreementPayment; inputs?: Inputs; signal?: AbortSignal; chosen?: Chosen }`. |
| `Approver` | `(toSign: ToSign) => boolean \| Promise<boolean>`: approves only by answering `true`. |
| `ToSign` | `{ act: "payment" \| "agreement"; pairing: string; request: SigningRequest; summary: Summary; step: SigningStep }`. |
| `SigningStep` | `{ index: number; count: number }`: which signing of the payment, from 0, of the number the pairing's payment takes. |
| `Summary` | `{ amount?; maximum?; payees: Payee[]; period?; limitPerPeriod?; end?; operator?; authorizationExpiry?; refundExpiry?; deposit?; closableBy?: string[]; grant?: Json; asset: string; network: string \| null; validity: Validity; atr: Uint8Array }`, every integer a decimal string. See [the approver](../guides/pay-with-the-gate.md#the-approver). |
| `Payee` | `{ account: string; amount: string }`. |
| `Validity` | `{ notBefore: string \| null; notAfter: string \| null; unit: string }`, `unit` `"seconds"` or the chain's unit. |
| `ResourceRequest` | `HttpRequest \| ToolCall`, the protocol package's types: `{ method; target; body: Uint8Array; headers? }`, `target` the origin-form request-target as sent (the path and query, starting with `/`), or `{ name; arguments? }`. |
| `Ceilings` | `{ readonly [pairing: string]: number \| "no-end" }`. |
| `ToReturn` | `{ agreement?: AgreementReceipt; agreementChallenges?: readonly MppChallenge[]; legalContext: string; charge: string; bytes: Uint8Array; h: AtrHash }`: exactly one of `agreement` and `agreementChallenges` is present. |
| `AgreementChallenges` | `{ agreementChallenges: readonly MppChallenge[]; bytes: Uint8Array; h: AtrHash }`: the agreement resource's MPP agreement challenges, in the seller's order, for the caller's own MPP client; nothing is signed. `MppChallenge` is the protocol package's type (`@integraledger/lcp/mpp`). |
| `Chosen` | `{ pairing: string; choice: Json; ref: string; agreement?: string; deadline?: string }`: what the gate chose to pay, as plain JSON, with the agreement URL where the pairing needs one, and the latest deadline handed to a wallet that picks its expiry. |
| `AgreementPayment` | `{ url: string; option: PaymentRequirements; required: PaymentRequired }`: the agreement payment to approve. `option` is the x402 option paid, with its `amount`, `asset`, `payTo` and `network`; `required` is the agreement URL's payment request as served. |
| `ToApprove` | `{ approve: AgreementPayment; bytes: Uint8Array; h: AtrHash }`. |
| `AgreementReceipt` | `{ atrHash: AtrHash; agreed: true; network: string; transaction: string }`. |
| `ChannelHold` | `{ pairing; network; channel; h; atr; opening; landed?; charged; signedMax }`. See [the hold](../guides/channels-and-sessions.md#the-hold). |
| `Declined` | `{ decline: Reason; moved?: { signed: unknown; bytes: Uint8Array; h: AtrHash } }`. |
| `Reason` | `{ code: DeclineCode; detail: string }`. |
| `DeclineCode` | One of the codes in the [declines reference](./declines.md). |

`AtrHash` and `Json` are exported by `@integraledger/lcp`; `PaymentRequirements` and `PaymentRequired` by
`@integraledger/lcp/x402`.

## Constants of the gate

| Bound | Value |
| --- | --- |
| Largest ATR fetched, hashed or checked | 1,048,576 bytes |
| ATR fetch deadline, over headers and body | 10 seconds |
| ATR fetch | one `GET`, `redirect: "manual"`, a redirect answered is `atr-unfetchable`, `https` only |
| Content coding, every request | `Accept-Encoding: identity`; a `200` with any other `Content-Encoding` is declined unread (`atr-unfetchable` for the ATR), and so is a `200` or a `402` from the agreement URL (`agreement-failed`) |
| Signer calls for one payment | at most 2 |
| A pairing's ceiling | 600 seconds, unless `ceilings` raises it; on a rail with a served floor, the floor plus the service's margin |
| `FLOOR_INPUTS` | `ReadonlyMap<string, readonly string[]>`: each pairing whose rail has a served floor, with the names of its floor inputs |
| Agreement URL, unpaid request | 10 seconds |
| Agreement URL, each paid request | `min(maxTimeoutSeconds, 120) + 70` seconds |
| Agreement exchange, whole | `maxTimeoutSeconds + 180` seconds, of the option paid |
| Agreement option's `maxTimeoutSeconds` | a JSON number with an integral value, from 1 to 2<sup>53</sup> − 1 |
| Agreement receipt | at most 64 KiB |
| Agreement retry after `202` | `Retry-After` seconds, one to nine digits, at least 1; 2 when absent or in any other form, an HTTP-date included |
