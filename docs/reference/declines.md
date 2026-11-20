---
title: Declines
description: Every decline code the gate returns, what it means, what was and was not done, and the detail codes it carries.
---

This page is for a developer handling what the gate returns: every decline code, when it is returned, whether the
signer was called, and what to do next. The gate never throws for a protocol outcome. Every function returns its result
or a decline:

```ts no-run
import type { AtrHash } from "@integraledger/lcp";
import type { DeclineCode } from "@integraledger/terms";

type Declined = {
  readonly decline: { readonly code: DeclineCode; readonly detail: string };
  readonly moved?: { readonly signed: unknown; readonly bytes: Uint8Array; readonly h: AtrHash };
};
```

In Python, a decline is `Declined(code, detail, moved)`, with `moved` a `Moved(signed, atr_bytes, h)` or `None`.

`code` is one of the values below, the `DeclineCode` type in both languages. `detail` is either a sentence for a person to read, or a refusal code,
normally of the form `<protocol>/<reason>`, such as `x402/no-payable-option` or `mpp/credential-malformed`
(`member-failed`, for a binding member that threw in `openChannel` or `within`, has no prefix). Program against `code`;
log `detail`.

## Decline codes

| Code | Returned when | Signer called? | What to do |
| --- | --- | --- | --- |
| `pairing-not-supported` | The binding names no pairing the gate serves. `chosen`, or a channel hold, belongs to another pairing. The pairing has no channel (for `openChannel` and `within`), or no in-channel build (`within` on `mpp/session/solana/memo`). An MPP in-session action the binding does not build (`mpp/within-action-not-built`). | No | Pass the binding of the pairing the option is (`pairingOf` in `@integraledger/lcp` names an x402 option's), or the hold's own. |
| `offer-unreadable` | The binding cannot read the seller's document, the chosen payment carries no choice, or a build refuses. The payment request of an approved agreement payment is one the protocol package's read refuses for a fault of its own (its version, legal context or agreement URL, or an `accepts` that is not a list of at most 32 entries holding an option), or its option is not one of that request's `accepts` (`x402/option-not-in-document`). For `recordCharge`: the charged amount is not a decimal, is below the charge already recorded, or is above the largest amount signed. The `legalContext` given to `transact` is one the protocol package's `fromLegalContextHeader` refuses (its code, such as `return/header-malformed`). A first response offering the agreement alone has an agreement option whose served names the protocol package's `servesOf` refuses, read alone or resolved against the ATR's bytes (`return/serves-malformed`). | No | Do not pay. `detail` is the reason, often the protocol package's code (an x402 version-1 document is `x402/not-v2`). |
| `no-payable-option` | No option in the document is payable by the signer's account on its network; no option of the agreement URL's payment request is payable by the signer with an x402 pairing whose payment can be an agreement (an option whose `maxTimeoutSeconds` is not a JSON number with an integral value from 1 to 2<sup>53</sup> − 1 included is payable by none); an input the build needs is missing or malformed (`<protocol>/input-missing`); the options of `transact` or `agree` hold something other than their members, or a member of the wrong kind, or the `inputs` given to `confirm`, `agree` or `within` are not an object, or the `account` of the signer or agreement signer given to `transact` or `agree` is not a string, or a Solana refund value, or a Solana refund's `paymentResponse` or its `errorReason`, is given in another form (`<protocol>/input-malformed`), or `confirm`'s or `finish`'s options hold another member; a `refund` passed to `within` is not an object, or its `amount` is not a decimal (`<protocol>/input-missing`); or a later channel challenge asks for a payment in a channel the hold did not open. | No | Use a signer on a network the offer names. For `<protocol>/input-malformed`, fix the call's arguments; for `<protocol>/input-missing`, give the input the build or the ceiling reads (see [rails](../guides/rails.md)). |
| `link-not-https` | The ATR's link, or the agreement URL, is not an `https` URL. `detail` is `<protocol>/link-not-https` for another scheme and `<protocol>/legal-context-malformed` for a value that is not a URL. Nothing was fetched. | No | Do not pay. |
| `atr-unfetchable` | The link answered a status other than `200`, redirected, answered `200` with a `Content-Encoding` other than `identity`, did not answer within 10 seconds, or failed. | No | Nothing was signed. Retry later. |
| `atr-too-large` | The ATR is larger than 1,048,576 bytes, by its declared `Content-Length` or as it streamed. Also for bytes over that size passed to `finish`, `check` or `openChannel`. | No | Do not pay. |
| `hash-mismatch` | SHA-256 of the served bytes is not the advertised H. The agreement URL's challenge advertises another H, or its MPP agreement challenges are placed for another H. The `legalContext` return value given to `transact` names another H. A later channel challenge advertises another H than the held one, or the held bytes do not hash to the held H. | No | Do not pay: the seller served other bytes than it advertised. |
| `signer-failed` | Your signer threw (TypeScript) or raised (Python). | Yes | Your signer's own error. Keep `moved` where it is present. |
| `signed-not-bound` | The pairing does not read the hash of the compared bytes from the payment, from a payment presented to `check` or from a channel opening; the signer's answer did not complete the payment; a channel opening or voucher does not belong to the held channel; the signed agreement payment or channel opening is not plain JSON (nested past 64 levels, or not written by JSON); the channel hold passed to `within` or `recordCharge` is malformed; a `landed` passed to `check` or `openChannel` is not a JSON object beside an object payment. The payment is not returned, and an agreement payment is not sent. | Yes, or not needed | Never send what was signed. Keep `moved` where it is present. |
| `agreement-not-offered` | The pairing's payment is not itself a public proof of H, and the seller's offer names no agreement URL. | No | None: the seller's offer must name an agreement URL. |
| `agreement-pending` | The agreement URL answered `202` before the gate paid (another agreement payment for this ATR is settling); the agreement payment is sent and not recorded within the paid option's `maxTimeoutSeconds` plus 180 seconds; or the caller's `signal` ended the exchange after the agreement payment is sent. | No, for a `202` before paying; otherwise for the agreement only | Keep `moved`, and call again without `approved` to collect the receipt; never again with `approved`. |
| `agreement-failed` | The unpaid request: the agreement URL could not be reached, or answered a status other than `200`, `202` or `402`, or a `402` without a readable `PAYMENT-REQUIRED`. The paid request: any answer but `200`, `202` or a `5xx`, a `402` included (an unreachable URL, a timeout and a `5xx` are retried). Either request: a redirect; a `200` or `402` with a `Content-Encoding` other than `identity`; or a `200` that is not a receipt for this H, a receipt over 64 KiB included. The approved agreement payment names another agreement URL. The caller's `signal` ended the exchange before the agreement payment is sent. | For the agreement only, when it failed after payment | Where `moved` is present, the agreement payment has left your wallet: keep it, and call again without `approved` to learn whether it is recorded. |
| `not-approved` | The approver answered anything but `true` (in Python `True`), threw (raised) or rejected, for the signing it was asked about. | Not for the signing declined; an earlier step of the same payment, or the agreement payment, may have been signed | Your approver's own answer. |
| `atr-malformed` | The ATR's bytes do not parse by the gate's one grammar: not UTF-8; a byte-order mark; not exactly one JSON text (RFC 8259, section 2), `NaN` and `Infinity` among what is not; nesting past 64 levels; a member name repeated in an object, compared after its escapes are decoded; a number that rounds to infinity as a double; or an integer outside −(2^53 − 1) to 2^53 − 1. A seller writes a number beyond the safe integers as a string. | No | Do not pay: no ATR the protocol package writes is declined. |
| `option-not-in-atr` | The ATR's binding slot lists the options offered (`accepts` in `x402`, `challenges` in `mpp`, `options` in `acp`, `ap2`, `card` and `ucp`, `paymentOptions` in `ack`), and none is the option chosen. An option is compared as RFC 8785 JSON in the slot's form (`unplaced`): on `acp` the pairing's handler option, `{"requires_delegate_payment": true}` on `acp/checkout/delegated` and `false` on `acp/checkout/undelegated`; on `ap2` and `ucp` the checkout's `id`, as `{"checkout": id}`, or `{"booking": id}` on the `ucp/booking/` pairings; on `ack` the payment option chosen from the signed Payment Request. An MPP challenge is compared by its bound members (`issuedDigest`, without `id` and the protocol package's `opaque` members). On `card`, whose documents do not show the seller's checkout id, a member of the pairing's `scheme` holds the option. | No | Do not pay. |
| `request-mismatch` | The ATR's `x402` slot holds a `request` commitment that is not the commitment of `resourceRequest`, or one of no form the protocol package writes. Where the protocol package refuses `resourceRequest` itself, `detail` is its code: `x402/request-target-invalid`, `x402/request-header-invalid`, `x402/tool-call-malformed` or `x402/request-too-large`. | No | Check that `resourceRequest` is the request as sent, its `target` origin-form; otherwise do not pay. |
| `summary-missing` | The request handed to the signer is of a kind the gate has no summary for, or one the summary cannot read as its kind's row states (a voucher of a channel the opening did not open, a Gateway burn intent whose challenge request does not give its hash), so it cannot show it; nothing is signed unshown. | No | None: this release cannot show that request, and signs nothing unshown. |
| `past-ceiling` | The signed payment would stay payable longer than the pairing's ceiling: 600 seconds, the served floor plus the service's margin on a rail with a served floor, or the larger value `ceilings` gives. A Circle Gateway burn intent is held in whole blocks of the network it spends from, and one shown on a network other than its `sourceNetwork` input is declined too. | No; where the wallet picks the expiry and signed past the latest deadline it was handed, once, and its payment is discarded | Pay only if your principal accepts the longer window: raise the pairing in `ceilings`. |
| `no-end` | The form signs no end (a delegation, a card checkout, a transaction with no validity), and `ceilings` does not map the pairing to `"no-end"`. | No; where the wallet picks the expiry and signed none, once, and its payment is discarded | Pay only if your principal accepts a payment with no end: map the pairing to `"no-end"` in `ceilings`. |
| `floor-missing` | The pairing's rail has a served floor, and `inputs` does not hold its input in its form. `detail` is the input's name, such as `minValiditySeconds`. | No | Read the floor the rail's service serves and give it in `inputs` under the name in `detail`. |

The terms profile
[`buyer-gate.md`](https://github.com/IntegraLedger/integra-agentic-terms/blob/main/agentic-terms/profiles/buyer-gate.md)
states the order of the checks, the decline each answers, and these last eight codes.

The MCP server adds three codes of its own:

| Code | Returned when | Signer called? |
| --- | --- | --- |
| `hold-unverified` | A channel hold passed to `atr_channel_record_charge` or `atr_channel_within` is not one this server process returned, unchanged: its `mac` does not verify. See [channel holds](./mcp.md#channel-holds). | No |
| `opening-unverified` | A channel opening passed to `atr_channel_open` is not one this server process returned, unchanged: the `mac` beside it does not verify. See [channel holds](./mcp.md#channel-holds). | No |
| `chosen-unverified` | The `chosen` passed to `atr_agree`, or to `atr_finish` for a pairing with a channel, is not one `atr_confirm` returned in this server process, unchanged: its `mac` does not verify. Nothing is fetched. See [`atr_agree`](./mcp.md#atr_agree) and [channel holds](./mcp.md#channel-holds). | No |

## `moved`

Some signers move the payment themselves: a Lightning node pays the invoice, a signer broadcasts a transaction it was
asked to broadcast. If the gate declines after that, the decline carries `moved`:

- `signed`: the payment as signed, in the protocol's own form (or the signer's answers, in order, for a payment signed
  in steps);
- `bytes` (`atr_bytes` in Python): the ATR's bytes;
- `h`: their SHA-256.

The agreement exchange does the same: once the agreement payment has been sent, every decline carries it as `moved`.

Keep `moved`. It is a payment that has left, or may have left, your wallet. For the payment for the resource, present it
again to the seller rather than signing a new one. For an agreement payment, call again without `approved`: the gate
asks the agreement URL unpaid and goes on once it answers `200` with the receipt, or declines `agreement-pending` again
while it answers `202`, signing nothing. Never call again with `approved` for the same agreement: every call with
`approved` signs and sends a new agreement payment.

## Detail codes the gate writes

Most refusal codes in `detail` come from the binding in `@integraledger/lcp`, which documents them. These are the ones
the gate itself writes:

| Detail | Meaning |
| --- | --- |
| `<protocol>/no-payable-option` | No option or challenge serves the signer's account. An MPP challenge the protocol package's checks refuse serves none, whatever their refusal code: `transact`, `confirm` and `within` pass over it. `within` reads a challenge that names the held channel without those checks, and declines its faults as this page lists them. |
| `<protocol>/input-missing` | A value the build reads from `inputs` is absent or of the wrong form; a `refund` passed to `within` is not an object, or its `amount` is not a decimal. See [rails](../guides/rails.md). Also `xrpl/input-missing`, `cardano/input-missing` (`cip34/input-missing` on a network named by its CIP-34 alias) and `sui/input-missing` at the ceiling check, where `inputs` lacks `ledgerIndex`, `currentSlot` or `currentEpoch`. |
| `<protocol>/input-malformed` | `transact`'s, `confirm`'s, `finish`'s or `agree`'s options (an `approver` that is not a function, a `resourceRequest` that is not an object, `ceilings` of another form, among them), or a session's inputs, are malformed, the `inputs` given to `confirm`, `agree` or `within` are not an object, the `account` of the signer or agreement signer given to `transact` or `agree` is not a string, or a Solana refund value, or a Solana refund's `paymentResponse` or its `errorReason`, is given in another form. See [refunds](../guides/channels-and-sessions.md#refunds-and-closing). |
| `<protocol>/choice-malformed` | The `chosen` handed to `finish` does not carry the choice the pairing built from. |
| `<protocol>/signature-malformed`, `mpp/credential-malformed` | The signer's answer is not of the form the request kind takes. See [signers](../guides/signers.md). |
| `<protocol>/build-failed` | The binding's build threw. |
| `<protocol>/link-not-https`, `<protocol>/legal-context-malformed` | The link or agreement URL is not an `https` URL. |
| `x402/option-not-in-document` | The option of an approved agreement payment is not one of its payment request's `accepts`, compared by RFC 8785 form, as the protocol package's build holds a chosen option to the document. |
| `x402/payment-identifier-unwritable` | The seller advertises x402's `payment-identifier` extension, and its `info` is not an object or already holds an `id`. |
| `x402/payload-malformed` | A rail's completed payment is not of the form the pairing's payload takes. |
| `mpp/request-malformed` | An MPP challenge's `request` is not base64url JSON with a decimal amount. |
| `mpp/opaque-malformed` | A session's within challenge carries an `opaque` that is not MPP's flat string-to-string map: base64url without padding, at most 8 KiB decoded, one JSON object whose members are all strings. |
| `mpp/legal-context-malformed` | In `within`: the session challenge's `opaque.legalContext` is not an LCP string. (As the link's refusal, see `<protocol>/legal-context-malformed` above.) |
| `<protocol>/option-malformed` | An option or challenge member that the build or the gate reads is not of its form, such as a batch option's `extra.minDeposit`, a channel challenge's `amount`, or the network of an x402 option a wallet builds from. |
| `x402/request-malformed` | A rail's build gave no request for the signer. |
| `card/vi-malformed` | A Verifiable Intent build gave no checkout mandate. |
| `mpp/within-action-not-built` | The in-session action (a top-up, for example) is not one the binding builds. |
| `ln/preimage-malformed` | The Lightning node's answer is not a 64-digit hex preimage. |
