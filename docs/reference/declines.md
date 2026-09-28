---
title: Declines
description: Every decline code the gate returns, what it means, what was and was not done, and the detail codes it carries.
---

The gate never throws for a protocol outcome. Every function returns its result or a decline:

```ts no-run
import type { AtrHash } from "@integraledger/lcp";
import type { DeclineCode } from "@integraledger/terms";

type Declined = {
  readonly decline: { readonly code: DeclineCode; readonly detail: string };
  readonly moved?: { readonly signed: unknown; readonly bytes: Uint8Array; readonly h: AtrHash };
};
```

In Python, a decline is `Declined(code, detail, moved)`, with `moved` a `Moved(signed, atr_bytes, h)` or `None`.

`code` is one of the twelve values below. `detail` is either a sentence for a person to read, or a refusal code of the
form `<protocol>/<reason>`, such as `x402/no-payable-option` or `mpp/credential-malformed`. Program against `code`;
log `detail`.

## Decline codes

| Code | Returned when | Signer called? |
| --- | --- | --- |
| `pairing-not-supported` | The binding names no pairing the gate serves. `chosen`, or a channel hold, belongs to another pairing. The pairing has no channel (for `openChannel` and `within`). An MPP in-session action the binding does not build (`mpp/within-action-not-built`). | No |
| `offer-unreadable` | The binding cannot read the seller's document, the chosen payment carries no choice, a build refuses, or the agreement URL's option is malformed (its `maxTimeoutSeconds` not a JSON number with an integral value from 1 to 2<sup>53</sup> − 1 included). For `recordCharge`: the charged amount is not a decimal, is below the charge already recorded, or is above the largest amount signed. | No |
| `no-payable-option` | No option in the document is payable by the signer's account on its network; no option of the agreement URL's payment request is payable by the signer with a pairing whose payment is a public proof; an input the build needs is missing or malformed (`<protocol>/input-missing`); the options of `transact` or `agree` hold something other than their members, or a member of the wrong kind (`<protocol>/input-malformed`); or a later channel challenge asks for a payment in a channel the hold did not open. | No |
| `link-not-https` | The ATR's link, or the agreement URL, is not an `https` URL. `detail` is `<protocol>/link-not-https` for another scheme and `<protocol>/legal-context-malformed` for a value that is not a URL. Nothing was fetched. | No |
| `atr-unfetchable` | The link answered a status other than `200`, redirected, answered `200` with a `Content-Encoding` other than `identity`, did not answer within 10 seconds, or failed. | No |
| `atr-too-large` | The ATR is larger than 1,048,576 bytes, by its declared `Content-Length` or as it streamed. Also for bytes over that size passed to `finish`, `check` or `openChannel`. | No |
| `hash-mismatch` | SHA-256 of the served bytes is not the advertised H. The agreement URL's challenge advertises another H. A later channel challenge advertises another H than the held one, or the held bytes do not hash to the held H. | No |
| `signer-failed` | Your signer threw (TypeScript) or raised (Python). | Yes |
| `signed-not-bound` | What was signed does not carry the hash of the compared bytes; the signer's answer did not complete the payment; a payment presented to `check` does not carry the hash; a channel opening or voucher does not belong to the held channel. The payment is not returned. | Yes, or not needed |
| `agreement-not-offered` | The pairing's payment is not itself a public proof of H, and the seller's offer names no agreement URL. | No |
| `agreement-pending` | The agreement URL answered `202` before the gate paid (another agreement payment for this ATR is settling); the agreement payment was sent and not recorded within the paid option's `maxTimeoutSeconds` plus 180 seconds; or the caller's `signal` ended the exchange after the agreement payment was sent. | For the agreement only |
| `agreement-failed` | The agreement URL could not be reached; answered a status other than `200`, `202` or `402`; answered `402` without a readable `PAYMENT-REQUIRED`; answered `200` or `402` with a `Content-Encoding` other than `identity`; or answered `200` with something other than a receipt for this H, a receipt over 64 KiB included. The approved agreement payment names another agreement URL. The caller's `signal` ended the exchange before the agreement payment was sent. | For the agreement only, when it failed after payment |

The MCP server adds three codes of its own:

| Code | Returned when | Signer called? |
| --- | --- | --- |
| `hold-unverified` | A channel hold passed to `atr_channel_record_charge` or `atr_channel_within` is not one this server process returned, unchanged: its `mac` does not verify. See [channel holds](./mcp.md#channel-holds). | No |
| `opening-unverified` | A channel opening passed to `atr_channel_open` is not one this server process returned, unchanged: the `mac` beside it does not verify. See [channel holds](./mcp.md#channel-holds). | No |
| `chosen-unverified` | The `chosen` passed to `atr_agree` is not one `atr_confirm` returned in this server process, unchanged: its `mac` does not verify. Nothing is fetched. See [`atr_agree`](./mcp.md#atr_agree). | No |

## `moved`

Some signers move the payment themselves: a Lightning node pays the invoice, a signer broadcasts a transaction it was
asked to broadcast, a session opening is sent on chain. If the gate declines after that, the decline carries `moved`:

- `signed`: the payment as signed, in the protocol's own form (or the signer's answers, in order, for a payment signed
  in steps);
- `bytes` (`atr_bytes` in Python): the ATR's bytes;
- `h`: their SHA-256.

The agreement exchange does the same: once the agreement payment has been sent, every decline carries it as `moved`.

Keep `moved`. It is a payment that has left, or may have left, your wallet. Present it again to the seller rather than
signing a new one.

## Detail codes the gate writes

Most refusal codes in `detail` come from the binding in `@integraledger/lcp`, which documents them. These are the ones
the gate itself writes:

| Detail | Meaning |
| --- | --- |
| `<protocol>/no-payable-option` | No option or challenge serves the signer's account. |
| `<protocol>/input-missing` | A value the build reads from `inputs` is absent or of the wrong form. See [rails](../guides/rails.md). |
| `<protocol>/input-malformed` | `transact`'s options, or a session's inputs, are malformed. |
| `<protocol>/choice-malformed` | The `chosen` handed to `finish` does not carry the choice the pairing built from. |
| `<protocol>/signature-malformed`, `mpp/credential-malformed` | The signer's answer is not of the form the request kind takes. See [signers](../guides/signers.md). |
| `<protocol>/build-failed` | The binding's build threw. |
| `<protocol>/link-not-https`, `<protocol>/legal-context-malformed` | The link or agreement URL is not an `https` URL. |
| `x402/deposit-above-maximum` | A batch-settlement deposit is above the buyer's `maxDeposit` input. |
| `x402/payment-identifier-unwritable` | The seller advertises x402's `payment-identifier` extension, and its `info` is not an object or already holds an `id`. |
| `x402/payload-malformed` | A rail's completed payment is not of the form the pairing's payload takes. |
| `mpp/splits-malformed` | A Tempo charge's splits are not one to the maximum of recipients, each with an address and a non-zero amount. |
| `mpp/request-malformed` | An MPP challenge's `request` is not base64url JSON with a decimal amount. |
| `mpp/within-action-not-built` | The in-session action (a top-up, for example) is not one the binding builds. |
| `hedera/tx-mismatch` | A pushed Hedera transaction id does not name the body's payer and valid start. |
| `ln/preimage-malformed` | The Lightning node's answer is not a 64-digit hex preimage. |
| `ln/request-hash-mismatch` | x402's request hash, recomputed from your `request` input, is not the option's `extra.requestHash` or the invoice's description hash. |
| `ln/request-binding-malformed`, `ln/request-resource-mismatch`, `ln/request-server-mismatch`, `ln/request-profile-mismatch`, `ln/invoice-malformed` | Your `request` input, or the option's invoice, does not match the Lightning option it is for. |
| `card/document-missing` | A card pairing's build found no seller document. |
