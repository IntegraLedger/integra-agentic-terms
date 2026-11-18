---
title: Pay with the gate
description: Compare and check, then build, show and sign, then finish. One call with transact, or two with confirm and finish when your signer lives elsewhere.
---

This guide is for a developer wiring the gate into an agent that pays. At the end you can pay through `transact` in one
call, or through `confirm` and `finish` with a signer that lives elsewhere, and you know what each option, ceiling and
floor does.

Every payment through the gate follows the same order: compare the served bytes with H, parse them and, on x402 and
MPP, hold the option and your request to what the ATR commits to, build the payment with the hash the gate computed,
show your approver what the signature grants and hold it to its ceiling, have your signer sign exactly that request, and
finish only when the pairing reads H from the completed payment, or the proof is the agreement payment. You can run the
whole order with one call, `transact`, or split it with `confirm` and `finish`. The checks, their order and the decline
each answers are the profile
[`buyer-gate.md`](https://github.com/IntegraLedger/integra-agentic-terms/blob/main/agentic-terms/profiles/buyer-gate.md)'s.

The runnable samples on this page and in the other guides sign with [viem](https://viem.sh) (`npm install viem`) and
the published Anvil development key.

## What you pass

Every gate function takes the same few values:

| Value | What it is |
| --- | --- |
| `doc` | The seller's payment request, as the protocol delivers it: an x402 `PaymentRequired` object, a list of MPP challenges, or the pairing's document. Pass it as parsed JSON; the gate never needs the raw response. |
| `binding` | The pairing's binding, from `@integraledger/lcp` (TypeScript) or a constant of `integraledger_terms` (Python). The [pairings reference](../reference/pairings.md) names each one. |
| `signer` | Your wallet: an `account` in CAIP-10 form (`eip155:84532:0xf39F…2266`) and a `sign(request)` method. See [signers](./signers.md). |
| `fetch` | Your HTTP client. TypeScript: WHATWG `fetch`, or anything with its call shape. Python: an `httpx.AsyncClient`. Your network policy (proxy, egress rules, timeouts of your own) lives here. |
| `resourceRequest` | The request the seller's offer answered, the one you are about to pay: over HTTP `{ method, target, body, headers? }`, the method token and the origin-form request-target as sent (the path and query, starting with `/`, never the full URL), the body's bytes (a `Uint8Array`; in Python `bytes`) and, where it has header fields, each field's value or lines in order; over MCP the tool call `{ name, arguments? }`. Required by `transact` and `confirm`. Where the ATR's binding slot holds a request commitment (an x402 `request` member), the gate computes that commitment of this request and declines `request-mismatch` for another. |
| `approver` | Your approval callback, required by `transact`. See [The approver](#the-approver). |
| `inputs` | The buyer's own values a pairing's build needs beside the offer, such as a recent blockhash or an account sequence, and the floor a rail's payment service serves. Most pairings need none. See [rails](./rails.md). |
| `ceilings` | The raised ceilings, optional: a pairing id mapped to a positive whole number of seconds, or to `"no-end"`. See [Ceilings and floors](#ceilings-and-floors). |

The `account` names the network the buyer pays on. The gate pays the first option (an x402 `accepts` entry, an MPP
challenge) in document order that the pairing serves on the account's network. To pay a different option, remove the
others from the document before you pass it.

## One call: `transact`

`transact` compares and checks, pays the agreement where the pairing needs one, asks your approver about each signing,
calls your signer, and finishes:

```ts no-run
import { transact } from "@integraledger/terms";
import { exactEip3009 } from "@integraledger/lcp/x402";
import type { ResourceRequest, Signer, ToSign } from "@integraledger/terms";

declare const offer: unknown; // the seller's PAYMENT-REQUIRED document, parsed
declare const signer: Signer;
declare const request: ResourceRequest; // the request the 402 answered
declare function yourPolicy(toSign: ToSign): Promise<boolean>; // your agent's decision, or its principal's

const result = await transact(offer, exactEip3009, signer, globalThis.fetch, {
  approver: (toSign) => yourPolicy(toSign),
  resourceRequest: request,
});
if ("decline" in result) {
  console.error(result.decline.code, result.decline.detail);
} else if ("approve" in result) {
  // The pairing needs an agreement payment first, and nothing was signed. result.approve.option is its amount, asset,
  // payTo and network. Once your agent approves it, call transact again with approved: result.approve.
} else if ("charge" in result) {
  // The seller offered the agreement alone, and it is paid (or, on MPP, result.agreementChallenges are your own MPP
  // client's to pay). Repeat your request with the Legal-Context value result.legalContext, and call transact again
  // with the second response, which offers result.charge.
} else if ("agreementChallenges" in result) {
  // The agreement URL offers only MPP agreement challenges, and nothing was signed: your own MPP client pays one there,
  // and a later call finds the agreement recorded and pays the charge.
} else {
  // result.signed: the payment to send (null when the pairing has nothing for the buyer to sign)
  // result.bytes:  the ATR's exact bytes, your copy of the record
  // result.h:      their SHA-256
  // result.agreement: the agreement's receipt, where the pairing needs one
  // result.landed: a landed receipt to keep beside the payment, for the few pairings that return one
}
```

The signer is called only after every check passed and your approver answered `true`: for this pairing's requests,
and, without `agreementSigner`, first for the approved agreement payment. On any decline before it, the signer is never
called.

`transact`'s options are its last argument, required:

| Member | What it is |
| --- | --- |
| `approver` | Required. The approval callback. |
| `resourceRequest` | Required. The request the seller's offer answered. |
| `inputs` | The buyer's own values the build needs, and the floor a rail's service serves. |
| `ceilings` | The raised ceilings. |
| `legalContext` | The first response's `Legal-Context` value as received (over MCP, its `_meta["com.integraledger.lcp/legal-context"]`), where it carried one. See [agreement payments](./agreement-payments.md#paid-after-its-agreement). |
| `agreementSigner` | The signer that pays the agreement, where it differs from the one that pays the resource (for example a card payment whose agreement is paid from an EVM wallet). Without it, `signer` pays both. |
| `approved` | The agreement payment your agent approved, exactly as a previous call returned it in `approve`. See [agreement payments](./agreement-payments.md). |
| `signal` | An `AbortSignal` that ends the agreement exchange. |
| `chosen` | The payment `confirm` chose, unchanged: `transact` builds that exact request, the one your approver saw from `confirm`, rather than choosing anew with its clock and a new reference. |

Any other member, or a member of the wrong kind, is declined with `no-payable-option` and the detail
`<protocol>/input-malformed`, before any fetch, and so is a `signer` or `agreementSigner` whose `account` is not a
string.

## The approver

`transact` calls your approver once for each signing, after every check on it has passed and before the signer is
called for it, with one argument, `ToSign`:

| Member | What it holds |
| --- | --- |
| `act` | `"payment"`, the payment for the resource, or `"agreement"`: the agreement payment, and every payment through a pairing whose agreement is never a charge (its data in the protocol package's registry holds `agreement.only`, as `spend-permissions/eip155`'s and `x402/exact/stellar/precondition`'s do). |
| `pairing` | The id of the pairing whose build made the request. |
| `request` | The request the signer will be handed, as it is handed. |
| `summary` | Every authority the signature grants, below. |
| `step` | `{ index, count }`: which signing of the payment, from 0, of the number the pairing's payment takes, at most two. |

It answers `true` (in Python `True`), or a promise of it (an awaitable), to approve. Any other answer, `false`, `"yes"`
and `1` among them, a throw or a rejection approves nothing: the gate declines `not-approved` and never calls the signer
for that signing. What the approver does to the values it is handed changes nothing the signer is handed.

The summary is computed from the request handed to the signer, never from the seller's option or the build's inputs,
so a request that grants more than the offer is shown granting it. Every integer is a decimal string, every amount in
the asset's base units:

| Member | What it holds |
| --- | --- |
| `amount` | What the payee is paid, where the payment pays a fixed amount. |
| `maximum` | The most the payee may charge, where the payee names the charge (`upto`). |
| `payees` | Every payee, `{ account, amount }`: its account as the form names it, and its part. On an authorization and capture, the fee's payee too (the fee receiver, or the operator where none is named), with the most it may take: the maximum times the fee's basis points over 10,000, rounded down. Always present. |
| `period`, `limitPerPeriod`, `end` | A recurring grant: the period in seconds, the most per period, and when it ends. |
| `operator`, `authorizationExpiry`, `refundExpiry` | An authorization and capture: its operator, and when the authorization and the refund expire. |
| `deposit`, `closableBy` | A session's or a channel's deposit, and the accounts that may close it. |
| `grant` | What a delegation or a checkout grants, as JSON; for a session's opening, its escrow and the key that signs its vouchers; for a Circle Gateway burn intent, the network the payee is paid on and the most Gateway may take as its fee, paid beside the amount. |
| `asset` | The asset, as the form names it. Always present. |
| `network` | The CAIP-2 network, or `null` where the payment moves on no ledger (a card network, a fiat checkout). Where the request names none, the signer's account's. Always present. |
| `validity` | `{ notBefore, notAfter, unit }`: from and until when the signed payment is payable, each `null` where the form signs none, in `"seconds"` (Unix seconds) or the chain's unit (`round`, `slot`, `block`, `ledger`, `epoch`). Always present. |
| `atr` | The ATR's bytes the gate hashed, parsed and compared. Always present. |

A request of a kind the gate has no summary for is declined `summary-missing`, and nothing is signed unshown. The
profile's rule 13 names, for every request kind, the signed field that fills each member. A pairing whose build hands
the signer no request, one with nothing for the buyer to sign or whose build is itself the payment, has no summary,
since nothing is signed; its agreement payment is shown by its own pairing's row.

Where the request commits to its payer only by a hash, as a session's channel id hashes the payer's address, the gate
hands the summary your signer's account. A later step that names only its channel, such as the voucher after a
session's opening, is shown with the payees, asset, network and validity of that opening, once the gate has recomputed
the channel the opening opens for your account; a voucher of another channel has no summary.

## Ceilings and floors

The gate declines a payment that would stay payable longer than its pairing's **ceiling**, `past-ceiling`, before it
is signed. `transact`, `confirm` and `finish` hold every request they hand the signer to it; `agree` called on its own
and `within` hold none (see [the security model](../security-model.md)). How long it stays payable is read from the summary's `validity`: a deadline in seconds less the gate's
clock; a deadline signed as a height, a slot, a round, a ledger or an epoch less the start the request signs, or the
height the caller gave the build, times the chain's pace (the profile's rule 8 states each chain's pace with its
source); and, where the payer signs no deadline and the rail itself bounds the payment, that bound.

- A pairing's ceiling is 600 seconds. `ceilings` raises it: `{ "x402/exact/sui": 86400 }`. The larger of the two
  holds. An id the call does not pay is not read.
- A form that signs no end (a delegation, a card checkout, a transaction with no validity) is past every ceiling and is
  declined `no-end`, unless `ceilings` maps its pairing to `"no-end"`.
- On the XRP Ledger the request signs its deadline, `LastLedgerSequence`, and no start: give `ledgerIndex` in
  `inputs`, the index of the validated ledger you read. On Cardano and Sui give `currentSlot` and `currentEpoch`. A
  signing without it is declined `no-payable-option` with `xrpl/input-missing`, `cardano/input-missing` (or
  `cip34/input-missing`) or `sui/input-missing`.
- Where the wallet builds the transaction and picks its expiry itself (`x402/exact/aptos`, `x402/exact/cardano`,
  `x402/exact/cardano/lock`, `x402/exact/sui`, `x402/exact/polkadot/lcp-assets-remark`), the gate adds the latest
  deadline the wallet may sign to the request (`maxExpirationTimestampSecs`, `maxTtl`, `maxEpoch`, `maxEraPeriod`),
  keeps it in `chosen` as `deadline`, and reads the deadline the signed transaction signs before returning it: a payment
  signed past it is declined `past-ceiling`, and one that signs none `no-end`, and either is discarded, never returned,
  logged or sent. The cost: the wallet signs before the deadline it chose is checked, so a wallet that signs past the
  latest deadline it was handed has that payment discarded, and nothing is paid. A Sui epoch is a day, so a Sui payment
  is paid only once you raise its ceiling to a day.

A deadline signed in a chain's own unit is counted at that chain's pace, which the profile states with its source:

| Chain | Unit | Seconds per unit |
| --- | --- | --- |
| Algorand | round | 2.82 |
| Cardano | slot | 1 |
| NEAR | block | 0.6 |
| Polkadot | block | 6 |
| Solana | block | 0.3 |
| Stellar | ledger | 5 |
| Sui | epoch | 86,400 |
| XRP Ledger | ledger | 5 |
| An EVM network, for a Circle Gateway burn intent's `maxBlockHeight` | block | 604,800 / `withdrawalDelay` |

On a rail whose payment service refuses a shorter validity, you read the **floor** that service serves and give it in
`inputs`, under the name the build takes; the gate reads no service of its own. Without it the gate declines
`floor-missing`, whose detail is the input's name, before it reads the offer. That rail's ceiling is the floor plus the
service's margin, never the 600 seconds. `FLOOR_INPUTS` (both languages) maps each such pairing to its input names:

| Pairing | Inputs | Ceiling |
| --- | --- | --- |
| `x402/exact/eip155/gateway-batched` | `minValiditySeconds`: the `minValiditySeconds` Circle Gateway's `/supported` serves for the network, a positive whole number | `minValiditySeconds` plus 100 seconds |
| `mpp/charge/usdc/gateway` | `sourceNetwork`, the CAIP-2 network the burn intent spends from; `burnIntentExpirationHeight`, the decimal string Circle Gateway's `GET /v1/info` serves for it; `withdrawalDelay`, that network's Gateway Wallet's `withdrawalDelay()` in blocks, a decimal string | the burn intent's `maxBlockHeight` at `burnIntentExpirationHeight` plus 100 seconds counted in that network's blocks |

On `x402/exact/eip155/gateway-batched` the build signs `validBefore` at the clock plus the larger of the option's
`maxTimeoutSeconds` and `minValiditySeconds` plus 100, so a stock offer whose `maxTimeoutSeconds` is no larger is within
the ceiling, and a larger one is declined `past-ceiling` unless `ceilings` raises it.

On `mpp/charge/usdc/gateway` the build signs `maxBlockHeight` itself, as `burnIntentExpirationHeight` plus
`withdrawalDelay` × 100 / 604,800 blocks, rounded up, so your Gateway client does not choose it, and the gate holds the
burn intent to that ceiling in exact whole blocks: its `maxBlockHeight` less `burnIntentExpirationHeight` is at most
that many, or, where `ceilings` raises the pairing to R seconds, R × `withdrawalDelay` / 604,800 blocks, rounded down,
where that is more. A `withdrawalDelay` of `"0"` admits 0 blocks, raised or not. The summary's network is your signer's
account's, which must be `sourceNetwork`: a burn intent shown on another network is declined `past-ceiling`.

## Two calls: `confirm`, then `finish`

When the key lives somewhere else (a hardware wallet, a signing service, another process), split the order:

1. `confirm(doc, binding, account, fetch, { resourceRequest, inputs?, ceilings? })` reads the offer, fetches,
   compares, parses and holds the option and the request to the ATR, builds the signing request with H, computes its
   summary and holds it to the ceiling (checks 1 to 11 of the profile), and returns the request with its `summary`,
   together with `chosen` and the ATR's bytes. It calls no approver.
2. You show the summary, and your signer signs `request`, exactly as given. Or pass `chosen` back to `transact`, which
   then builds that exact request and asks your approver about it.
3. `finish(bytes, chosen, signature, binding, { ceilings? })` rebuilds the same payment from `chosen` and the bytes,
   joins the signature, and returns the payment only when the pairing reads the hash of those bytes from the completed
   payment, or, where the proof is the agreement payment, without that reading.

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

// 1. Compare, check, and build the request with H, with its summary. confirm calls no approver: show it yourself.
const confirmed = await confirm(offer, exactEip3009, "eip155:84532:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", fetch, {
  resourceRequest: { method: "GET", target: "/v1/quote", body: new Uint8Array() },
});
if ("decline" in confirmed) throw new Error(confirmed.decline.code);
if (confirmed.request === null || confirmed.request.kind !== "eip712") throw new Error("expected an EIP-712 request");
const { amount, payees, validity } = confirmed.summary!;
console.log("shown:", amount, "to", payees[0]?.account, "until", validity.notAfter === null ? "no end" : "a deadline");

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
shown: 10000 to 0x209693Bc6afc0C5328bA36FaF03C514EF312287C until a deadline
nonce is H: true
```

### A request of `null`

Some pairings give the buyer nothing to sign: the seller's own flow completes the payment (an MPP `card` or `stripe`
charge, an ACP checkout without delegation, a UCP checkout without a mandate). For these, `confirm` returns `request:
null` after the comparison, and `transact` returns `signed: null`. The comparison was the whole of your step; complete
the payment through the protocol's own flow.

For a pairing whose build is itself the payment (`x402/batch-settlement/cloudflare`), `confirm` also returns `request:
null`: call `finish` with a `null` signature, and it completes the payment with no signer call, as `transact` does.

### Payments signed in steps

A few pairings take two signatures: a channel funding and then its first voucher (`mpp/session/evm` and others). For
these, `finish` returns `{ next, summary, h }` instead of the payment, only once the later step has a summary and is
within the pairing's ceiling. The voucher is shown for the account `confirm` chose, with its opening's payee, asset and
network. Show `summary`, have your signer sign `next`, then call `finish` again with every answer so
far, in order, as a list:

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

`transact` does this for you, asking your approver about each step with its `step.index` and `step.count`, the count
the pairing's piece declares for its payment. It never calls the signer more than twice for one payment.

## Sending the payment

The gate returns the payment in the protocol's own form. You send it as that protocol defines:

| Protocol | How the payment travels |
| --- | --- |
| x402 over HTTP | Base64 of the UTF-8 bytes of the payment's JSON, in the `PAYMENT-SIGNATURE` request header, on a retry of the original request. |
| x402 over MCP | The payment object in the tool call's `_meta["x402/payment"]`. |
| MPP | The credential in the field the challenge selects, `Authorization` by default, after the `Payment` scheme name. |
| Card, AP2, UCP, ACP, ACK | The pairing's own message: the TAP field, the mandate, the checkout completion, as its protocol defines. |

Where `transact` or `finish` also returned `landed`, keep it beside the payment. `check` reads the payment with it. The
caller passes as `landed` only the receipt its own reader read for the payment, as `finish` or `transact` returned it,
never a value another party sent.

## After you send it

- **The seller answers that the payment is still settling.** Send the same payment again. Never sign a new one: the
  payment already carries H, and a second signature would be a second payment.
- **A decline carries `moved`.** Your signer moved the payment itself (a Lightning invoice paid, a transaction
  broadcast) before the gate declined. `moved.signed` is that payment, with the bytes and their hash. Keep it and
  present it again rather than signing a new one. See [keeping the record](./keeping-the-record.md).
- **The agreement payment may settle yet.** Once the agreement payment is sent, every decline carries it as `moved`.
  The code is `agreement-pending` where it may settle yet: a `202`, a `5xx` or a timeout until the exchange's bound, or
  your `signal`. It is `agreement-failed` where the agreement URL answered with a redirect, another status, or a `200`
  that is not a receipt for H. Either way, keep `moved`, and call again without `approved` to learn whether it is
  recorded: the gate asks the agreement URL unpaid and goes on once it answers `200` with the receipt, or declines
  `agreement-pending` again while it answers `202`, signing nothing. Never call again with `approved` for the same
  agreement: every call with `approved` signs and sends a new agreement payment.
- **Any other decline.** Nothing was sent, and nothing should be. The [declines reference](../reference/declines.md)
  says what each code means. Whether to deal with the seller another way is your principal's decision.

## In a Cloudflare Worker

Pass the Worker's own `fetch`. The gate asks with `redirect: "manual"`: the Workers runtime refuses
`redirect: "error"` with a `TypeError`, and under `"manual"` it answers a redirect with the `3xx` itself.

Measured on Cloudflare's runtime (`wrangler dev --remote`, wrangler 4.141.0, compatibility date 2026-09-01), with this
package, `@integraledger/lcp` and every optional peer dependency of lcp installed:

- With and without the `nodejs_compat` flag, `confirm` fetched a link that answered `200`, hashed the bytes and
  compared them with the advertised hash.
- A link that answered `301` or `302` was declined `atr-unfetchable`, and the fetch did not throw.
- Without the optional peer dependencies, wrangler's build stopped at `Could not resolve` for each one the bundle
  imports.

## In Python

The Python gate has the same functions, with Python names and dataclass results:

| TypeScript | Python |
| --- | --- |
| `transact(doc, binding, signer, fetch, { approver, resourceRequest, inputs, ceilings, legalContext, agreementSigner, approved, signal, chosen })` | `await transact(doc, binding, signer, client, approver=…, resource_request=…, inputs=…, ceilings=…, legal_context=…, agreement_signer=…, approved=…, signal=…, chosen=…)` |
| `confirm(doc, binding, account, fetch, { resourceRequest, inputs, ceilings })` | `await confirm(doc, binding, account, client, resource_request=…, inputs=…, ceilings=…)` |
| `finish(bytes, chosen, signature, binding, { ceilings })` | `finish(atr_bytes, chosen, signature, binding, ceilings=…)` |
| `check(bytes, presented, binding, landed?, act?)` | `check(atr_bytes, presented, binding, landed=None, act="payment")` |
| `ToSign`, `Summary`, `ToReturn`, `AgreementChallenges` | `ToSign`, `Summary`, `ToReturn`, `AgreementChallenges`: frozen dataclasses, their members in snake case |
| `{ next, summary, h }` | `Next(next, summary, h)` |
| `FLOOR_INPUTS` | `FLOOR_INPUTS` |
| `{ decline: { code, detail } }` | `Declined(code, detail, moved)` |

See the [Python guide](./python.md).
