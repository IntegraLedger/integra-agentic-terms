---
title: Upgrading
description: What a 0.x version means for these packages, which protocol package each release takes, and every call to change from 0.4.x to 0.5.0, in TypeScript, over MCP and in Python.
---

This page is for a developer whose code runs on an earlier release of `@integraledger/terms`,
`@integraledger/terms-mcp` or `integraledger-terms`. At the end you know which versions to pin, and every call to
change to run on 0.5.0. The
[changelog](https://github.com/IntegraLedger/integra-agentic-terms/blob/main/agentic-terms/CHANGELOG.md) lists every
change of the release.

## Versions

- The three packages are released together, under one version number. This documentation is 0.5.0's.
- At 0.x, a minor release may change the public API, as 0.5.0 changed 0.4.x's. Pin the exact version, as every install
  line here does, and read this page before you move to a new minor release.
- `@integraledger/terms` and `@integraledger/terms-mcp` 0.5.x take `@integraledger/lcp` `~0.6.2`, 0.6.2 or a later 0.6.x release, as
  a peer dependency (0.5.0 and 0.5.1: `~0.6.0`); 0.4.x took `~0.5.1`. Install it beside them, so your application and the gate share one copy, and
  import the bindings you pass in from it. The Python package carries its own bindings and needs no protocol package.
- Node.js `>=24.22.1` for both TypeScript packages (0.4.x: `>=24`). Python `>=3.11`, as before.
- Security fixes are released for the latest published version of each package only.

```sh
npm install @integraledger/terms@0.5.1 @integraledger/lcp@0.6.1
npx -y @integraledger/terms-mcp@0.5.1
pip install integraledger-terms==0.5.1
```

## From 0.4.x to 0.5.0

0.5.0 adds checks before every signing: the gate parses the ATR, holds the option and the request to it, shows your
approver a summary of each signing, and bounds how long a signed payment stays payable. Every caller changes.

### What now declines

These apply in all three packages, whatever the call:

- **Every signed payment has a ceiling.** Through `transact`, `confirm` and `finish`, a payment that stays payable longer
  than 600 seconds is declined `past-ceiling`, and a form that signs no end (an ERC-7710 delegation, a card checkout, a
  transaction with no validity) `no-end`. Raise a pairing's ceiling with `ceilings`: `{ "x402/batch-settlement/eip155":
  3600 }` admits a deposit payable for an hour, and `{ "x402/exact/eip155/erc7710": "no-end" }` a delegation. See
  [Ceilings and floors](./guides/pay-with-the-gate.md#ceilings-and-floors).
- **Some chains need the start of a deadline.** On the XRP Ledger give `ledgerIndex` in `inputs`, on Cardano
  `currentSlot` and on Sui `currentEpoch`; without it the signing is declined `no-payable-option` with
  `xrpl/input-missing`, `cardano/input-missing` or `sui/input-missing`.
- **Two Gateway rails need their served floor.** `x402/exact/eip155/gateway-batched` and `mpp/charge/usdc/gateway`
  decline `floor-missing` until `inputs` holds the floor inputs `FLOOR_INPUTS` names.
- **The ATR must be one JSON text both languages read alike.** Bytes that are not are declined `atr-malformed`.
- **On x402 and MPP, the option and the request are held to the ATR.** An option the ATR's `x402` `accepts` or `mpp`
  `challenges` does not list is declined `option-not-in-atr`, and a request other than the `x402` slot's request
  commitment `request-mismatch`.
- **A request the gate cannot summarize is not signed.** It is declined `summary-missing`: in 0.5.0, every
  `x402/batch-settlement/solana` opening and every Masumi lock of `x402/exact/cardano/lock`.
- **The agreement payment carries the agreement's own value.** On a pairing whose agreement has its own single-use
  value, such as an EIP-3009 or Permit2 nonce, the agreement payment carries `agreementValue(H)` where 0.4.x put H.
  Check a kept agreement payment with the act `"agreement"` (below), and expect the agreement URL to read it as an
  agreement.
- **The agreement option follows the charge.** Given the charge, the gate pays only an agreement option its pairing's
  `agreementOn` admits: any network, or the charge's own.
- **Nine pairings are gone**, as the protocol package retired them: `mpp/charge/hedera`, `mpp/charge/stellar`,
  `mpp/charge/tempo/memo`, `mpp/charge/tempo/push`, `mpp/session/hedera`, `mpp/session/solana`, `x402/exact/lnbtc`,
  `x402/exact/lnbtc/invoice-named` and `x402/exact/stellar`. Their bindings and Python constants no longer exist.

### TypeScript: `@integraledger/terms`

| Call | 0.4.x | 0.5.0 |
| --- | --- | --- |
| `transact` | `transact(doc, binding, signer, fetch, options?)`, `options` `{ inputs?, agreementSigner?, approved?, signal? }` | `transact(doc, binding, signer, fetch, options)`, `options` required, holding `approver` and `resourceRequest`, and optionally `inputs`, `ceilings`, `legalContext`, `agreementSigner`, `approved`, `signal` and `chosen` |
| `transact`'s result | the payment, `ToApprove` or `Declined` | also `AgreementChallenges` (`agreementChallenges`) and `ToReturn` (`charge`, `legalContext`) |
| `confirm` | `confirm(doc, binding, account, fetch, inputs?)` | `confirm(doc, binding, account, fetch, { resourceRequest, inputs?, ceilings? })`; the result also holds `summary` |
| `finish` | `finish(bytes, chosen, signature, binding)`; a later step `{ next, h }` | `finish(bytes, chosen, signature, binding, { ceilings? })`; a later step `{ next, summary, h }` |
| `check` | `check(bytes, presented, binding, landed?)` | `check(bytes, presented, binding, landed?, act?)`: pass `"agreement"` for an agreement payment |
| `agree` | `options` `{ approved?, inputs?, signal? }`; the result `ToApprove`, `{ receipt }` or `Declined` | `options` also take `chosen`; the result may also be `AgreementChallenges` |
| `Chosen` | `{ pairing, choice, ref, agreement? }` | also `deadline?` |
| `DeclineCode` | 12 codes | also `not-approved`, `atr-malformed`, `option-not-in-atr`, `request-mismatch`, `summary-missing`, `past-ceiling`, `no-end`, `floor-missing` |

A 0.4 call of `transact` with no options, or of `confirm` with `inputs` as its fifth argument, is declined
`no-payable-option` with `<namespace>/input-malformed` before anything is fetched. A `switch` over `DeclineCode` must
handle the eight new codes. `FLOOR_INPUTS`, `viJson` and the types `Approver`, `Ceilings`, `ConfirmOptions`,
`FinishOptions`, `Payee`, `ResourceRequest`, `SigningStep`, `Summary`, `AgreementChallenges`, `ToReturn`, `ToSign` and
`Validity` are new exports.

The calls as 0.5.0 takes them:

```ts no-run
import { check, confirm, finish, transact, type Fetch, type Signer, type ToSign } from "@integraledger/terms";
import { exactEip3009 } from "@integraledger/lcp/x402";

declare const offer: unknown; // the seller's PAYMENT-REQUIRED document, parsed
declare const signer: Signer;
declare const fetch: Fetch;
declare function yourPolicy(toSign: ToSign): Promise<boolean>; // your agent's decision, or its principal's

// The request the seller's 402 answered, exactly as sent: the target is origin-form, never the full URL.
const resourceRequest = { method: "GET", target: "/v1/quote", body: new Uint8Array() };

// transact: approver and resourceRequest are required; ceilings raises a pairing's 600-second ceiling.
const result = await transact(offer, exactEip3009, signer, fetch, {
  approver: yourPolicy,
  resourceRequest,
  ceilings: { "x402/exact/eip155/eip3009": 900 },
});
if ("decline" in result) console.error(result.decline.code, result.decline.detail);
else if ("approve" in result) console.log("approve the agreement payment, then call again with approved");
else if ("charge" in result) console.log("repeat the request with Legal-Context:", result.legalContext);
else if ("agreementChallenges" in result) console.log("your own MPP client pays the agreement");
else console.log("send", result.signed);

// confirm: inputs moves into the options, beside resourceRequest; the request comes with its summary to show.
const confirmed = await confirm(offer, exactEip3009, signer.account, fetch, { resourceRequest, inputs: {} });
if (!("decline" in confirmed) && confirmed.request !== null) {
  console.log("show before signing:", confirmed.summary);
  const signature = await signer.sign(confirmed.request);
  const done = await finish(confirmed.bytes, confirmed.chosen, signature, exactEip3009, { ceilings: {} });
  if (!("decline" in done) && "next" in done) console.log("show the next step:", done.summary);

  // check: an agreement payment is checked as the act it was paid as.
  if (!("decline" in done) && !("next" in done)) {
    console.log(await check(confirmed.bytes, done.signed, exactEip3009, null, "payment"));
  }
}
```

### MCP: `@integraledger/terms-mcp`

| Tool or option | 0.4.x | 0.5.0 |
| --- | --- | --- |
| `atr_confirm` | `{ pairing, document, account, inputs?, receipt? }` | also `resourceRequest`, required; the result holds `summary` beside `request` |
| `atr_transact` | `{ pairing, document, inputs?, approved? }`, `approved` the agreement payment `approve` returned | `{ pairing, document, resourceRequest, inputs?, approved?, legalContext? }`, `approved` `{ agreement?, signings }`, exactly as the last `approve` returned it |
| `atr_transact`'s first call | signs, or returns the agreement payment to approve | signs nothing: returns `approve`, `{ agreement?, signings }`, for every signing to approve; call again with it as `approved` |
| `atr_transact`'s result | the payment or `approve` | also `legalContext` and `charge` after an agreement offered alone, or `agreementChallenges` |
| `atr_finish` | a later step `{ atrHash, next }` | `{ atrHash, next, summary }` |
| `atr_check` | `{ pairing, atr, presented, landed? }` | also `act`, `"payment"` or `"agreement"` |
| `createBuyerServer` | `{ fetch, signer?, agreementSigner? }` | also `ceilings` and `floors`, the host's, never a tool input |

`resourceRequest` is the request the seller's 402 answered, as JSON: over HTTP `{ method, target, body, headers? }`,
`body` the body's bytes as padded standard base64 (`""` for none), or over MCP `{ name, arguments? }`. A 0.4 call of
`atr_confirm` or `atr_transact` fails the tool's input schema: `isError: true` with one text block,
`Input validation error: …`, and nothing is fetched or signed. The binary takes neither `ceilings` nor `floors`, so it
declines a payment past 600 seconds, one that signs no end, and `x402/exact/eip155/gateway-batched` (`floor-missing`);
in 0.5.0 it passes `mpp/charge/usdc/gateway`'s floor inputs through from a tool's `inputs`. A host that calls
`createBuyerServer` installs `@integraledger/lcp` `~0.6.0` beside it, on Node.js `>=24.22.1`. The `pairing` argument no
longer accepts the nine retired pairings. See the [MCP guide](./guides/mcp.md).

### Python: `integraledger-terms`

| Call | 0.4.x | 0.5.0 |
| --- | --- | --- |
| `transact` | `await transact(doc, binding, signer, client, *, inputs=None, agreement_signer=None, approved=None, signal=None)` | `await transact(doc, binding, signer, client, *, approver, resource_request, inputs=None, ceilings=None, legal_context=None, agreement_signer=None, approved=None, signal=None, chosen=None)` |
| `transact`'s result | `Transacted`, `ToApprove` or `Declined` | also `AgreementChallenges` and `ToReturn` |
| `confirm` | `await confirm(doc, binding, account, client, inputs=None)` | `await confirm(doc, binding, account, client, *, resource_request, inputs=None, ceilings=None)`; `Confirmed` also holds `summary` |
| `finish` | `finish(atr_bytes, chosen, signature, binding)`; a later step `Next(next, h)` | `finish(atr_bytes, chosen, signature, binding, *, ceilings=None)`; a later step `Next(next, summary, h)` |
| `check` | `check(atr_bytes, presented, binding, landed=None)` | `check(atr_bytes, presented, binding, landed=None, act="payment")` |
| `agree` | `await agree(atr_bytes, url, signer, client, *, approved=None, inputs=None, signal=None)` | also `chosen=None`; the result may also be `AgreementChallenges` |
| `Chosen` | `pairing`, `choice`, `ref`, `agreement` | also `act` and `deadline` |
| `DeclineCode` | 12 codes | the eight new codes above |

A 0.4 call raises `TypeError`: `confirm`'s `inputs` is keyword-only, and `transact` and `confirm` require
`resource_request=`, `transact` `approver=` too. `FLOOR_INPUTS`, `vi_json` and the types `Approver`, `Ceilings`,
`HttpRequest`, `ToolCall`, `ResourceRequest`, `Payee`, `SigningStep`, `Summary`, `Validity`, `ToSign`, `ToReturn` and
`AgreementChallenges` are new exports. The nine retired pairings' constants, such as `MPP_CHARGE_HEDERA` and
`X402_EXACT_STELLAR`, are gone.

The calls as 0.5.0 takes them:

```python no-run
from integraledger_terms import X402_EXACT_EIP155_EIP3009, Declined, Next, ToSign, check, confirm, finish, transact


def approver(to_sign: ToSign) -> bool:
    """Your agent's decision, or its principal's, on what the signature grants."""
    return to_sign.summary.amount == "10000"


async def pay(offer, signer, client):
    # The request the seller's 402 answered, exactly as sent: the target is origin-form, never the full URL.
    request = {"method": "GET", "target": "/v1/quote", "body": b""}
    result = await transact(
        offer,
        X402_EXACT_EIP155_EIP3009,
        signer,
        client,
        approver=approver,
        resource_request=request,
        ceilings={"x402/exact/eip155/eip3009": 900},
    )
    if isinstance(result, Declined):
        return result.code

    confirmed = await confirm(offer, X402_EXACT_EIP155_EIP3009, signer.account, client, resource_request=request, inputs={})
    if isinstance(confirmed, Declined) or confirmed.request is None:
        return None
    signature = await signer.sign(confirmed.request)
    done = finish(confirmed.atr_bytes, confirmed.chosen, signature, X402_EXACT_EIP155_EIP3009, ceilings={})
    if isinstance(done, Declined):
        return done.code
    if isinstance(done, Next):
        return done.summary  # show it, then sign done.next
    return check(confirmed.atr_bytes, done.signed, X402_EXACT_EIP155_EIP3009, None, "payment")
```

See the [Python guide](./guides/python.md).
