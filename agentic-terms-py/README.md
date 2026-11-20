# integraledger-terms

The buyer gate for agents that pay, in Python: before your wallet signs anything, it confirms that the record a seller
serves hashes to the value the payment will carry, and builds the payment with that hash.

```sh
pip install integraledger-terms==0.5.3
```

## What it is

A seller that follows the Legal Context Protocol publishes the agreement's record, an **Agentic Transaction Record
(ATR)**, at an `https` link, and advertises its hash beside the payment request. Where the payment your agent approves
carries that hash, that approval is the buyer's acceptance of that exact record; where it does not, the pairing's
statement of what it proves says so.

That only holds if the hash in the payment is the hash of the record you can read. This package is the check that makes
sure it is. It fetches the record, computes its SHA-256, compares it with what the seller advertised, parses the bytes,
holds the option you pay (and on x402 the request you make) to what the record's binding slot commits to, and only
then builds a request with that hash. Before your signer is called, it shows your approver what the
signature grants (the amount, the payees, the asset, the network and how long the payment stays payable) and declines a
payment that would stay payable past its ceiling. After your signer answers, the pairing reads the hash back from the
completed payment, and the payment is returned only if it is the hash of the bytes you received, or, where the proof is
the agreement payment, without that reading.

It is the Python implementation of the same gate as the TypeScript package
[`@integraledger/terms`](https://www.npmjs.com/package/@integraledger/terms). Both run the same rules and pass the same
shared vectors, pairing for pairing. It holds no keys and judges none of the record's terms: what the record says is for
you and your principal to judge. The one payment it sends is the agreement payment your approver approved, to the
agreement URL.

The checks, their order, the decline each answers and the names of their arguments are fixed, for both languages, by
the profile
[`agentic-terms/profiles/buyer-gate.md`](https://github.com/IntegraLedger/integra-agentic-terms/blob/main/agentic-terms/profiles/buyer-gate.md).

## Key concepts

- **Agentic Transaction Record (ATR):** the agreement's record: the exact bytes the seller serves; `assemble` in
  `@integraledger/lcp` writes them as one JSON object.
- **ATR hash (H):** SHA-256 over the ATR's exact bytes, `0x` and 64 hex digits. It is computed over the bytes as
  received, never over a parsed and re-serialised copy.
- **Legal Context Protocol (LCP):** the pattern this package implements: where the payment the buyer approves carries
  H, that approval is the buyer's acceptance of that exact record; where it does not, the pairing's statement of what
  it proves says so.
- **Pairing:** a payment protocol, scheme and rail combination, such as `x402/exact/eip155/eip3009`.
- **Binding:** how H rides in a pairing's payment: the field of that payment, as the protocol's own specification
  defines the payment, that carries H. This package exports one binding per pairing, named after its id:
  `X402_EXACT_EIP155_EIP3009`.
- **Coverage:** whether a pairing's payment is itself a public proof of H, as the protocol package's registry states it
  for each pairing: `full` where the payer's own signed act on a public ledger binds all of H, and `none` otherwise. A
  pairing at `none` is paid only after an **agreement payment**, a payment at `full` carrying H, to the seller's
  agreement URL.
- **Buyer gate:** this package: the buyer-side check that compares the served bytes with H, and holds what is about to
  be signed to the ATR, before anything is signed.
- **Approver:** your callback, which `transact` asks about each signing, with its **summary**: every authority the
  signature grants, read from the request the signer is handed.
- **Ceiling:** the longest a signed payment may stay payable, 600 seconds unless you raise it for a pairing.
- **Seller:** the party serving the resource.
- **Facilitator:** the x402 role that verifies and settles. The gate never talks to one. It returns the payment to you,
  except the approved agreement payment, which it sends to the agreement URL.
- **Vectors:** the shared test cases that fix the rules byte for byte across languages.

## Install

```sh
pip install integraledger-terms==0.5.3
```

Python `>=3.11`. The package depends on `httpx` (`>=0.28.1,<0.29`) and `cryptography` (`==50.0.2`, an exact pin:
install it in an environment that can take that version), and is fully typed (`py.typed`).

The examples below sign with [eth-account](https://github.com/ethereum/eth-account) (`pip install eth-account`). The
gate itself never signs; any wallet that can sign the request works.

## Quickstart

The seller answered with an x402 `402 Payment Required` whose `PAYMENT-REQUIRED` document advertises H and the link.
This example uses the ATR, the document and the payer key of the shared vectors, and an `httpx.MockTransport` as a
local stand-in for the network, so it runs offline and prints the same values every time.

```python
import asyncio
import uuid
from collections.abc import Mapping
from typing import Any

import httpx
from eth_account import Account
from eth_account.messages import encode_typed_data

from integraledger_terms import X402_EXACT_EIP155_EIP3009, Declined, ToSign, Transacted, transact

# The ATR, exactly as the seller's link serves it. The gate hashes and parses these bytes, never a copy.
ATR = (
    '{"atrVersion":"1","id":"0f8fad5b-d9cb-469f-a165-70867728950e","x402":{"z":1.0,"a":"caf\\u00e9"},'
    '"seller":{"note":"Café — 30 días ✓"}}'
).encode()
H = "0x8b1e122580ae3f6a8c3d36a24294e1260a87bde70f597279b973e39310072938"
LINK = f"https://atr.seller.example/{uuid.uuid4()}"

# The seller's x402 payment request, advertising H and the link.
OFFER = {
    "x402Version": 2,
    "resource": {"url": "https://api.seller.example/v1/quote"},
    "accepts": [
        {
            "scheme": "exact",
            "network": "eip155:84532",
            "amount": "10000",
            "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
            "maxTimeoutSeconds": 60,
            "extra": {"name": "USDC", "version": "2"},
        }
    ],
    "extensions": {"legalContext": {"info": {"type": "sha256", "value": H, "legalContextUrl": LINK}, "schema": {}}},
}

# The published Anvil development key. Never use it for real funds.
KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"


class Wallet:
    account = "eip155:84532:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

    async def sign(self, request: Mapping[str, Any]) -> str:
        if request["kind"] != "eip712":
            raise ValueError(f"this wallet signs EIP-712 only, not {request['kind']}")
        signed = Account.sign_message(encode_typed_data(full_message=dict(request["typedData"])), KEY)
        return "0x" + bytes(signed.signature).hex()


def seller(request: httpx.Request) -> httpx.Response:
    """A stand-in for the network: the link serves the ATR."""
    return httpx.Response(200, content=ATR) if str(request.url) == LINK else httpx.Response(404)


def approver(to_sign: ToSign) -> bool:
    """Asked once for each signing, before the signer is called, with what the signature grants."""
    summary = to_sign.summary
    print("approve     ", to_sign.act, summary.amount, "to", summary.payees[0].account, "on", summary.network)
    return True


async def main() -> None:
    async with httpx.AsyncClient(transport=httpx.MockTransport(seller)) as client:
        result = await transact(
            OFFER,
            X402_EXACT_EIP155_EIP3009,
            Wallet(),
            client,
            approver=approver,
            # The request the seller's 402 answered, as your agent made it.
            resource_request={"method": "GET", "target": "/v1/quote", "body": b""},
        )
    if isinstance(result, Declined):
        raise SystemExit(f"{result.code}: {result.detail}")
    assert isinstance(result, Transacted) and result.signed is not None
    print("H           ", result.h)
    print("signed nonce", result.signed["payload"]["authorization"]["nonce"])
    print("kept bytes  ", len(result.atr_bytes))


asyncio.run(main())
```

```text output
approve      payment 10000 to 0x209693Bc6afc0C5328bA36FaF03C514EF312287C on eip155:84532
H            0x8b1e122580ae3f6a8c3d36a24294e1260a87bde70f597279b973e39310072938
signed nonce 0x8b1e122580ae3f6a8c3d36a24294e1260a87bde70f597279b973e39310072938
kept bytes   138
```

Your approver was shown what the signature grants, read from the request the wallet signed, and the nonce your wallet
signed is the hash of the 138 bytes the link served. Keep `result.atr_bytes` with the payment:
they are your copy of the record. To send the payment over x402's HTTP transport, put base64 of its JSON in the
`PAYMENT-SIGNATURE` header.

If the link had served one byte more, less or different, `transact` would have returned
`Declined(code="hash-mismatch", …)` and never called the approver or the signer. Had the approver answered anything but
`True`, it would have returned `Declined(code="not-approved", …)` and never called the signer.

## How it works

1. **Read.** The pairing's binding reads the seller's document: H, the link, and the payment options.
2. **Compare.** The gate fetches the link once, with your `httpx.AsyncClient`, and hashes the bytes it received. No
   match: a `Declined`, and no signer call.
3. **Parse and hold.** The gate parses the bytes it hashed, by one grammar both languages read alike. Where the ATR's
   binding slot lists the options offered (`accepts` in `x402`, `challenges` in `mpp`, `options` in `acp`, `ap2`,
   `card` and `ucp`, `paymentOptions` in `ack`), the option chosen must be one of them, on card one of the pairing's
   `scheme`; where the `x402` slot holds a commitment to the buyer's request, `resource_request` must be that request.
4. **Build.** The gate builds the payment with the hash it computed, not the string the seller advertised.
5. **Show.** The gate computes the summary of the request your signer would be handed, declines a payment that would
   stay payable past its ceiling, and asks your approver.
6. **Sign and finish.** Only on `True` does it call your signer. It joins the answer and returns the payment only when
   the pairing reads H back from the completed payment as the hash of the compared bytes, or, where the proof is the
   agreement payment, without that reading.

`confirm` and `finish` split this order at the signer: `confirm` makes steps 1 to 5 but the approver, and returns the
request and its summary. Every function returns a value and never raises for a protocol outcome: either its result, or
a `Declined`; nothing the seller serves and nothing your approver answers makes it raise.

## Guides

### Pay with `transact`

`await transact(doc, binding, signer, fetch, *, approver, resource_request, inputs=None, ceilings=None,
legal_context=None, agreement_signer=None, approved=None, signal=None, chosen=None)` runs the whole order: compare, check, pay the
agreement where the pairing needs one, ask your approver, sign, finish. Every signing, the agreement payment's among
them, is asked of your `approver` before the signer is called for it; the gate judges no term and applies no spending
limit, so what to approve is your approver's decision. It returns `Transacted`:

| Field | What it is |
| --- | --- |
| `signed` | The payment to send, in the protocol's own form. `None` when the pairing gives the buyer nothing to sign, except for `x402/batch-settlement/cloudflare`, whose build is itself the payment. |
| `atr_bytes` | The ATR's exact bytes: your copy of the record. |
| `h` | Their SHA-256. |
| `agreement` | The agreement's `AgreementReceipt`, where the pairing needs an agreement payment. |
| `landed` | A landed receipt to keep beside the payment, for the few pairings that return one. |

Where the pairing needs an agreement payment that is not yet recorded, it returns `ToApprove(approve, atr_bytes, h)`
instead, and nothing has been signed: see [Pay the agreement first](#pay-the-agreement-first). Where the pairing is paid
after its agreement and the first response offers the agreement alone, it returns `ToReturn`: see
[Paid after its agreement](#paid-after-its-agreement). Where the agreement URL offers only MPP agreement challenges, it
returns `AgreementChallenges(agreement_challenges, atr_bytes, h)`, and nothing has been signed: see
[Pay the agreement first](#pay-the-agreement-first).

| Keyword | What it is |
| --- | --- |
| `approver` | Required. Your approval callback, `Callable[[ToSign], bool \| Awaitable[bool]]`. It is called once for each signing, after every check and before the signer, and approves only by answering `True`. Anything else, a raise or a failed awaitable declines `not-approved`. |
| `resource_request` | Required. The request the seller's offer answered, exactly as your agent sent it: over HTTP an `HttpRequest`, `{"method", "target", "body", "headers"?}`, `target` the origin-form request-target (the path and query, starting with `/`, such as `/v1/quote?city=Paris`, never the full URL) and `body` as `bytes` (`b""` for none); over MCP a `ToolCall`, `{"name", "arguments"?}`. Where the ATR's `x402` slot holds a request commitment, the gate holds this request to it, and declines a target that is not in origin form `request-mismatch` with `x402/request-target-invalid`. |
| `inputs` | The buyer's own values a build needs, such as a recent blockhash, and the floor a rail's payment service serves. See the [rails guide](https://github.com/IntegraLedger/integra-agentic-terms/blob/main/docs/guides/rails.md). |
| `ceilings` | The raised ceilings: a pairing id mapped to seconds, or to `"no-end"`. See [Ceilings and floors](#ceilings-and-floors). |
| `legal_context` | The first response's `Legal-Context` value, as received, where it carried one. |
| `agreement_signer` | The wallet that pays the agreement, where it is not `signer`. |
| `approved` | The agreement payment your agent approved, exactly as a previous call returned it in `ToApprove.approve`. |
| `signal` | An `asyncio.Event`; setting it ends the agreement exchange. |
| `chosen` | The payment `confirm` chose, `Confirmed.chosen`, unchanged: `transact` then builds that exact request, the one `confirm` returned, rather than choosing anew with its clock and a new reference. |

A value of the wrong kind (an `approver` that is not callable, a `resource_request`, `inputs` or `ceilings` that is not
a mapping, a `legal_context` that is not a `str`, an `agreement_signer` with no `sign` method, an `approved` that is not
an `AgreementPayment`, a `signal` that is not an `asyncio.Event`, a `chosen` that is not `confirm`'s for the pairing, a
signer whose `account` is not a `str`) is declined `no-payable-option` with
`<namespace>/input-malformed` before any fetch. An unknown keyword, or a missing `approver` or `resource_request`, is a
`TypeError`, as in any Python call.

### What the approver is shown

`ToSign` holds the act, the pairing, the request the signer will be handed, its `summary` and the `step`
(`SigningStep(index, count)`, `index` from 0, of the number of signings the pairing's payment takes, at most two). The
act is `"payment"`, the payment for the resource, or `"agreement"`: the agreement payment, and every payment through a
pairing whose agreement is never a charge (its data in the protocol package's registry holds `agreement.only`, as
`spend-permissions/eip155`'s and `x402/exact/stellar/precondition`'s do). The `Summary` is computed
from the request handed to the signer, never from the seller's option, so a request that grants more than the offer is
shown granting it. Its fields are those of the TypeScript `Summary` in snake case: `amount` or `maximum`, `payees`
(each a `Payee(account, amount)`), `asset`, `network` (`None` where the payment moves on no ledger), `validity`
(`Validity(not_before, not_after, unit)`), `period`, `limit_per_period`, `end`, `operator`, `authorization_expiry`,
`refund_expiry`, `deposit`, `closable_by`, `grant` and `atr`, each `None` where the form has nothing it names. On an
authorization and capture, `payees` holds the fee's payee too, with the most it may take of the maximum. A request
of a kind the gate has no summary for is declined `summary-missing`: nothing is signed unshown. A pairing whose build
hands the signer no request has no summary, since nothing is signed. A later step that names only its channel, such as
a session's voucher, is shown with the payees, asset, network and validity of the opening, once the gate has
recomputed the channel the opening opens for your account; a voucher of another channel has no summary.

### Ceilings and floors

The gate declines a payment that would stay payable longer than its pairing's ceiling, `past-ceiling`, and one that
signs no end, such as a delegation or a card checkout, `no-end`. A pairing's ceiling is 600 seconds unless `ceilings`
raises it: `{"x402/exact/sui": 86400}` raises one pairing's ceiling to a day, and `{"card/visa-tap": "no-end"}` admits
a form that signs no end; a `bool` is no integer. A deadline signed as a height, a slot, a round, a ledger or an epoch
is counted at the chain's pace, which the profile states with its source; on the XRP Ledger the caller gives
`ledgerIndex` in `inputs`, the validated ledger it read, and on Cardano and Sui `currentSlot` and `currentEpoch`, since
those requests sign no start.

Where a rail's payment service refuses a shorter validity, the caller reads the floor that service serves and gives it
in `inputs`, under the name the build takes; the gate reads no service of its own, and a missing floor input is
declined `floor-missing`, its detail the input's name. `FLOOR_INPUTS` maps each such pairing to the names of its floor
inputs. That rail's ceiling is the served floor plus the service's margin:

| Pairing | Floor inputs | Ceiling |
| --- | --- | --- |
| `x402/exact/eip155/gateway-batched` | `minValiditySeconds`, the minimum Circle Gateway's `/supported` serves for the network | `minValiditySeconds` plus 100 seconds |
| `mpp/charge/usdc/gateway` | `sourceNetwork`, the CAIP-2 network the burn intent spends from; `burnIntentExpirationHeight`, the height Circle Gateway's `GET /v1/info` serves for it; `withdrawalDelay`, that network's Gateway Wallet's `withdrawalDelay()`, in blocks | the burn intent's `maxBlockHeight` at `burnIntentExpirationHeight` plus 100 seconds counted in that network's blocks |

A Gateway burn intent's deadline is a block height on the network it spends from, so the gate holds it in whole blocks:
its `maxBlockHeight` less `burnIntentExpirationHeight` is at most `withdrawalDelay` × 100 / 604,800, rounded up, the
Gateway Wallet's withdrawal delay being 7 days; a raised ceiling of R seconds admits R × `withdrawalDelay` / 604,800
blocks, rounded down, where that is more. A burn intent shown on another network than `sourceNetwork` is declined
`past-ceiling`.

### Sign elsewhere: `confirm`, then `finish`

When the key lives in a hardware wallet or a signing service, split the order. `confirm` makes every check up to the
signing (1 to 11 of the profile) and returns the request with its `summary`; it calls no approver and no signer, so
showing that summary before the request is signed is your step. `Confirmed.chosen` is a `Chosen` dataclass whose fields
are plain JSON. Send `dataclasses.asdict(confirmed.chosen)` with the bytes, and rebuild it with
`Chosen(**data)` before `finish`. `finish` declines anything that is not a `Chosen` (`offer-unreadable`).

```python
import asyncio
import uuid

import httpx
from eth_account import Account
from eth_account.messages import encode_typed_data

from integraledger_terms import X402_EXACT_EIP155_EIP3009, Declined, Finished, confirm, finish

ATR = (
    '{"atrVersion":"1","id":"0f8fad5b-d9cb-469f-a165-70867728950e","x402":{"z":1.0,"a":"caf\\u00e9"},'
    '"seller":{"note":"Café — 30 días ✓"}}'
).encode()
H = "0x8b1e122580ae3f6a8c3d36a24294e1260a87bde70f597279b973e39310072938"
LINK = f"https://atr.seller.example/{uuid.uuid4()}"
OFFER = {
    "x402Version": 2,
    "resource": {"url": "https://api.seller.example/v1/quote"},
    "accepts": [
        {
            "scheme": "exact",
            "network": "eip155:84532",
            "amount": "10000",
            "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
            "maxTimeoutSeconds": 60,
            "extra": {"name": "USDC", "version": "2"},
        }
    ],
    "extensions": {"legalContext": {"info": {"type": "sha256", "value": H, "legalContextUrl": LINK}, "schema": {}}},
}
KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"


def seller(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, content=ATR) if str(request.url) == LINK else httpx.Response(404)


async def main() -> None:
    # 1. Compare, check, and build the request with H. confirm calls no approver: show the summary yourself.
    async with httpx.AsyncClient(transport=httpx.MockTransport(seller)) as client:
        confirmed = await confirm(
            OFFER,
            X402_EXACT_EIP155_EIP3009,
            "eip155:84532:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            client,
            resource_request={"method": "GET", "target": "/v1/quote", "body": b""},
        )
    if isinstance(confirmed, Declined) or confirmed.request is None or confirmed.summary is None:
        raise SystemExit(f"not confirmed: {confirmed}")
    print("to approve:", confirmed.summary.amount, confirmed.summary.asset, confirmed.summary.validity.unit)

    # 2. Sign exactly the request, elsewhere.
    typed = encode_typed_data(full_message=dict(confirmed.request["typedData"]))
    signature = "0x" + bytes(Account.sign_message(typed, KEY).signature).hex()

    # 3. Finish from the bytes and chosen. finish recomputes H from the bytes; it trusts nothing it did not rebuild.
    done = finish(confirmed.atr_bytes, confirmed.chosen, signature, X402_EXACT_EIP155_EIP3009)
    if not isinstance(done, Finished):
        raise SystemExit(f"not finished: {done}")
    print("nonce is H:", done.signed["payload"]["authorization"]["nonce"] == H)


asyncio.run(main())
```

```text output
to approve: 10000 0x036CbD53842c5426634e7929541eC2318f3dCF7e seconds
nonce is H: True
```

A pairing signed in two steps (a channel funding, then its first voucher) makes `finish` return
`Next(next, summary, h)`: show `summary`, sign `next` and call `finish` again with every answer so far, in order, as a
list. `finish` holds each later step to its summary and its ceiling before returning it, a voucher shown for the
account `confirm` chose; `finish(..., ceilings=...)` takes the raised ceilings. `transact` does this for you, asking
your approver at each step. Or pass `chosen=confirmed.chosen` to `transact`, which then builds that exact request and
asks your approver about it.

`confirm` and `finish` neither pay nor check the agreement; only `transact` and `agree` do. When
`confirmed.chosen.agreement` is set, the pairing's payment is not itself a public proof of H: do not sign yet. Call
`to_approve = await agree(confirmed.atr_bytes, confirmed.chosen.agreement, signer, fetch, chosen=confirmed.chosen)`,
have your agent approve `to_approve.approve`, call `agree` again with `approved=to_approve.approve` and the same
`chosen`, and sign `confirmed.request` only with the `Agreed` receipt in hand. Given `chosen`, `agree` pays only an
agreement option the charge's pairing admits (its `agreementOn` in the protocol package's registry: any network, or the
charge's own). See [Pay the agreement first](#pay-the-agreement-first).

Where `request` is `None`, there is nothing to sign. For `x402/batch-settlement/cloudflare` the build is itself the
payment: with the agreement's receipt in hand, `finish(confirmed.atr_bytes, confirmed.chosen, None, binding)` returns
it. For every other such pairing, the comparison and, where the pairing needs one, the agreement payment are the whole
of the buyer's step.

To pay the agreement without `agree`, request `chosen.agreement` yourself: it answers `402` with an x402 payment
request. Call `confirm` on that payment request with `act="agreement"`, through the x402 pairing of the option you pay,
and `finish` with the same `act`. The request `confirm` returns is then the agreement payment, built as `agree` builds
it, and `confirmed.chosen.act` is `"agreement"`: on a pairing whose agreement has its own single-use value, such as
`x402/exact/eip155/eip3009`, it carries that value in place of H. A pairing whose payment cannot be an agreement is
declined `no-payable-option`, and the option and `resource_request` are not held to the ATR's binding slot, which lists
the charge's options. Check that the `h` `confirm` returns is the H of the charge, sign, send the payment `finish`
returns to the agreement URL until it answers `200` with the receipt, and keep it: `check(atr_bytes, payment, binding,
act="agreement")` reads H from it.

### Pay the agreement first

Some payments are not a public proof of H: a card charge, a Stripe payment, a Lightning invoice, a checkout in which
the buyer signs nothing. For those pairings the seller's offer also names an **agreement URL**, an x402 resource for the
same H whose payment is a public proof. The agreement payment is a payment like any other, so your agent approves it
before anything is signed:

1. `transact` fetches the agreement URL's payment request and returns `ToApprove(approve, atr_bytes, h)`, signing
   nothing. `approve.option` is the option it would pay: its `amount`, `asset`, `payTo` and `network`. `approve.url` is
   the agreement URL, and `approve.required` the payment request as served.
2. Your agent approves it as it approves any payment. To pay it, call `transact` again with the same arguments and
   `approved=approve`.
3. The second call holds that payment to its own pairing's ceiling, asks your approver about it with `act`
   `"agreement"`, signs exactly that payment, sends it, and asks about and signs the main payment only after the
   agreement URL answers `200` with a receipt `{"atrHash": H, "agreed": true, "network": …, "transaction": …}`.

- The option paid is the first, in document order, that your signer can pay with an x402 pairing whose payment is itself
  a public proof (coverage `full`, with an agreement form) and that the main payment's pairing admits: its `agreementOn`
  says whether an agreement on any network will do, or only one on the payment's own network. Its `maxTimeoutSeconds`
  is a JSON number with an integral value: `60` and `60.0` are the same value.
- The agreement payment is built with the act `agreement`: on a pairing whose agreement has its own single-use value,
  the payment carries that value, computed from H, where a payment for the resource would carry H itself.
- The agreement URL's `402` must advertise the same H, or nothing is signed (`hash-mismatch`).
- Once the agreement payment is sent, the gate sends the same payment again after each `202`, `5xx` or timeout, within
  the paid option's `maxTimeoutSeconds` plus 180 seconds. Within one call it never signs a second agreement payment.
- Once the agreement payment is sent, every decline carries it as `moved`: `agreement-pending` when it may settle yet,
  and `agreement-failed` when the agreement URL answered otherwise. Either way, it has left your wallet. To collect the
  receipt, call again without `approved`: the gate asks the agreement URL unpaid and goes on once it answers `200` with
  the receipt, or declines `agreement-pending` again while it answers `202`, signing nothing. Never call again with
  `approved` for the same agreement: every call with `approved` signs and sends a new agreement payment.
- Setting `signal` ends the exchange sooner: before the payment is sent, `agreement-failed`, and nothing is sent (a
  payment signed in that window is discarded); after, `agreement-pending` with the payment as `moved`. Cancelling the
  task raises `asyncio.CancelledError`, and a payment already sent is not returned: set the signal to get it back as
  `moved`.
- The receipt is the agreement URL's statement: the gate checks its form and that its `atrHash` is H, and does not look
  up the transaction it names. A `200` to the first, unpaid request is the agreement URL's word alone: the gate made no
  agreement payment and read none, returns that receipt with `unpaid=True`, and the first call goes straight on to the
  main payment.
- A pairing that needs an agreement and whose offer names none is declined with `agreement-not-offered`.
- Where the agreement URL answers with no x402 payment request and with MPP agreement challenges
  (`WWW-Authenticate: Payment`), the gate signs nothing and returns
  `AgreementChallenges(agreement_challenges, atr_bytes, h)`, the challenges in the seller's order: terms does not send
  an MPP credential to the agreement URL, so your own MPP client pays one there, and a later call finds the agreement
  recorded and pays the charge.
- `await agree(atr_bytes, url, signer, fetch, approved=…, inputs=…, ceilings=…, signal=…, chosen=…)` runs the exchange
  on its own, in the same two calls. It takes no approver: showing the agreement payment before it is approved is then
  your step. It holds the agreement payment to its summary and its own pairing's ceiling before it is signed, as
  `transact` does, `ceilings` raising it. With `confirm` and `finish`, call it before you sign: see
  [Sign elsewhere](#sign-elsewhere-confirm-then-finish).

### Paid after its agreement

A seller may answer first with the agreement alone (the protocol package's profile `legal-context-return.md`): its
first response offers the agreement option and no charge, each agreement option naming, by its `serves`
(`extra.legalContextServes` on x402, the `opaque` member `legalContextServes` of an MPP agreement challenge), the
charges it is for, each `<slot>/<i>`: the option at index `i` of the charge options the ATR's binding slot of that name
holds (`x402/<i>`, `mpp/<i>`, `ack/<i>`, `acp/<i>`, `ap2/<i>`, `card/<i>` or `ucp/<i>`). The gate resolves each name
against the ATR's bytes once it has fetched them, and declines `offer-unreadable`, `return/serves-malformed`, an
option one of whose names is of another slot than the ATR's binding slot or past the options it holds. `transact` then
chooses the charge from the options the ATR's binding slot holds, pays the agreement
option that serves it, asked of your approver with `act` `"agreement"`, ends at the agreement's receipt, signs no
charge, and returns `ToReturn`.

Where the slot holds the charge in the form the first response would offer it, the charge is built with H and held to
its summary and its ceiling before its agreement is paid. Where the seller writes part of it only when it serves the
charge, the charge is chosen by the option's own checks, and the call that pays it makes the rest: an
`x402/exact/lnbtc/payment-hash` option, whose invoice comes later, and every MPP challenge, which the slot holds as
issued.

A card or checkout sale (`card`, `acp`, `ap2`, `ucp` or `ack`) whose agreement the first response offers as an x402
or MPP option is paid the same way: pass `transact` that first response and the charge's pairing, such as
`CARD_VISA_TAP`. The charge chosen is a served option of the ATR's binding slot that the pairing pays for your account, a
CAIP-10 account: on `card` the option of the pairing's `scheme`, on `acp` its handler option, on `ap2` and `ucp` a
checkout (on a booking pairing a booking), on `ack` a payment option on your account's network. Its build, summary and
ceiling are left to the call that pays it, with the seller's document served after the return, which names the
agreement URL; `charge` is then such as `card/0`.

On MPP, `transact` follows the agreement URL the agreement challenges carry and reads its one `402`: it pays an x402
agreement option there as on x402. Where that `402` offers only MPP agreement challenges, `transact` signs nothing and
returns them in `ToReturn.agreement_challenges`, with `agreement` `None`, for your own MPP client to pay at the
agreement URL.

`ToReturn(agreement, legal_context, charge, atr_bytes, h, agreement_challenges)` holds the receipt, where `transact`
paid the agreement; the `Legal-Context` value to send when you repeat your request, H's LCP string with `rv`, the return
value, where the first response carried one; the charge chosen, `<slot>/<i>` such as `x402/0`; the ATR's bytes
and their hash; and the MPP agreement challenges, where `transact` returns them instead of paying.

Pass the first response's `Legal-Context` header (over MCP, its `_meta["com.integraledger.lcp/legal-context"]`), as
received, as `legal_context`: a value the protocol package refuses is declined `offer-unreadable`, and one whose H is
not the ATR's `hash-mismatch`. Repeat your request with the returned `legal_context`, and call `transact` again with
the second response, which offers the charge: the agreement being recorded, that call pays the charge as any other.

### Channels and sessions

In an x402 batch-settlement channel or an MPP session, one ATR covers the whole channel. The gate compares it once, at
the opening; you keep a **hold** (a JSON-ready `dict`) and sign every later voucher from it. This example opens a
channel with the vectors' two development keys and pays two more requests in it:

```python
import asyncio
import uuid
from collections.abc import Mapping
from typing import Any

import httpx
from eth_account import Account
from eth_account.messages import encode_typed_data

from integraledger_terms import (
    X402_BATCH_SETTLEMENT_EIP155,
    Declined,
    ToSign,
    Transacted,
    open_channel,
    record_charge,
    transact,
    within,
)

ATR = (
    '{"atrVersion":"1","id":"0f8fad5b-d9cb-469f-a165-70867728950e","x402":{"z":1.0,"a":"caf\\u00e9"},'
    '"seller":{"note":"Café — 30 días ✓"}}'
).encode()
H = "0x8b1e122580ae3f6a8c3d36a24294e1260a87bde70f597279b973e39310072938"
LINK = f"https://atr.seller.example/{uuid.uuid4()}"

# The seller's batch-settlement offer: 1000 units per request, into a channel.
OFFER = {
    "x402Version": 2,
    "resource": {"url": "https://api.seller.example/v1/quote"},
    "accepts": [
        {
            "scheme": "batch-settlement",
            "network": "eip155:84532",
            "amount": "1000",
            "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
            "maxTimeoutSeconds": 3600,
            "extra": {
                "receiverAuthorizer": "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
                "withdrawDelay": 900,
                "name": "USDC",
                "version": "2",
            },
        }
    ],
    "extensions": {"legalContext": {"info": {"type": "sha256", "value": H, "legalContextUrl": LINK}, "schema": {}}},
}

# Anvil development keys: the payer funds the channel, the payer authorizer signs vouchers. Never use them for real funds.
PAYER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
AUTHORIZER_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
AUTHORIZER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"


def sign_typed(typed_data: Mapping[str, Any], key: str) -> str:
    signed = Account.sign_message(encode_typed_data(full_message=dict(typed_data)), key)
    return "0x" + bytes(signed.signature).hex()


class Wallet:
    account = "eip155:84532:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

    async def sign(self, request: Mapping[str, Any]) -> list[str]:
        if request["kind"] != "batch":
            raise ValueError(f"unexpected {request['kind']}")
        answers = []
        for each in request["requests"]:
            typed = each["typedData"]
            answers.append(sign_typed(typed, AUTHORIZER_KEY if typed["primaryType"] == "Voucher" else PAYER_KEY))
        return answers


def seller(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, content=ATR) if str(request.url) == LINK else httpx.Response(404)


def approver(to_sign: ToSign) -> bool:
    summary = to_sign.summary
    print("opening  deposit", summary.deposit, "to", summary.payees[0].account)
    return True


async def main() -> None:
    wallet = Wallet()
    # Open: compare the ATR once, show the opening, sign the deposit and the first voucher.
    async with httpx.AsyncClient(transport=httpx.MockTransport(seller)) as client:
        opened = await transact(
            OFFER,
            X402_BATCH_SETTLEMENT_EIP155,
            wallet,
            client,
            approver=approver,
            resource_request={"method": "GET", "target": "/v1/quote", "body": b""},
            inputs={"payerAuthorizer": AUTHORIZER, "deposit": "100000"},
            # The deposit's authorization stays payable for the option's 3600 seconds: raise the 600-second ceiling.
            ceilings={"x402/batch-settlement/eip155": 3600},
        )
    if not isinstance(opened, Transacted) or opened.signed is None:
        raise SystemExit(f"the channel did not open: {opened}")
    hold = open_channel(opened.atr_bytes, opened.signed, X402_BATCH_SETTLEMENT_EIP155)
    if isinstance(hold, Declined):
        raise SystemExit(hold.code)
    print("channel ", hold["channel"])

    # Each later request: the seller's new offer must advertise the held H.
    for charged in ("1000", "2000"):
        paid = await within(OFFER, hold, X402_BATCH_SETTLEMENT_EIP155, wallet)
        if isinstance(paid, Declined):
            raise SystemExit(paid.code)
        print("voucher up to", paid.hold["signedMax"])
        # The seller reports its cumulative charge; it may not exceed what was signed.
        recorded = record_charge(paid.hold, charged)
        if isinstance(recorded, Declined):
            raise SystemExit(recorded.code)
        hold = recorded


asyncio.run(main())
```

```text output
opening  deposit 100000 to 0x209693Bc6afc0C5328bA36FaF03C514EF312287C
channel  0x9c2d7031768ecb3fe688ae307c45f2e3a3d98b0d9ce1a6afcd27131fabb67e56
voucher up to 1000
voucher up to 2000
```

The channel id is the one the TypeScript gate computes for the same inputs: both languages build the same payment.

The hold is a plain `dict`: store it, and pass the latest one to each call. `within` takes the bytes, H and the channel
from the hold, and the amount from the new challenge. On x402's batch channels it signs only when that challenge
advertises the held H and the payment it builds names the held channel. On an MPP session it declines a challenge that
names another channel or another H, and signs one with no legal context under the held H. `within` takes no approver and
holds a voucher to no summary or ceiling of its own, by rule: a voucher signs no deadline of its own and pays only from
the deposit its opening moves, and the gate holds an opening it builds to its summary and its ceiling before it is
signed, `transact` asking your approver too; the hold keeps no copy of the opening's request, which a voucher's summary
is read with. A caller that wants each later voucher shown shows it before it calls `within`.
`mpp/session/solana/memo` opens through the gate, but terms builds none of its vouchers, the protocol package giving
that pairing no in-channel build: `within` declines it `pairing-not-supported`, and its buyer writes the 50 bytes a
voucher signs and signs them itself, as the protocol package's `solanaVoucher` (`@integraledger/lcp/svm`) writes them:
`56 01`, the 32-byte channel id, the cumulative amount as a little-endian u64, and the expiry as a little-endian i64, 0
where there is none.

### Confirm a payment later: `check`

`check(atr_bytes, presented, binding, landed=None, act="payment")` returns `Checked(h)` when the ATR hash the pairing
reads from a payment you hold is the SHA-256 of the bytes you kept. A payment from which the pairing reads no ATR hash is declined
`signed-not-bound`. Where `finish` or `transact` returned `landed`, pass it as `landed`, beside the payment: a
`"landed"` member written into the payment is not read. The caller passes as `landed` only the receipt its own reader
read for the payment, as `finish` or `transact` returned it, never a value another party sent. `act` is the act the
payment was paid as: `"payment"`, the default, or `"agreement"` for an agreement payment, which carries the agreement's
own value computed from H where a payment would carry H, and is read as such.

### Declines and `moved`

A decline is `Declined(code, detail, moved)`. `code` is a `DeclineCode`, one of the values in the table below; `detail`
is a sentence or the protocol's refusal code. Where your signer moved the payment itself before the gate declined (a Lightning node paid the invoice, a
signer broadcast a transaction), `moved` is `Moved(signed, atr_bytes, h)`. A decline that follows a sent agreement
payment carries that payment as `moved` too. Keep it: present a payment your signer moved again rather than signing a
new one, and for an agreement payment, call again without `approved` to collect its receipt, never with `approved`.

| Code | Meaning |
| --- | --- |
| `pairing-not-supported` | The binding names no pairing the gate serves; `chosen` or a hold belongs to another pairing; or the pairing has no channel. |
| `offer-unreadable` | The seller's document, the chosen option or a build could not be read, or a recorded charge is out of range. `detail` carries the reason. |
| `no-payable-option` | No option is payable by this account (for the agreement, with a public-proof pairing), an input the build needs is missing or malformed, the arguments of `transact` or `agree` are malformed, or a later channel challenge asks for a payment in a channel the hold did not open. |
| `link-not-https` | The ATR link or the agreement URL is not an `https` URL. Nothing was fetched. |
| `atr-unfetchable` | The link did not answer `200` with the bytes within 10 seconds (a redirect counts as a failure), or answered `200` with a `Content-Encoding` other than `identity`. |
| `atr-too-large` | The ATR is larger than 1 MiB (1,048,576 bytes). |
| `hash-mismatch` | The served bytes do not hash to the advertised H; the agreement URL or a later channel challenge advertises another H; or a hold's bytes do not hash to its H. Nothing was signed. |
| `signer-failed` | Your signer raised. |
| `signed-not-bound` | The pairing does not read the hash of the compared bytes from the payment. The payment is not returned. |
| `agreement-not-offered` | The pairing's payment is not a public proof, and the offer names no agreement URL. |
| `agreement-pending` | The agreement payment is sent and not yet recorded, or the agreement URL answered `202` to the unpaid request: another is already settling. |
| `agreement-failed` | The unpaid request: the agreement URL could not be reached, or answered a status other than `200`, `202` or `402`, or a `402` without a readable `PAYMENT-REQUIRED`. The paid request: any answer but `200`, `202` or `5xx`, a `402` included. Either request: a `200` or `402` with a `Content-Encoding` other than `identity`, or a `200` that is not a receipt for this H (a receipt over 64 KiB included). Also: the approved payment names another agreement URL, or `signal` ended the exchange before the payment is sent. |
| `not-approved` | Your approver answered anything but `True`, raised or failed, for the signing it was asked about. The signer was not called for it. |
| `atr-malformed` | The ATR's bytes are not one JSON text the gate reads alike in both languages: not UTF-8, a byte-order mark, `NaN` or `Infinity`, a repeated member name, a number past a double or an integer past 2^53 − 1, or nesting past 64 levels. |
| `option-not-in-atr` | The ATR's binding slot lists the options offered (`accepts` in `x402`, `challenges` in `mpp`, `options` in `acp`, `ap2`, `card` and `ucp`, `paymentOptions` in `ack`), and none is the option chosen. |
| `request-mismatch` | The ATR's `x402` slot holds a request commitment that is not your request's; a `target` that is not in origin form gives the detail `x402/request-target-invalid`. |
| `summary-missing` | The request for the signer is of a kind the gate cannot summarize, so it is not signed unshown. |
| `past-ceiling` | The signed payment would stay payable longer than its pairing's ceiling. |
| `no-end` | The form signs no end, and `ceilings` does not map its pairing to `"no-end"`. |
| `floor-missing` | The rail has a served floor and `inputs` lacks its input; `detail` is the input's name. |

The profile
[`buyer-gate.md`](https://github.com/IntegraLedger/integra-agentic-terms/blob/main/agentic-terms/profiles/buyer-gate.md)
states when each of the last eight is returned and whether the signer was called.

## API reference

Everything below is exported from `integraledger_terms`.

### Functions

| Export | Signature | What it does |
| --- | --- | --- |
| `transact` | `async (doc, binding, signer, fetch, *, approver, resource_request, inputs=None, ceilings=None, legal_context=None, agreement_signer=None, approved=None, signal=None, chosen=None) -> Transacted \| ToApprove \| AgreementChallenges \| ToReturn \| Declined` | Compare and check, pay the approved agreement first where needed, ask the approver, sign, finish. |
| `confirm` | `async (doc, binding, account, fetch, *, resource_request, inputs=None, ceilings=None, act="payment") -> Confirmed \| Declined` | Read, fetch, compare and check, and build the signing request with H, with its summary. `request` is `None` when there is nothing to sign; `chosen.agreement` is the agreement URL, where the pairing needs one. With `act="agreement"`, build the agreement payment an agreement URL's payment request asks for, as `agree` does. |
| `finish` | `(atr_bytes, chosen, signature, binding, *, ceilings=None, act="payment") -> Finished \| Next \| Declined` | Rebuild from `chosen` and the bytes, join the signature, and return the payment only when the pairing reads H from the completed payment, or, where the proof is the agreement payment, without that reading. A later step is returned with its summary, held to the ceiling. `act` is the act `confirm` built the payment as. |
| `check` | `(atr_bytes, presented, binding, landed=None, act="payment") -> Checked \| Declined` | Confirm a held payment carries the hash of the kept bytes, as the act it was paid as. |
| `agree` | `async (atr_bytes, url, signer, fetch, *, approved=None, inputs=None, ceilings=None, signal=None, chosen=None) -> ToApprove \| AgreementChallenges \| Agreed \| Declined` | Without `approved`, return the agreement payment to approve, signing nothing, or, where the agreement URL answers that unpaid request with a receipt, that receipt with `unpaid=True`, nothing paid or read; with it, pay that payment and return the receipt. Where the agreement URL offers only MPP agreement challenges, return them, signing nothing. |
| `open_channel` | `(atr_bytes, opened, binding, landed=None) -> ChannelHold \| Declined` | Hold a channel opened for the compared ATR. Pass `landed` where `transact` returned one. |
| `within` | `async (doc, hold, binding, signer, refund=None, inputs=None) -> Within \| Declined` | Sign a later voucher, or a refund with `refund`, in a held channel, with no approver, and no summary or ceiling of its own: the gate holds an opening it builds to both. |
| `record_charge` | `(hold, charged_cumulative_amount) -> ChannelHold \| Declined` | Record the seller's cumulative charge, between the last recorded and the most signed. |
| `vi_json` | `(value) -> str \| None` | The JSON text a Mastercard Verifiable Intent signer signs for a value (the protocol package's profile `card-mastercard-vi.md`, rule 7); `None` for a value that is not JSON. |
| `atr_hash` | `(data: bytes) -> AtrHash` | SHA-256 of the bytes, `0x` and 64 lower-case hex digits. |
| `hash_equals` | `(a: str, b: str) -> bool` | Compares two hashes as 32 decoded bytes, in either case; `False` when either is malformed. |

`fetch` is an `httpx.AsyncClient`. The gate asks it for one `GET` of the link, with `Accept-Encoding: identity` and no
redirect, and reads the body as sent, stopping at the size bound. A `200` whose `Content-Encoding` names any coding is
declined with its body unread, so nothing is decompressed and the bytes hashed are the bytes sent. The agreement URL is
asked the same way, and its receipt read as sent, at most 64 KiB.

`httpx` refuses some hosts the gate accepts in an `https` link: an `xn--` label that is not valid Punycode, such as
`xn--zz`, and a label IDNA 2008 does not allow, such as `xn--a` or `xn--ls8h`. An ATR link on such a host is declined
`atr-unfetchable`, and an agreement URL on one is declined `agreement-failed`; nothing is fetched. The TypeScript gate
passes such a link to its `fetch`.

### Results and types

| Export | What it is |
| --- | --- |
| `Transacted` | `signed`, `atr_bytes`, `h`, `agreement`, `landed`. |
| `ToReturn` | `agreement`, `legal_context`, `charge`, `atr_bytes`, `h`, `agreement_challenges`: the agreement paid, or its MPP agreement challenges, for a pairing paid after its agreement. Exactly one of `agreement` and `agreement_challenges` is not `None`. |
| `AgreementChallenges` | `agreement_challenges`, `atr_bytes`, `h`: the agreement resource's MPP agreement challenges, for your own MPP client to pay; nothing is signed. |
| `Confirmed` | `chosen`, `request` (a `dict`, or `None`), `atr_bytes`, `h`, `summary` (a `Summary`, or `None` where nothing is signed). |
| `Finished` | `signed`, `h`, `landed`. |
| `Next` | `next` (the next request), `summary` (its `Summary`) and `h`, for a payment signed in steps. |
| `Checked` | `h`. |
| `ToApprove` | `approve` (an `AgreementPayment`), `atr_bytes`, `h`: the agreement payment to approve. |
| `AgreementPayment` | `url`, `option` (the x402 option paid: `amount`, `asset`, `payTo`, `network`), `required` (the agreement URL's payment request as served). |
| `Agreed` | `receipt`. |
| `AgreementReceipt` | `atr_hash`, `agreed`, `network`, `transaction`, `unpaid`: `True` where the agreement URL answered the first, unpaid request with it, the gate having made no agreement payment and read none; `False` where it answered the paid request. |
| `Within` | `signed` and the updated `hold`. |
| `ChannelHold` | A `dict`: `pairing`, `network`, `channel`, `h`, `atr` (base64), `opening`, `landed` (where there is a read made for the opening), `charged`, `signedMax`. |
| `Declined` | `code`, `detail`, `moved`. |
| `Moved` | `signed`, `atr_bytes`, `h`: the payment the signer moved before a decline, to keep and present again. |
| `DeclineCode` | The codes in the table above. |
| `Chosen` | A dataclass: `pairing`, `choice`, `ref`, `agreement`, `act`, `deadline`, whose values are plain JSON; the agreement URL where the pairing needs one, and the latest deadline handed to a wallet that picks its expiry. |
| `Signer` | A protocol: an `account` string (CAIP-10) and `async def sign(self, request) -> Signature`. |
| `Approver` | `Callable[[ToSign], bool \| Awaitable[bool]]`. |
| `ToSign` | `act`, `pairing`, `request`, `summary`, `step`: what the approver is asked about. |
| `SigningStep` | `index`, `count`: which signing of the payment, from 0, of the number the pairing's payment takes. |
| `Summary`, `Payee`, `Validity` | Every authority the signature grants, as [What the approver is shown](#what-the-approver-is-shown) lists. |
| `ResourceRequest`, `HttpRequest`, `ToolCall` | The buyer's own request: `TypedDict`s with the protocol package's member names. |
| `Ceilings` | `Mapping[str, int \| Literal["no-end"]]`: the raised ceilings, in seconds. |
| `Binding` | A protocol: `id`, `read`, `build`, `bound`, `broadcaster`, with the registry's coverage and agreement data. |
| `Advertised`, `Step`, `Refusal`, `Unsigned`, `BatchUnsigned`, `ChannelRef` | The values a binding and the gate exchange, for code that implements a binding. |
| `AtrHash`, `Json`, `Inputs`, `Signature` | Aliases: `str`, `Mapping[str, Any]`, `Mapping[str, Any]`, `Any`. |
| `MAX_ATR_BYTES` | `1048576`. |
| `FLOOR_INPUTS` | A mapping from each pairing whose rail has a served floor to the names of its floor inputs in `inputs`, a tuple. |

A binding's `broadcaster(presented)` names who puts the presented payment on its rail: `"payer"`, which sent it before
presenting it, or `"payee"`, the seller, or the facilitator or processor acting for it, which sends or executes it. It
answers only for a payment of a type and kind the pairing takes, within the shape gate `bound` applies first, and gives
any other payment the `Refusal` `bound` gives that fault. Where a payment has a second fault that `bound` finds first,
in H or the challenge, the two codes differ.

A signer receives each request with every byte string as `0x` and lower-case hex, and answers with byte strings in
the form the [signers guide](https://github.com/IntegraLedger/integra-agentic-terms/blob/main/docs/guides/signers.md)
names for its kind: `0x` hex, except where the guide names base58, base64, or hex digits without `0x`. The guide
lists every request kind and the answer it takes.

## Supported pairings

Each pairing is a module-level binding constant. The list is generated from the TypeScript registry and checked against
this package's exports, so both languages serve the same pairings; each column is read from the pairing's registry
data in `@integraledger/lcp`. "Coverage" is `full` where the payment is itself a public proof of H and `none`
otherwise. "Confirmed" is `yes` where something outside the protocol package has shown the form as its profile defines
it (`confirmed`); the gate builds and reads the others exactly as their profiles define them, though nothing outside
the protocol package has yet shown those forms. On `x402/exact/casper` and `x402/exact/ccd` the stock clients cannot
pay the form: the stock Casper client draws a random nonce, and the stock Concordium client writes no memo. "Agreement
payment first" marks the pairings paid after an agreement payment, and on which network that agreement may be. "Pays
an agreement" marks the pairings through which the gate pays the agreement payment another pairing follows, the x402
pairings whose registry data holds an agreement form, and `only` where a payment is never a charge, only an agreement.
An MPP pairing whose registry data holds an agreement form reads `no`: the gate pays no agreement over MPP, and returns
the seller's MPP agreement challenges in `AgreementChallenges` for your own MPP client to pay.

<!-- pairings:python:start -->
| Rail | Pairing | Python binding | Coverage | Confirmed | Agreement payment first | Pays an agreement |
| --- | --- | --- | --- | --- | --- | --- |
| EVM | `mpp/charge/evm/authorization` | `MPP_CHARGE_EVM_AUTHORIZATION` | full | yes | no | no |
| EVM | `mpp/charge/evm/hash` | `MPP_CHARGE_EVM_HASH` | none | yes | yes, any network | no |
| EVM | `mpp/charge/evm/permit2` | `MPP_CHARGE_EVM_PERMIT2` | full | no | no | no |
| EVM | `mpp/charge/evm/transaction` | `MPP_CHARGE_EVM_TRANSACTION` | none | yes | yes, any network | no |
| EVM | `mpp/charge/usdc/evm` | `MPP_CHARGE_USDC_EVM` | full | yes | no | no |
| EVM | `mpp/charge/usdc/gateway` | `MPP_CHARGE_USDC_GATEWAY` | none | no | yes, any network | no |
| EVM | `mpp/session/evm` | `MPP_SESSION_EVM` | full | no | no | no |
| EVM | `spend-permissions/eip155` | `SPEND_PERMISSIONS_EIP155` | full | yes | no | only |
| EVM | `x402/auth-capture/eip155/eip3009` | `X402_AUTH_CAPTURE_EIP155_EIP3009` | full | yes | no | no |
| EVM | `x402/auth-capture/eip155/permit2` | `X402_AUTH_CAPTURE_EIP155_PERMIT2` | full | yes | no | no |
| EVM | `x402/batch-settlement/eip155` | `X402_BATCH_SETTLEMENT_EIP155` | full | yes | no | no |
| EVM | `x402/exact/eip155/eip3009` | `X402_EXACT_EIP155_EIP3009` | full | yes | no | yes |
| EVM | `x402/exact/eip155/erc7710` | `X402_EXACT_EIP155_ERC7710` | none | yes | yes, any network | no |
| EVM | `x402/exact/eip155/erc7710-salt` | `X402_EXACT_EIP155_ERC7710_SALT` | full | yes | no | no |
| EVM | `x402/exact/eip155/gateway-batched` | `X402_EXACT_EIP155_GATEWAY_BATCHED` | none | yes | yes, its network | no |
| EVM | `x402/exact/eip155/permit2` | `X402_EXACT_EIP155_PERMIT2` | full | yes | no | yes |
| EVM | `x402/upto/eip155/permit2` | `X402_UPTO_EIP155_PERMIT2` | full | yes | no | no |
| Tempo | `mpp/charge/tempo/split-memo` | `MPP_CHARGE_TEMPO_SPLIT_MEMO` | full | yes | no | no |
| Tempo | `mpp/charge/tempo/split-memo/push` | `MPP_CHARGE_TEMPO_SPLIT_MEMO_PUSH` | full | yes | no | no |
| Tempo | `mpp/session/tempo` | `MPP_SESSION_TEMPO` | full | yes | no | no |
| Tempo | `mpp/subscription/tempo` | `MPP_SUBSCRIPTION_TEMPO` | full | yes | no | no |
| Solana | `mpp/charge/solana` | `MPP_CHARGE_SOLANA` | full | yes | no | no |
| Solana | `mpp/charge/solana/unsponsored` | `MPP_CHARGE_SOLANA_UNSPONSORED` | full | yes | no | no |
| Solana | `mpp/charge/usdc/solana` | `MPP_CHARGE_USDC_SOLANA` | full | yes | no | no |
| Solana | `mpp/session/solana/memo` | `MPP_SESSION_SOLANA_MEMO` | full | no | no | no |
| Solana | `mpp/session/solana/stock` | `MPP_SESSION_SOLANA_STOCK` | none | yes | yes, its network | no |
| Solana | `mpp/subscription/solana` | `MPP_SUBSCRIPTION_SOLANA` | full | no | no | no |
| Solana | `x402/batch-settlement/solana` | `X402_BATCH_SETTLEMENT_SOLANA` | full | no | no | no |
| Solana | `x402/exact/solana` | `X402_EXACT_SOLANA` | full | yes | no | yes |
| Solana | `x402/upto/solana` | `X402_UPTO_SOLANA` | full | no | no | no |
| Stellar | `x402/exact/stellar/precondition` | `X402_EXACT_STELLAR_PRECONDITION` | full | yes | no | only |
| XRP Ledger | `mpp/charge/xrpl` | `MPP_CHARGE_XRPL` | full | yes | no | no |
| XRP Ledger | `mpp/session/xrpl` | `MPP_SESSION_XRPL` | full | no | no | no |
| XRP Ledger | `mpp/session/xrpl/stock` | `MPP_SESSION_XRPL_STOCK` | none | no | yes, its network | no |
| XRP Ledger | `x402/exact/xrpl` | `X402_EXACT_XRPL` | full | yes | no | yes |
| XRP Ledger | `x402/upto/xrpl` | `X402_UPTO_XRPL` | none | yes | yes, its network | no |
| Hedera | `mpp/charge/lcp/hedera` | `MPP_CHARGE_LCP_HEDERA` | full | yes | no | no |
| Hedera | `mpp/session/hedera/stock` | `MPP_SESSION_HEDERA_STOCK` | none | no | yes, its network | no |
| Hedera | `x402/exact/hedera` | `X402_EXACT_HEDERA` | full | yes | no | yes |
| Hedera | `x402/exact/hedera/transfer-executor` | `X402_EXACT_HEDERA_TRANSFER_EXECUTOR` | none | no | yes, any network | no |
| Algorand | `x402/exact/algorand` | `X402_EXACT_ALGORAND` | full | yes | no | yes |
| Aptos | `x402/exact/aptos` | `X402_EXACT_APTOS` | none | yes | yes, any network | no |
| Sui | `x402/exact/sui` | `X402_EXACT_SUI` | full | yes | no | yes |
| NEAR | `mpp/charge/nearintents` | `MPP_CHARGE_NEARINTENTS` | none | no | yes, any network | no |
| NEAR | `x402/exact/near` | `X402_EXACT_NEAR` | full | yes | no | yes |
| Starknet | `x402/exact/starknet` | `X402_EXACT_STARKNET` | full | yes | no | yes |
| Polkadot | `x402/exact/polkadot/lcp-assets-remark` | `X402_EXACT_POLKADOT_LCP_ASSETS_REMARK` | full | yes | no | yes |
| TRON | `x402/exact/tron/lcp-trc20-memo` | `X402_EXACT_TRON_LCP_TRC20_MEMO` | full | yes | no | yes |
| TON | `x402/exact/tvm` | `X402_EXACT_TVM` | full | yes | no | yes |
| Cardano | `x402/exact/cardano` | `X402_EXACT_CARDANO` | full | yes | no | yes |
| Cardano | `x402/exact/cardano/lock` | `X402_EXACT_CARDANO_LOCK` | full | yes | no | no |
| Casper | `x402/exact/casper` | `X402_EXACT_CASPER` | full | no | no | yes |
| Concordium | `x402/exact/ccd` | `X402_EXACT_CCD` | full | no | no | no |
| Stacks | `mpp/charge/usdc/stacks` | `MPP_CHARGE_USDC_STACKS` | full | no | no | no |
| Lightning | `mpp/charge/lightning` | `MPP_CHARGE_LIGHTNING` | none | no | yes, any network | no |
| Lightning | `mpp/session/lightning` | `MPP_SESSION_LIGHTNING` | none | no | yes, any network | no |
| Lightning | `x402/exact/lnbtc/payment-hash` | `X402_EXACT_LNBTC_PAYMENT_HASH` | none | yes | yes, any network | no |
| Cloudflare | `x402/batch-settlement/cloudflare` | `X402_BATCH_SETTLEMENT_CLOUDFLARE` | none | no | yes, any network | no |
| Card | `card/mastercard-agent-pay` | `CARD_MASTERCARD_AGENT_PAY` | none | no | yes, any network | no |
| Card | `card/mastercard-vi/autonomous` | `CARD_MASTERCARD_VI_AUTONOMOUS` | none | no | yes, any network | no |
| Card | `card/mastercard-vi/immediate` | `CARD_MASTERCARD_VI_IMMEDIATE` | none | no | yes, any network | no |
| Card | `card/seller-reference` | `CARD_SELLER_REFERENCE` | none | no | yes, any network | no |
| Card | `card/visa-tap` | `CARD_VISA_TAP` | none | no | yes, any network | no |
| Card | `card/visa-vic` | `CARD_VISA_VIC` | none | no | yes, any network | no |
| Card | `mpp/charge/card` | `MPP_CHARGE_CARD` | none | no | yes, any network | no |
| Stripe | `mpp/charge/stripe` | `MPP_CHARGE_STRIPE` | none | no | yes, any network | no |
| Stripe | `mpp/subscription/stripe` | `MPP_SUBSCRIPTION_STRIPE` | none | no | yes, any network | no |
| Mandate | `ap2/checkout-mandate` | `AP2_CHECKOUT_MANDATE` | none | no | yes, any network | no |
| Mandate | `ap2/checkout-mandate/x402` | `AP2_CHECKOUT_MANDATE_X402` | none | no | yes, any network | no |
| Mandate | `ucp/booking/ap2-mandate` | `UCP_BOOKING_AP2_MANDATE` | none | no | yes, any network | no |
| Mandate | `ucp/checkout/ap2-mandate` | `UCP_CHECKOUT_AP2_MANDATE` | none | no | yes, any network | no |
| Checkout | `ack/payment-request` | `ACK_PAYMENT_REQUEST` | none | no | yes, any network | no |
| Checkout | `acp/checkout/delegated` | `ACP_CHECKOUT_DELEGATED` | none | no | yes, any network | no |
| Checkout | `acp/checkout/undelegated` | `ACP_CHECKOUT_UNDELEGATED` | none | no | yes, any network | no |
| Checkout | `ucp/booking/unsigned` | `UCP_BOOKING_UNSIGNED` | none | no | yes, any network | no |
| Checkout | `ucp/checkout/agent-signed` | `UCP_CHECKOUT_AGENT_SIGNED` | none | no | yes, any network | no |
| Checkout | `ucp/checkout/unsigned` | `UCP_CHECKOUT_UNSIGNED` | none | no | yes, any network | no |
<!-- pairings:python:end -->

## Security model

What the gate guarantees, in the code:

- **Nothing is signed before the comparison.** The signer is called only after SHA-256 of the served bytes equals the
  advertised H, compared as 32 decoded bytes.
- **The payment carries the computed hash.** The build takes the hash the gate computed, not the advertised string.
- **The hash is read back from the payment.** `finish` returns a payment only when the binding reads, from the completed
  payment, the hash of the compared bytes, or, where the proof is the agreement payment, without that reading. For a
  pairing whose payment is not a public proof, `transact` signs the payment only after the agreement's receipt for that
  hash. `confirm` and `finish` neither pay nor check the agreement: a caller that drives them signs `request` only with
  the receipt `agree` returns.
- **`transact` shows every payment before it is signed.** Each signing, the agreement payment's and each later step's
  among them, is asked of your approver with its summary, computed from the request the signer is handed, and the
  signer is called only on `True`. This holds of `transact` alone: a payment you sign yourself from `confirm` and
  `finish`, and the payments `agree` and `within` sign, which take no approver, are shown only where you show them.
- **The option is one the ATR commits to.** Where the ATR's binding slot lists the options offered, the option paid is
  one of them (on card, whose documents do not show the seller's checkout id, one of the pairing's `scheme`); where the
  `x402` slot holds a commitment to the buyer's request, the request is the buyer's own.
- **A bounded window, in `transact`, `confirm`, `finish` and `agree`.** A payment that would stay payable past its
  pairing's ceiling is declined before it is signed, as is a form that signs no end, unless you raise that pairing's
  ceiling. `within` applies no ceiling of its own: a voucher signs no deadline and pays only from the deposit of its
  opening, which the gate holds to its ceiling when it builds it.
- **One bounded fetch.** One `GET` of an `https` link, no redirect, one 10-second deadline over headers and body, at most
  1 MiB (1,048,576 bytes) read as sent.
- **Exact bytes.** The ATR is hashed as received and returned as received, and the bytes parsed are the bytes hashed,
  never a re-serialised copy. Every request asks for
  `Accept-Encoding: identity`, and a `200` whose `Content-Encoding` names any coding is declined unread, so nothing is
  decompressed: the bytes hashed are the bytes sent.
- **No keys.** The gate hands requests to your signer and holds nothing that could sign.
- **Your network policy.** Every request goes through the `httpx.AsyncClient` you pass. The ATR link and the agreement
  URL are the seller's choice, so a server-side buyer should give a client that refuses addresses that are not public.

What it does not do:

- It judges none of the ATR's terms: it parses the bytes, and reads only the binding slot's options and, on x402, its
  request commitment.
- It does not check amount, payee, asset, timing or payer against the ATR, and applies no spending limit. It shows
  them; a discrepancy is between the parties, and what to approve is your approver's decision.
- `confirm` and `finish` neither pay nor check the agreement; only `transact` and `agree` do. With `confirm` and
  `finish`, when `confirmed.chosen.agreement` is set, call `agree` and sign `confirmed.request` only with the `Agreed`
  receipt in hand.
- It does not authenticate the agreement's receipt. The receipt is the agreement URL's statement: the gate checks its
  form and that its `atrHash` is H, and does not look up the transaction it names. A `200` to the first, unpaid
  request is the agreement URL's word alone, and the receipt it carries is returned with `unpaid=True`. The public
  proof is the transaction the receipt names, on its network.
- It does not bound the amount a channel voucher adds: that is the amount the seller's new challenge asks.
- It carries no business or legal logic.
- It does not store the ATR, talk to a facilitator, or settle a payment.

## Test vectors and conformance

The rules are fixed by the shared vectors that the TypeScript package `@integraledger/lcp` ships in its `vectors/`
directory: the buyer rows of `buyer.json` (the hash, a record changed by one byte, the fetch bounds, the agreement
exchange) and each pairing's file (the request it builds and the payment it completes). The gate's own checks are fixed
by `agentic-terms/vectors/buyer-gate.json`, whose every input is a published row or a specification's own example,
under the profile `agentic-terms/profiles/buyer-gate.md`. This package's test suite runs every one on Python 3.11 and
3.14, and the TypeScript gate runs the same files, so both compute the same hashes, build
the same requests and give the same declines. The tests read the vectors from `@integraledger/lcp` as `pnpm install`
places it in a checkout, so they run from a checkout after `pnpm install`, not from the published package.

## Requirements

- Python `>=3.11`.
- `httpx` (`>=0.28.1,<0.29`) and `cryptography` (`==50.0.2`, an exact pin), installed with the package.
- A signer for the pairings you pay.

## Versions and upgrading

This package is at 0.x: a minor release may change the public API. Pin the exact version, as the install line above
does. 0.5.x builds and reads the forms of `@integraledger/lcp` 0.6.3 (0.5.0 and 0.5.1: 0.6.0; 0.5.2: 0.6.2), whose vectors
its tests run, and needs Python `>=3.11`.

From 0.4.x, a caller changes this:

- `confirm` takes `resource_request=` (required) and `inputs=` as keywords:
  `confirm(doc, binding, account, fetch, *, resource_request, inputs=None, ceilings=None)`. A 0.4.x call that passes
  `inputs` fifth, or no `resource_request`, raises `TypeError`.
- `transact` requires `approver=` and `resource_request=`, and may return `ToReturn` and `AgreementChallenges` as well
  as `Transacted`, `ToApprove` and `Declined`. `agree` may return `AgreementChallenges`.
- `Next` is `Next(next, summary, h)`, and `Confirmed` carries `summary`.
- A payment `transact`, `confirm` or `finish` builds is held to its pairing's ceiling, 600 seconds unless `ceilings`
  raises it: one payable longer is declined `past-ceiling`, and a form that signs no end `no-end`. The two Gateway
  rails need their floor inputs (`FLOOR_INPUTS`), else `floor-missing`.
- `DeclineCode` has eight new codes: `not-approved`, `atr-malformed`, `option-not-in-atr`, `request-mismatch`,
  `summary-missing`, `past-ceiling`, `no-end` and `floor-missing`.
- Some binding constants were removed, with their pairings, and others added.

The [CHANGELOG](https://github.com/IntegraLedger/integra-agentic-terms/blob/main/agentic-terms-py/CHANGELOG.md) lists
every change.

## Contributing

See the [repository README](https://github.com/IntegraLedger/integra-agentic-terms#readme) and
[CONTRIBUTING.md](https://github.com/IntegraLedger/integra-agentic-terms/blob/main/CONTRIBUTING.md).

## License

Apache-2.0. See [LICENSE](https://github.com/IntegraLedger/integra-agentic-terms/blob/main/agentic-terms-py/LICENSE).
